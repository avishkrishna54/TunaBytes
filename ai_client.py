"""
ai_client.py
Tunabytes V4 — Bounded AI Advisor, Plain-English Behavioral Classifier,
and Live Runtime Google Gemini API Integration.

Enforces Invariant 4:
- Shared httpx.AsyncClient with bounded timeouts and exponential backoff retries.
- Total operation deadline strictly <= 12.0 seconds via asyncio.wait_for().
- Strict Pydantic validation (compatible with Pydantic v1 and v2):
  * verdict: BENIGN | SUSPICIOUS | MALICIOUS
  * confidence: finite float in [0.0, 1.0] (rejects NaN, Inf, and booleans)
  * evidence: sanitized plain-text string (1..250 chars, HTML & control chars stripped)
- Any timeout, HTTP error, or validation failure resolves deterministically to UNKNOWN (0.0).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

try:
    from pydantic import field_validator as _pydantic_validator
    _PYDANTIC_V2 = True
except ImportError:
    from pydantic import validator as _pydantic_validator  # type: ignore
    _PYDANTIC_V2 = False

logger = logging.getLogger("tunabytes.ai_client")


class AIAdvisorHealth(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class StrictVerdictEnum(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RuntimeVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


def _validate_confidence_value(val: Any) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError("Confidence must be a numeric float, not boolean or non-number.")
    fval = float(val)
    if math.isnan(fval) or math.isinf(fval):
        raise ValueError("Confidence cannot be NaN or Infinite.")
    if fval < 0.0 or fval > 1.0:
        raise ValueError("Confidence must be strictly between 0.0 and 1.0.")
    return round(fval, 4)


def _sanitize_evidence_text(val: Any) -> str:
    if not isinstance(val, str):
        raise ValueError("Evidence must be a string.")
    # Strip HTML tags and control characters
    no_html = re.sub(r"<[^>]*>", "", val)
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", no_html)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        raise ValueError("Evidence cannot be empty after sanitization.")
    return cleaned[:250]


class StrictAIModelOutput(BaseModel):
    """Strict Pydantic schema validating raw AI JSON outputs (Invariant 4)."""

    verdict: StrictVerdictEnum
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: str = Field(..., min_length=1, max_length=250)

    if _PYDANTIC_V2:
        @_pydantic_validator("confidence", mode="before")
        @classmethod
        def _check_conf_v2(cls, v: Any) -> float:
            return _validate_confidence_value(v)

        @_pydantic_validator("evidence", mode="before")
        @classmethod
        def _check_ev_v2(cls, v: Any) -> str:
            return _sanitize_evidence_text(v)
    else:
        @_pydantic_validator("confidence", pre=True)
        def _check_conf_v1(cls, v: Any) -> float:
            return _validate_confidence_value(v)

        @_pydantic_validator("evidence", pre=True)
        def _check_ev_v1(cls, v: Any) -> str:
            return _sanitize_evidence_text(v)


class AdvisoryResult(BaseModel):
    verdict: RuntimeVerdict
    confidence: float
    evidence: str
    latency_ms: float
    engine_used: str


def parse_and_validate_ai_payload(raw_data: Any) -> StrictAIModelOutput:
    """Compatible wrapper for both Pydantic v2 and v1 validation."""
    if isinstance(raw_data, str):
        cleaned_json = raw_data.strip()
        if cleaned_json.startswith("```"):
            cleaned_json = re.sub(r"^```(?:json)?\s*", "", cleaned_json)
            cleaned_json = re.sub(r"\s*```$", "", cleaned_json)
        raw_data = json.loads(cleaned_json)

    if _PYDANTIC_V2:
        return StrictAIModelOutput.model_validate(raw_data)
    return StrictAIModelOutput.parse_obj(raw_data)


class BoundedAIAdvisor:
    """
    Bounded async AI advisor with a hard 12.0s total deadline (Invariant 4).
    Supports live runtime Google Gemini API key configuration from the UI
    or falls back to the deterministic Plain-English Behavioral Classifier.
    """

    TOTAL_DEADLINE_SEC: float = 12.0
    MAX_RETRIES: int = 2
    ALLOWED_MODELS = ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash")

    def __init__(self) -> None:
        env_key = (
            os.environ.get("GEMINI_API_KEY", "").strip()
            or os.environ.get("TUNABYTES_AI_KEY", "").strip()
        )
        env_model = os.environ.get("TUNABYTES_GEMINI_MODEL", "gemini-2.5-flash").strip()
        self._gemini_api_key: str = env_key
        self._gemini_model: str = (
            env_model if env_model in self.ALLOWED_MODELS else "gemini-2.5-flash"
        )
        self._custom_endpoint_url: str = os.environ.get("TUNABYTES_AI_URL", "").strip()

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=3.0, read=4.5, write=3.0, pool=2.0),
            limits=httpx.Limits(max_connections=12, max_keepalive_connections=6),
        )
        self._health: AIAdvisorHealth = AIAdvisorHealth.AVAILABLE
        self._consecutive_failures: int = 0
        self._last_error: Optional[str] = None
        self._total_calls: int = 0

    @property
    def health(self) -> AIAdvisorHealth:
        return self._health

    def set_gemini_config(self, api_key: str, model: str = "gemini-2.5-flash") -> Dict[str, Any]:
        """Updates the live Google Gemini API key and model in memory at runtime."""
        cleaned_key = (api_key or "").strip()
        selected_model = model.strip() if model in self.ALLOWED_MODELS else "gemini-2.5-flash"
        self._gemini_api_key = cleaned_key
        self._gemini_model = selected_model
        self._consecutive_failures = 0
        self._last_error = None
        self._health = AIAdvisorHealth.AVAILABLE
        logger.info(
            "AI Advisor runtime configuration updated: mode=%s, model=%s",
            "GEMINI_LIVE_API" if cleaned_key else "LOCAL_BEHAVIORAL_ENGINE",
            self._gemini_model,
        )
        return self.get_gemini_config_status()

    def get_gemini_config_status(self) -> Dict[str, Any]:
        has_key = bool(self._gemini_api_key)
        masked = ""
        if has_key:
            k = self._gemini_api_key
            masked = f"{k[:4]}...{k[-4:]}" if len(k) > 8 else "****"
        return {
            "mode": "GEMINI_LIVE_API" if has_key else "LOCAL_BEHAVIORAL_ENGINE",
            "has_api_key": has_key,
            "masked_key": masked,
            "model": self._gemini_model,
            "health": self._health.value,
            "last_error": self._last_error,
            "total_calls": self._total_calls,
        }

    async def close(self) -> None:
        await self._client.aclose()

    async def analyze_process_window(
        self,
        pid: int,
        create_time: float,
        name: str,
        exe_path: str,
        cmdline: str,
        samples: List[Dict[str, Any]],
        is_trusted_demo: bool = False,
    ) -> AdvisoryResult:
        """
        Executes AI behavioral analysis within a strict 12.0s deadline (Invariant 4).
        Any timeout, HTTP error, or validation failure returns a fail-safe UNKNOWN state.
        """
        start_mono = time.monotonic()
        self._total_calls += 1
        engine_label = "GEMINI_LIVE_API" if self._gemini_api_key else "LOCAL_BEHAVIORAL_ENGINE"

        try:
            raw_output = await asyncio.wait_for(
                self._dispatch_with_retries(
                    pid=pid,
                    create_time=create_time,
                    name=name,
                    exe_path=exe_path,
                    cmdline=cmdline,
                    samples=samples,
                    is_trusted_demo=is_trusted_demo,
                ),
                timeout=self.TOTAL_DEADLINE_SEC,
            )
            validated = parse_and_validate_ai_payload(raw_output)
            self._consecutive_failures = 0
            self._last_error = None
            self._health = AIAdvisorHealth.AVAILABLE
            latency_ms = round((time.monotonic() - start_mono) * 1000.0, 2)

            return AdvisoryResult(
                verdict=RuntimeVerdict(validated.verdict.value),
                confidence=validated.confidence,
                evidence=validated.evidence,
                latency_ms=latency_ms,
                engine_used=engine_label,
            )
        except Exception as exc:
            self._consecutive_failures += 1
            self._last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
            self._health = (
                AIAdvisorHealth.UNAVAILABLE
                if self._consecutive_failures >= 3
                else AIAdvisorHealth.DEGRADED
            )
            latency_ms = round((time.monotonic() - start_mono) * 1000.0, 2)
            logger.warning("AI Advisor fallback to fail-safe UNKNOWN for PID=%d: %s", pid, exc)
            return AdvisoryResult(
                verdict=RuntimeVerdict.UNKNOWN,
                confidence=0.0,
                evidence=_sanitize_evidence_text(
                    f"AI Advisor validation or timeout failure ({type(exc).__name__}). "
                    "Fail-safe UNKNOWN state enforced; automatic action blocked."
                ),
                latency_ms=latency_ms,
                engine_used=engine_label,
            )

    async def _dispatch_with_retries(
        self,
        pid: int,
        create_time: float,
        name: str,
        exe_path: str,
        cmdline: str,
        samples: List[Dict[str, Any]],
        is_trusted_demo: bool,
    ) -> Any:
        backoff = 0.35
        last_err: Optional[Exception] = None

        for attempt in range(1, self.MAX_RETRIES + 2):
            try:
                if self._gemini_api_key:
                    return await self._call_google_gemini(
                        pid=pid,
                        name=name,
                        exe_path=exe_path,
                        cmdline=cmdline,
                        samples=samples,
                        is_trusted_demo=is_trusted_demo,
                    )
                if self._custom_endpoint_url:
                    resp = await self._client.post(
                        self._custom_endpoint_url,
                        json={
                            "pid": pid,
                            "create_time": create_time,
                            "name": name,
                            "exe_path": exe_path,
                            "cmdline": cmdline,
                            "samples": samples,
                        },
                    )
                    resp.raise_for_status()
                    return resp.json()

                # Local Behavioral Engine (simulated tiny async yield)
                await asyncio.sleep(0.08)
                return self._evaluate_local_behavioral_heuristics(
                    pid=pid,
                    name=name,
                    exe_path=exe_path,
                    cmdline=cmdline,
                    samples=samples,
                    is_trusted_demo=is_trusted_demo,
                )
            except Exception as exc:
                last_err = exc
                if attempt <= self.MAX_RETRIES:
                    await asyncio.sleep(backoff)
                    backoff *= 2.0

        raise RuntimeError(f"AI Advisor exhausted retries: {last_err}")

    async def _call_google_gemini(
        self,
        pid: int,
        name: str,
        exe_path: str,
        cmdline: str,
        samples: List[Dict[str, Any]],
        is_trusted_demo: bool,
    ) -> Dict[str, Any]:
        """Calls Google Gemini REST API with JSON response schema enforcement."""
        url = (
            f"[https://generativelanguage.googleapis.com/v1beta/models/](https://generativelanguage.googleapis.com/v1beta/models/)"
            f"{self._gemini_model}:generateContent"
        )
        total_write_ops = sum(int(s.get("write_ops_delta", 0)) for s in samples)
        total_write_kb = sum(int(s.get("write_bytes_delta", 0)) for s in samples) // 1024
        total_delete_ops = sum(int(s.get("other_ops_delta", 0)) for s in samples)
        total_spawns = sum(int(s.get("spawned_children_delta", 0)) for s in samples)
        reasons: List[str] = []
        for s in samples:
            for r in s.get("anomaly_reasons", []):
                if r not in reasons:
                    reasons.append(r)

        prompt = (
            "You are Tunabytes V4, an enterprise Windows Behavioral EDR AI Advisor. "
            "Evaluate this process telemetry window. IMPORTANT RULE: High CPU or RAM alone "
            "is NEVER malicious. Only flag SUSPICIOUS or MALICIOUS based on destructive file "
            "corruption bursts, mass file deletion/renaming I/O, or unauthorized child process spawns.\n"
            f"Process Name: {name} (PID: {pid})\n"
            f"Executable: {exe_path}\n"
            f"Command Line: {cmdline[:240]}\n"
            f"Trusted Synthetic Attack Simulator: {is_trusted_demo}\n"
            f"Window Summary ({len(samples)} ticks): write_ops_delta={total_write_ops}, "
            f"write_kb={total_write_kb} KB, delete_or_meta_ops_delta={total_delete_ops}, "
            f"unauthorized_child_spawns={total_spawns}\n"
            f"Detected Behavioral Indicators: {reasons}\n\n"
            "Respond ONLY with valid JSON matching this exact structure:\n"
            '{"verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS", '
            '"confidence": float between 0.0 and 1.0, '
            '"evidence": "Plain-English explanation under 240 chars explaining to a non-technical user why this app was flagged."}'
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self._gemini_api_key,
        }
        response = await self._client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
        candidates = body.get("candidates") or []
        if not candidates:
            raise ValueError("Gemini API returned zero candidates.")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts or "text" not in parts[0]:
            raise ValueError("Gemini API response missing text part.")
        return json.loads(parts[0]["text"])

    @staticmethod
    def _evaluate_local_behavioral_heuristics(
        pid: int,
        name: str,
        exe_path: str,
        cmdline: str,
        samples: List[Dict[str, Any]],
        is_trusted_demo: bool,
    ) -> Dict[str, Any]:
        """
        Deterministic Plain-English Behavioral Classifier.
        Never flags high CPU or RAM alone — strictly evaluates destructive behavioral indicators.
        """
        total_write_ops = sum(int(s.get("write_ops_delta", 0)) for s in samples)
        total_write_bytes = sum(int(s.get("write_bytes_delta", 0)) for s in samples)
        total_write_kb = max(1, total_write_bytes // 1024)
        total_other_ops = sum(int(s.get("other_ops_delta", 0)) for s in samples)
        total_spawns = sum(int(s.get("spawned_children_delta", 0)) for s in samples)

        spawned_names: List[str] = []
        reasons: List[str] = []
        for s in samples:
            for child_name in s.get("spawned_children_names", []):
                if child_name not in spawned_names:
                    spawned_names.append(child_name)
            for reason in s.get("anomaly_reasons", []):
                if reason not in reasons:
                    reasons.append(reason)

        has_corruption = "FILE_CORRUPTION_BURST" in reasons
        has_deletion = "MASS_FILE_DELETION_IO" in reasons
        has_spawn = "UNAUTHORIZED_PROGRAM_SPAWN" in reasons

        actions_desc: List[str] = []
        if has_corruption:
            actions_desc.append(
                f"rapidly overwriting/corrupting files ({total_write_ops} write ops, {total_write_kb} KB)"
            )
        if has_deletion:
            actions_desc.append(
                f"deleting/renaming files in bulk ({total_other_ops} metadata/unlink ops)"
            )
        if has_spawn:
            child_label = ", ".join(spawned_names[:2]) if spawned_names else "background shell"
            actions_desc.append(
                f"spawning unauthorized program ({child_label})"
            )

        if is_trusted_demo or len(reasons) >= 2 or (has_corruption and total_write_bytes >= 360 * 1024):
            joined_actions = (
                ", ".join(actions_desc)
                if actions_desc
                else f"performing ransomware-like file corruption ({total_write_ops} writes, {total_write_kb} KB)"
            )
            conf = 0.97 if (is_trusted_demo or len(reasons) >= 2) else 0.91
            return {
                "verdict": "MALICIOUS",
                "confidence": conf,
                "evidence": (
                    f"DANGER: {name} (PID {pid}) was caught {joined_actions}. "
                    "Freeze or terminate this app if you did not authorize these actions."
                )[:250],
            }

        if len(reasons) == 1:
            joined_actions = actions_desc[0] if actions_desc else f"unusual behavioral activity ({reasons[0]})"
            return {
                "verdict": "SUSPICIOUS",
                "confidence": 0.82,
                "evidence": (
                    f"WARNING: {name} (PID {pid}) exhibited suspicious behavior by {joined_actions}. "
                    "Review before allowing it to continue."
                )[:250],
            }

        return {
            "verdict": "BENIGN",
            "confidence": 0.95,
            "evidence": (
                f"SAFE: {name} (PID {pid}) shows normal operating behavior with zero unauthorized "
                "file corruption, mass deletion, or covert child process spawns."
            )[:250],
        }