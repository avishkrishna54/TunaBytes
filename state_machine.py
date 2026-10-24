"""
state_machine.py
Tunabytes V4 — Coalescing Lifecycle State Machine, Immutable Process Whitelist,
Quarantine Thread Freeze (Suspend/Resume), and 2-Step "Double-Lock" HITL Termination.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import psutil

from ai_client import AdvisoryResult, BoundedAIAdvisor, RuntimeVerdict

logger = logging.getLogger("tunabytes.state_machine")

ProcessKey = Tuple[int, float]  # (PID, creation_time)

# Hardcoded immutable set of protected Windows system, browser, IDE, and shell binaries
PROTECTED_PROCESS_NAMES: Set[str] = {
    # OS & Kernel Critical Processes
    "system",
    "idle",
    "registry",
    "memcompression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "taskhostw.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "ctfmon.exe",
    "conhost.exe",
    "dllhost.exe",
    "WmiPrvSE.exe".lower(),
    "audiodg.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "smartscreen.exe",
    # Major Web Browsers
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    # IDEs, Editors & Developer Terminals
    "code.exe",
    "cursor.exe",
    "devenv.exe",
    "pycharm64.exe",
    "idea64.exe",
    "windsurf.exe",
    "sublime_text.exe",
    "notepad++.exe",
    "windowsterminal.exe",
    "wt.exe",
    "openconsole.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
}


def is_process_whitelisted(
    pid: int,
    name: str,
    exe_path: str = "",
    cmdline: str = "",
) -> Tuple[bool, str]:
    """
    Immutable, non-bypassable safety filter enforced in both `monitor.py` and `state_machine.py`.
    Returns `(is_whitelisted, protection_reason)`.
    Explicitly allows `demo_workload.py` and `rogue_test` so synthetic attack simulators can be tested.
    """
    cmd_lower = (cmdline or "").lower()
    name_lower = (name or "").strip().lower()
    exe_lower = os.path.normpath(exe_path or "").lower()

    # 1. Explicitly allow the synthetic attack simulators (`demo_workload.py` and `rogue_test`)
    if "demo_workload.py" in cmd_lower or "demo_workload" in name_lower or "demo_workload" in exe_lower:
        return False, ""
    if "rogue_test" in cmd_lower or "rogue_test" in name_lower or "rogue_test" in exe_lower:
        return False, ""

    # 2. Self-Preservation: Protect Tunabytes server process & parent process
    own_pid = os.getpid()
    parent_pid = os.getppid()
    if pid in (own_pid, parent_pid):
        return True, "TUNABYTES_SELF_PROTECTED"
    if ("main:app" in cmd_lower or "uvicorn" in cmd_lower or "main.py" in cmd_lower) and "python" in name_lower:
        return True, "TUNABYTES_SERVER_PROTECTED"

    # 3. Kernel & Low-PID Protection
    if pid < 1000:
        return True, "OS_KERNEL_PID_PROTECTED"

    # 4. Protected System, Browser, and IDE Executable Names
    if name_lower in PROTECTED_PROCESS_NAMES:
        return True, "IMMUTABLE_WHITELIST_APP"

    # 5. Windows System32 / SysWOW64 Directory Protection
    if exe_lower.startswith(r"c:\windows\system32") or exe_lower.startswith(r"c:\windows\syswow64"):
        return True, "WINDOWS_SYSTEM_BINARY"

    return False, ""


class ProcessLifecycleState(str, Enum):
    IDLE = "IDLE"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    COOLDOWN = "COOLDOWN"


class QueueHealthState(str, Enum):
    NORMAL = "NORMAL"
    BACKLOGGED = "BACKLOGGED"
    DROPPING_EVENTS = "DROPPING_EVENTS"


class EnforcementMode(str, Enum):
    DISABLED = "DISABLED"      # Displayed as HITL_ADVISORY (100% Human-in-the-Loop)
    DEMO_ONLY = "DEMO_ONLY"    # Auto-terminates ONLY verified demo_workload.py


@dataclass
class ProcessStateRecord:
    pid: int
    create_time: float
    name: str
    exe_path: str
    cmdline: str
    state: ProcessLifecycleState = ProcessLifecycleState.IDLE
    latest_samples: List[Dict[str, Any]] = field(default_factory=list)
    latest_captured_at_mono: float = 0.0
    enqueued_at_mono: float = 0.0
    coalesced_count: int = 0
    cooldown_until_mono: float = 0.0
    last_verdict: str = "NONE"
    last_confidence: float = 0.0
    last_evidence: str = ""
    last_engine: str = ""
    anomaly_reasons: List[str] = field(default_factory=list)
    is_suspended: bool = False
    alert_dismissed: bool = False
    updated_at_wall: float = field(default_factory=time.time)


class CoalescingStateMachine:
    """
    Event-loop-owned Coalescing Lifecycle Manager.
    Enforces Invariants 2, 3, and 5, plus HITL Freeze/Resume and 2-Step Double-Lock Termination.
    """

    PRE_AI_MAX_AGE_SEC: float = 15.0
    PRE_ACTION_MAX_AGE_SEC: float = 30.0
    COOLDOWN_SEC: float = 60.0
    MAX_QUEUE_SIZE: int = 64
    NUM_WORKERS: int = 2

    def __init__(self, ai_advisor: BoundedAIAdvisor) -> None:
        self.ai_advisor = ai_advisor

        # Event-loop-owned registries
        self._records: Dict[ProcessKey, ProcessStateRecord] = {}
        self._queue: asyncio.Queue[ProcessKey] = asyncio.Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._audit_log: Deque[Dict[str, Any]] = deque(maxlen=150)
        self._terminated_history: Deque[Dict[str, Any]] = deque(maxlen=60)

        self._enforcement_mode: EnforcementMode = EnforcementMode.DISABLED
        # Authorized demo target tuple: (popen_handle, pid, create_time, norm_script_path)
        self._demo_authority: Optional[Tuple[Any, int, float, str]] = None

        self._coalesced_total: int = 0
        self._dropped_events_total: int = 0
        self._stale_pre_ai_drops: int = 0
        self._stale_post_ai_drops: int = 0

        self._workers: List[asyncio.Task[None]] = []
        self._rearm_task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._enforcement_mode

    def set_enforcement_mode(self, mode: EnforcementMode) -> None:
        self._enforcement_mode = mode
        ui_mode_label = "HITL_ADVISORY (DISABLED)" if mode == EnforcementMode.DISABLED else "DEMO_ONLY"
        self.record_audit_event(
            pid=0,
            name="SYSTEM_POLICY",
            verdict="INFO",
            confidence=1.0,
            action="ENFORCEMENT_MODE_CHANGED",
            evidence=f"Enforcement mode switched to {ui_mode_label}.",
        )

    def register_demo_authority(
        self,
        popen_handle: Any,
        pid: Optional[int],
        create_time: Optional[float],
        script_path: Optional[str],
    ) -> None:
        """Invariant 5: Stores verified Popen handle, PID, creation_time, and script path."""
        if popen_handle is not None and pid is not None and create_time is not None and script_path:
            norm_path = os.path.normcase(os.path.abspath(script_path))
            self._demo_authority = (popen_handle, int(pid), float(create_time), norm_path)
        else:
            self._demo_authority = None

    def is_verified_demo_process(self, pid: int, create_time: float) -> bool:
        """Strictly verifies Invariant 5 demo identity."""
        if self._demo_authority is None:
            return False
        popen_handle, auth_pid, auth_ctime, _ = self._demo_authority
        if pid != auth_pid:
            return False
        if abs(create_time - auth_ctime) > 0.5:
            return False
        if popen_handle is not None and popen_handle.poll() is not None:
            return False
        return True

    @property
    def queue_health(self) -> QueueHealthState:
        qsize = self._queue.qsize()
        if self._dropped_events_total > 0 or qsize >= self.MAX_QUEUE_SIZE:
            return QueueHealthState.DROPPING_EVENTS
        if qsize >= (self.MAX_QUEUE_SIZE // 2):
            return QueueHealthState.BACKLOGGED
        return QueueHealthState.NORMAL

    def start(self) -> None:
        self._stop_event.clear()
        if not self._workers or all(w.done() for w in self._workers):
            self._workers = [
                asyncio.create_task(self._worker_loop(i + 1), name=f"tunabytes-sm-worker-{i+1}")
                for i in range(self.NUM_WORKERS)
            ]
        if self._rearm_task is None or self._rearm_task.done():
            self._rearm_task = asyncio.create_task(
                self._cooldown_rearm_loop(), name="tunabytes-sm-rearm"
            )

    async def stop(self) -> None:
        self._stop_event.set()
        tasks = list(self._workers)
        if self._rearm_task is not None:
            tasks.append(self._rearm_task)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._workers.clear()
        self._rearm_task = None

    async def submit_behavioral_event(self, event_payload: Dict[str, Any]) -> None:
        """
        Submits or coalesces a behavioral anomaly event into the state machine (Invariant 3).
        Double-checks the immutable whitelist before queueing.
        """
        pid = int(event_payload["pid"])
        create_time = float(event_payload["create_time"])
        name = str(event_payload.get("name") or f"pid-{pid}")
        exe_path = str(event_payload.get("exe_path") or "")
        cmdline = str(event_payload.get("cmdline") or "")

        whitelisted, _ = is_process_whitelisted(pid, name, exe_path, cmdline)
        if whitelisted:
            return

        key: ProcessKey = (pid, create_time)
        now_mono = time.monotonic()
        captured_at_mono = float(event_payload["captured_at_mono"])
        samples_copy = copy.deepcopy(event_payload.get("window_samples", []))
        reasons = list(event_payload.get("anomaly_reasons", []))

        rec = self._records.get(key)
        if rec is None:
            rec = ProcessStateRecord(
                pid=pid,
                create_time=create_time,
                name=name,
                exe_path=exe_path,
                cmdline=cmdline,
            )
            self._records[key] = rec

        # Merge anomaly reasons
        for r in reasons:
            if r not in rec.anomaly_reasons:
                rec.anomaly_reasons.append(r)

        # Automatic cooldown expiry check
        if rec.state == ProcessLifecycleState.COOLDOWN and now_mono >= rec.cooldown_until_mono:
            rec.state = ProcessLifecycleState.IDLE

        # Invariant 3: Coalesce in-place when already QUEUED or ANALYZING
        if rec.state in (ProcessLifecycleState.QUEUED, ProcessLifecycleState.ANALYZING):
            rec.latest_samples = samples_copy
            rec.latest_captured_at_mono = captured_at_mono
            rec.coalesced_count += 1
            rec.updated_at_wall = time.time()
            self._coalesced_total += 1
            return

        # Suppress duplicate enqueue during 60s COOLDOWN window
        if rec.state == ProcessLifecycleState.COOLDOWN:
            rec.latest_samples = samples_copy
            rec.latest_captured_at_mono = captured_at_mono
            rec.coalesced_count += 1
            self._coalesced_total += 1
            return

        # Transition IDLE -> QUEUED
        rec.latest_samples = samples_copy
        rec.latest_captured_at_mono = captured_at_mono
        rec.enqueued_at_mono = now_mono
        rec.state = ProcessLifecycleState.QUEUED
        rec.alert_dismissed = False
        rec.updated_at_wall = time.time()

        try:
            self._queue.put_nowait(key)
        except asyncio.QueueFull:
            self._dropped_events_total += 1
            rec.state = ProcessLifecycleState.IDLE
            self.record_audit_event(
                pid=pid,
                name=name,
                verdict="QUEUE_FULL",
                confidence=0.0,
                action="DROPPED_QUEUE_OVERFLOW",
                evidence="State machine queue reached max capacity (64); event dropped.",
            )

    async def _cooldown_rearm_loop(self) -> None:
        """Rearms processes from COOLDOWN -> IDLE once the 60.0s monotonic timer expires."""
        while not self._stop_event.is_set():
            try:
                now_mono = time.monotonic()
                for rec in list(self._records.values()):
                    if rec.state == ProcessLifecycleState.COOLDOWN and now_mono >= rec.cooldown_until_mono:
                        rec.state = ProcessLifecycleState.IDLE
                        rec.updated_at_wall = time.time()
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Cooldown rearm loop error: %s", exc)

    async def _worker_loop(self, worker_id: int) -> None:
        """
        Invariant 3: Worker loop guarantees `self._queue.task_done()` inside `finally:`
        on every code path (normal, stale drop, exception, or CancelledError).
        """
        while not self._stop_event.is_set():
            try:
                key = await self._queue.get()
            except asyncio.CancelledError:
                break

            try:
                rec = self._records.get(key)
                if rec is None:
                    continue

                # Transition QUEUED -> ANALYZING
                rec.state = ProcessLifecycleState.ANALYZING
                rec.updated_at_wall = time.time()

                captured_at_mono = rec.latest_captured_at_mono
                samples_snapshot = copy.deepcopy(rec.latest_samples)

                # Invariant 2: Pre-AI Freshness Gate (> 15.0s dropped)
                pre_ai_age = time.monotonic() - captured_at_mono
                if pre_ai_age > self.PRE_AI_MAX_AGE_SEC:
                    self._stale_pre_ai_drops += 1
                    rec.state = ProcessLifecycleState.IDLE
                    self.record_audit_event(
                        pid=rec.pid,
                        name=rec.name,
                        verdict="STALE",
                        confidence=0.0,
                        action="DROPPED_STALE_PRE_AI",
                        evidence=(
                            f"Observation age ({pre_ai_age:.2f}s) exceeded 15.0s Pre-AI freshness gate."
                        ),
                    )
                    continue

                is_demo = self.is_verified_demo_process(rec.pid, rec.create_time)
                advisory: AdvisoryResult = await self.ai_advisor.analyze_process_window(
                    pid=rec.pid,
                    create_time=rec.create_time,
                    name=rec.name,
                    exe_path=rec.exe_path,
                    cmdline=rec.cmdline,
                    samples=samples_snapshot,
                    is_trusted_demo=is_demo,
                )

                rec.last_verdict = advisory.verdict.value
                rec.last_confidence = advisory.confidence
                rec.last_evidence = advisory.evidence
                rec.last_engine = advisory.engine_used

                # Invariant 2: Pre-Action Freshness Gate (> 30.0s blocks enforcement)
                post_ai_age = time.monotonic() - rec.latest_captured_at_mono
                if post_ai_age > self.PRE_ACTION_MAX_AGE_SEC:
                    self._stale_post_ai_drops += 1
                    self.record_audit_event(
                        pid=rec.pid,
                        name=rec.name,
                        verdict=advisory.verdict.value,
                        confidence=advisory.confidence,
                        action="AUDIT_ONLY_STALE_POST_AI",
                        evidence=(
                            f"Post-AI observation age ({post_ai_age:.2f}s) exceeded 30.0s gate. "
                            f"{advisory.evidence}"
                        )[:250],
                    )
                else:
                    await self._handle_post_ai_decision(rec, advisory, is_demo)

                # Transition ANALYZING -> COOLDOWN (60.0s monotonic window)
                rec.state = ProcessLifecycleState.COOLDOWN
                rec.cooldown_until_mono = time.monotonic() + self.COOLDOWN_SEC
                rec.updated_at_wall = time.time()

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Worker %d error processing %s: %s", worker_id, key, exc)
                if key in self._records:
                    self._records[key].state = ProcessLifecycleState.IDLE
            finally:
                # Invariant 3: Guaranteed task_done() on every code path
                self._queue.task_done()

    async def _handle_post_ai_decision(
        self,
        rec: ProcessStateRecord,
        advisory: AdvisoryResult,
        is_demo: bool,
    ) -> None:
        if advisory.verdict == RuntimeVerdict.UNKNOWN:
            self.record_audit_event(
                pid=rec.pid,
                name=rec.name,
                verdict="UNKNOWN",
                confidence=0.0,
                action="FAILSAFE_NO_ACTION",
                evidence=advisory.evidence,
            )
            return

        # Invariant 5: Automatic termination ONLY if mode == DEMO_ONLY and verified demo target
        if (
            self._enforcement_mode == EnforcementMode.DEMO_ONLY
            and is_demo
            and advisory.verdict == RuntimeVerdict.MALICIOUS
            and advisory.confidence >= 0.80
        ):
            killed, msg = await asyncio.to_thread(
                self._safe_os_terminate, rec.pid, rec.create_time
            )
            action_tag = "AUTO_TERMINATED_DEMO" if killed else f"DEMO_TERMINATE_SKIPPED ({msg})"
            if killed:
                self._terminated_history.appendleft(
                    {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "pid": rec.pid,
                        "create_time": rec.create_time,
                        "name": rec.name,
                        "exe_path": rec.exe_path,
                        "verdict": advisory.verdict.value,
                        "confidence": advisory.confidence,
                        "triggers": list(rec.anomaly_reasons),
                        "mode": "DEMO_ONLY_AUTO",
                        "reason": advisory.evidence,
                    }
                )
            self.record_audit_event(
                pid=rec.pid,
                name=rec.name,
                verdict=advisory.verdict.value,
                confidence=advisory.confidence,
                action=action_tag,
                evidence=advisory.evidence,
            )
            return

        # Default Human-in-the-Loop (HITL) Advisory path
        action_tag = (
            "HITL_THREAT_ALERT_RAISED"
            if advisory.verdict in (RuntimeVerdict.MALICIOUS, RuntimeVerdict.SUSPICIOUS)
            else "TELEMETRY_VERIFIED_BENIGN"
        )
        self.record_audit_event(
            pid=rec.pid,
            name=rec.name,
            verdict=advisory.verdict.value,
            confidence=advisory.confidence,
            action=action_tag,
            evidence=advisory.evidence,
        )

    # ------------------------------------------------------------------
    # Human-in-the-Loop (HITL) Quarantine Freeze & Double-Lock Termination
    # ------------------------------------------------------------------
    def _find_latest_record_by_pid(self, pid: int) -> Optional[ProcessStateRecord]:
        matches = [r for r in self._records.values() if r.pid == pid]
        if not matches:
            return None
        matches.sort(key=lambda r: r.create_time, reverse=True)
        return matches[0]

    async def suspend_process_hitl(self, pid: int) -> Dict[str, Any]:
        """Freezes (suspends) a non-whitelisted process in RAM so it cannot corrupt more files."""
        rec = self._find_latest_record_by_pid(pid)
        expected_ctime = rec.create_time if rec else None

        ok, detail, proc_name = await asyncio.to_thread(
            self._safe_os_suspend_or_resume, pid, expected_ctime, True
        )
        if ok and rec is not None:
            rec.is_suspended = True
            rec.updated_at_wall = time.time()

        self.record_audit_event(
            pid=pid,
            name=proc_name,
            verdict=rec.last_verdict if rec else "MANUAL",
            confidence=rec.last_confidence if rec else 1.0,
            action="HITL_PROCESS_FROZEN" if ok else "HITL_FREEZE_REJECTED",
            evidence=detail,
        )
        return {"success": ok, "pid": pid, "name": proc_name, "detail": detail}

    async def resume_process_hitl(self, pid: int) -> Dict[str, Any]:
        """Resumes a previously frozen process in RAM."""
        rec = self._find_latest_record_by_pid(pid)
        expected_ctime = rec.create_time if rec else None

        ok, detail, proc_name = await asyncio.to_thread(
            self._safe_os_suspend_or_resume, pid, expected_ctime, False
        )
        if ok and rec is not None:
            rec.is_suspended = False
            rec.updated_at_wall = time.time()

        self.record_audit_event(
            pid=pid,
            name=proc_name,
            verdict=rec.last_verdict if rec else "MANUAL",
            confidence=rec.last_confidence if rec else 1.0,
            action="HITL_PROCESS_RESUMED" if ok else "HITL_RESUME_REJECTED",
            evidence=detail,
        )
        return {"success": ok, "pid": pid, "name": proc_name, "detail": detail}

    async def terminate_process_hitl(
        self,
        pid: int,
        step1_acknowledged: bool,
        step2_confirmed: bool,
        operator_note: str = "User confirmed 2-step Double-Lock termination",
    ) -> Dict[str, Any]:
        """
        Enforces the 2-Step "Double-Lock" Verification System before terminating any process.
        Re-verifies whitelist protection and creation_time identity before calling terminate().
        """
        if not (step1_acknowledged and step2_confirmed):
            return {
                "success": False,
                "pid": pid,
                "detail": "Double-Lock verification failed: Both Step 1 and Step 2 confirmations are required.",
            }

        rec = self._find_latest_record_by_pid(pid)
        expected_ctime = rec.create_time if rec else None

        killed, detail, proc_info = await asyncio.to_thread(
            self._safe_os_terminate_with_info, pid, expected_ctime
        )

        if killed:
            if rec is not None:
                rec.is_suspended = False
                rec.alert_dismissed = True
                rec.state = ProcessLifecycleState.IDLE

            ledger_entry = {
                "timestamp": time.strftime("%H:%M:%S"),
                "pid": pid,
                "create_time": proc_info.get("create_time", 0.0),
                "name": proc_info.get("name", f"pid-{pid}"),
                "exe_path": proc_info.get("exe_path", ""),
                "verdict": rec.last_verdict if rec else "USER_DIRECTED",
                "confidence": rec.last_confidence if rec else 1.0,
                "triggers": list(rec.anomaly_reasons) if rec else ["MANUAL_DOUBLE_LOCK"],
                "mode": "HITL_DOUBLE_LOCK",
                "reason": rec.last_evidence if (rec and rec.last_evidence) else operator_note,
            }
            self._terminated_history.appendleft(ledger_entry)

        self.record_audit_event(
            pid=pid,
            name=proc_info.get("name", f"pid-{pid}"),
            verdict=rec.last_verdict if rec else "USER_DIRECTED",
            confidence=rec.last_confidence if rec else 1.0,
            action="HITL_DOUBLE_LOCK_TERMINATED" if killed else "HITL_TERMINATE_BLOCKED",
            evidence=detail,
        )
        return {
            "success": killed,
            "pid": pid,
            "name": proc_info.get("name", f"pid-{pid}"),
            "detail": detail,
        }

    def dismiss_alert(self, pid: int) -> bool:
        rec = self._find_latest_record_by_pid(pid)
        if rec is None:
            return False
        rec.alert_dismissed = True
        self.record_audit_event(
            pid=pid,
            name=rec.name,
            verdict=rec.last_verdict,
            confidence=rec.last_confidence,
            action="HITL_ALERT_DISMISSED",
            evidence=f"Operator dismissed threat banner for {rec.name} (PID {pid}).",
        )
        return True

    @staticmethod
    def _safe_os_suspend_or_resume(
        pid: int, expected_ctime: Optional[float], do_suspend: bool
    ) -> Tuple[bool, str, str]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            ctime = proc.create_time()
            exe = ""
            cmdline = ""
            try:
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                cmdline = " ".join(proc.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            whitelisted, w_reason = is_process_whitelisted(pid, name, exe, cmdline)
            if whitelisted:
                return False, f"Protected process ({w_reason}) cannot be suspended.", name

            if expected_ctime is not None and abs(ctime - expected_ctime) > 0.5:
                return False, "PID creation_time mismatch (process exited/reused).", name

            if do_suspend:
                proc.suspend()
                return True, f"Process {name} (PID {pid}) threads frozen in RAM.", name
            else:
                proc.resume()
                return True, f"Process {name} (PID {pid}) resumed execution.", name
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return False, f"PID {pid} is no longer running.", f"pid-{pid}"
        except psutil.AccessDenied:
            return False, f"OS AccessDenied while modifying PID {pid}.", f"pid-{pid}"

    @staticmethod
    def _safe_os_terminate(pid: int, expected_ctime: float) -> Tuple[bool, str]:
        try:
            proc = psutil.Process(pid)
            if abs(proc.create_time() - expected_ctime) > 0.5:
                return False, "PID creation_time mismatch"
            proc.terminate()
            return True, "Terminated verified demo process"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            return False, type(exc).__name__

    @staticmethod
    def _safe_os_terminate_with_info(
        pid: int, expected_ctime: Optional[float]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        info: Dict[str, Any] = {"name": f"pid-{pid}", "exe_path": "", "create_time": 0.0}
        try:
            proc = psutil.Process(pid)
            info["name"] = proc.name()
            info["create_time"] = proc.create_time()
            try:
                info["exe_path"] = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            cmdline = ""
            try:
                cmdline = " ".join(proc.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            whitelisted, w_reason = is_process_whitelisted(
                pid, info["name"], info["exe_path"], cmdline
            )
            if whitelisted:
                return (
                    False,
                    f"Immutable Whitelist Protection ({w_reason}): {info['name']} cannot be terminated.",
                    info,
                )

            if expected_ctime is not None and abs(info["create_time"] - expected_ctime) > 0.5:
                return False, "PID reuse detected (creation_time mismatch); aborting termination.", info

            proc.terminate()
            return (
                True,
                f"Terminated {info['name']} (PID {pid}) after 2-step Double-Lock confirmation.",
                info,
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return False, f"Process PID {pid} already exited.", info
        except psutil.AccessDenied:
            return False, f"OS AccessDenied attempting to terminate PID {pid}.", info

    def record_audit_event(
        self,
        pid: int,
        name: str,
        verdict: str,
        confidence: float,
        action: str,
        evidence: str,
    ) -> None:
        self._audit_log.appendleft(
            {
                "timestamp": time.strftime("%H:%M:%S"),
                "pid": int(pid),
                "name": str(name),
                "verdict": str(verdict),
                "confidence": round(float(confidence), 2),
                "action": str(action),
                "evidence": str(evidence)[:250],
            }
        )

    def get_state_snapshot(self, active_pids: Optional[Set[int]] = None) -> Dict[str, Any]:
        """Returns a deep-copied snapshot of state machine metrics, active alerts, and audit logs."""
        now_mono = time.monotonic()
        counts = {s.value: 0 for s in ProcessLifecycleState}
        per_pid: Dict[int, Dict[str, Any]] = {}
        active_alerts: List[Dict[str, Any]] = []

        for rec in self._records.values():
            if rec.state == ProcessLifecycleState.COOLDOWN and now_mono >= rec.cooldown_until_mono:
                rec.state = ProcessLifecycleState.IDLE

            counts[rec.state.value] = counts.get(rec.state.value, 0) + 1
            cd_rem = (
                max(0.0, round(rec.cooldown_until_mono - now_mono, 1))
                if rec.state == ProcessLifecycleState.COOLDOWN
                else 0.0
            )
            per_pid[rec.pid] = {
                "state": rec.state.value,
                "coalesced_count": rec.coalesced_count,
                "cooldown_remaining_sec": cd_rem,
                "last_verdict": rec.last_verdict,
                "last_confidence": rec.last_confidence,
                "last_evidence": rec.last_evidence,
                "last_engine": rec.last_engine,
                "anomaly_reasons": list(rec.anomaly_reasons),
                "is_suspended": rec.is_suspended,
            }

            is_alive = active_pids is None or rec.pid in active_pids
            if (
                is_alive
                and not rec.alert_dismissed
                and rec.last_verdict in ("MALICIOUS", "SUSPICIOUS")
            ):
                active_alerts.append(
                    {
                        "pid": rec.pid,
                        "create_time": rec.create_time,
                        "name": rec.name,
                        "exe_path": rec.exe_path,
                        "verdict": rec.last_verdict,
                        "confidence": rec.last_confidence,
                        "evidence": rec.last_evidence,
                        "triggers": list(rec.anomaly_reasons),
                        "is_suspended": rec.is_suspended,
                        "state": rec.state.value,
                    }
                )

        return {
            "queue_depth": self._queue.qsize(),
            "queue_health": self.queue_health.value,
            "coalesced_total": self._coalesced_total,
            "dropped_events_total": self._dropped_events_total,
            "stale_pre_ai_drops": self._stale_pre_ai_drops,
            "stale_post_ai_drops": self._stale_post_ai_drops,
            "enforcement_mode": self._enforcement_mode.value,
            "state_counts": counts,
            "per_pid": per_pid,
            "active_alerts": active_alerts,
            "terminated_history": copy.deepcopy(list(self._terminated_history)),
            "audit_log": copy.deepcopy(list(self._audit_log)),
        }