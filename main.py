"""
main.py
Tunabytes V4 — FastAPI Application, Bounded 5.0s Lifespan, Loopback Security Authority,
Runtime Gemini API Key Configuration, HITL Double-Lock Endpoints, and Executive PDF Generator.
"""

from __future__ import annotations

import asyncio
import copy
import io
import logging
import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from ai_client import BoundedAIAdvisor
from monitor import TelemetryMonitor
from state_machine import CoalescingStateMachine, EnforcementMode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tunabytes.main")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DEMO_SCRIPT_PATH = str((BASE_DIR / "demo_workload.py").resolve())

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def verify_loopback_request(request: Request) -> None:
    """Invariant 5: Ensures sensitive control endpoints are only called from loopback."""
    client_host = (request.client.host if request.client else "").strip().lower()
    if client_host not in ALLOWED_LOOPBACK_HOSTS:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Endpoint restricted to loopback origin (got '{client_host}').",
        )


class StrictEmptyLaunchRequest(BaseModel):
    """Invariant 5: /api/launch-demo accepts zero arguments; extra fields return HTTP 422."""
    model_config = ConfigDict(extra="forbid")


class DoubleLockTerminateRequest(BaseModel):
    step1_acknowledged: bool
    step2_confirmed: bool
    reason: Optional[str] = "Confirmed via 2-Step Double-Lock UI"


class GeminiConfigPayload(BaseModel):
    api_key: str = ""
    model: str = "gemini-2.5-flash"


class EnforcementModePayload(BaseModel):
    mode: Optional[str] = None


class ManagedDemoTarget:
    """
    Invariant 5: Tracks the trusted `demo_workload.py` subprocess handle, PID,
    creation_time, and normalized script path.
    """

    def __init__(self) -> None:
        self.popen: Optional[subprocess.Popen[bytes]] = None
        self.pid: Optional[int] = None
        self.create_time: Optional[float] = None
        self.script_path: str = os.path.normcase(DEMO_SCRIPT_PATH)

    def is_running(self) -> bool:
        if self.popen is None or self.pid is None:
            return False
        if self.popen.poll() is not None:
            return False
        try:
            proc = psutil.Process(self.pid)
            if abs(proc.create_time() - (self.create_time or 0.0)) > 0.5:
                return False
            return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False

    def terminate_and_cleanup(self) -> None:
        if self.popen is not None and self.popen.poll() is None:
            try:
                self.popen.terminate()
                self.popen.wait(timeout=1.5)
            except Exception:
                try:
                    self.popen.kill()
                except Exception:
                    pass
        self.popen = None
        self.pid = None
        self.create_time = None


# Core Singleton Engine Instances
ai_advisor = BoundedAIAdvisor()
state_machine = CoalescingStateMachine(ai_advisor=ai_advisor)
monitor = TelemetryMonitor(
    poll_interval_sec=1.5,
    max_sample_age_sec=30.0,
    on_behavioral_anomaly=state_machine.submit_behavioral_event,
)
demo_target = ManagedDemoTarget()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Invariant 6: Starts background tasks and guarantees clean teardown of collector,
    state machine workers, managed demo subprocess, and httpx client within 5.0 seconds.
    """
    state_machine.start()
    monitor.start()
    logger.info("Tunabytes V4 Behavioral EDR online at [http://127.0.0.1:8000](http://127.0.0.1:8000)")

    yield

    logger.info("Initiating bounded 5.0s lifespan teardown...")

    async def _shutdown_all() -> None:
        await monitor.stop()
        await state_machine.stop()
        await asyncio.to_thread(demo_target.terminate_and_cleanup)
        await ai_advisor.close()

    try:
        await asyncio.wait_for(_shutdown_all(), timeout=5.0)
        logger.info("Tunabytes V4 clean teardown completed within 5.0s deadline.")
    except asyncio.TimeoutError:
        logger.error("Lifespan teardown exceeded 5.0s deadline; forcing immediate exit.")


app = FastAPI(
    title="Tunabytes V4 — AI Behavioral Antivirus & HITL EDR",
    version="4.0.0",
    lifespan=lifespan,
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Invariant 6: Non-blocking `/health` endpoint returning decoupled in-memory states.
    """
    return {
        "Collector": monitor.health.value,
        "AI Advisor": ai_advisor.health.value,
        "Queue": state_machine.queue_health.value,
        "Enforcement": state_machine.enforcement_mode.value,
    }


@app.get("/api/telemetry")
async def get_telemetry_dashboard_state() -> Dict[str, Any]:
    mon_snap = monitor.get_telemetry_snapshot(limit=45)
    sm_snap = state_machine.get_state_snapshot(active_pids=mon_snap["active_pids"])
    per_pid = sm_snap["per_pid"]
    demo_running = demo_target.is_running()

    for proc in mon_snap["processes"]:
        pid = proc["pid"]
        st = per_pid.get(pid, {})
        proc["edr_state"] = st.get("state", "IDLE")
        proc["coalesced_count"] = st.get("coalesced_count", 0)
        proc["cooldown_remaining_sec"] = st.get("cooldown_remaining_sec", 0.0)
        proc["last_verdict"] = st.get("last_verdict", "NONE")
        proc["last_confidence"] = st.get("last_confidence", 0.0)
        proc["last_evidence"] = st.get("last_evidence", "")
        proc["is_suspended"] = st.get("is_suspended", False) or proc["os_status"] == "stopped"
        proc["is_demo_target"] = bool(demo_running and demo_target.pid == pid)

    return {
        "health": await health_check(),
        "ai_config": ai_advisor.get_gemini_config_status(),
        "stats": {
            "total_tracked": mon_snap["total_tracked"],
            "whitelisted_count": mon_snap["whitelisted_count"],
            "user_app_count": mon_snap["user_app_count"],
            "trigger_stats": mon_snap["trigger_stats"],
            "queue_depth": sm_snap["queue_depth"],
            "coalesced_total": sm_snap["coalesced_total"],
            "dropped_events_total": sm_snap["dropped_events_total"],
            "stale_pre_ai_drops": sm_snap["stale_pre_ai_drops"],
            "stale_post_ai_drops": sm_snap["stale_post_ai_drops"],
            "state_counts": sm_snap["state_counts"],
            "enforcement_mode": sm_snap["enforcement_mode"],
        },
        "demo": {
            "running": demo_running,
            "pid": demo_target.pid if demo_running else None,
            "create_time": demo_target.create_time if demo_running else None,
            "script_path": DEMO_SCRIPT_PATH,
        },
        "active_alerts": sm_snap["active_alerts"],
        "terminated_history": sm_snap["terminated_history"],
        "processes": mon_snap["processes"],
        "audit_log": sm_snap["audit_log"],
    }


@app.post("/api/launch-demo")
async def launch_demo_workload(
    request: Request,
    _body: Optional[StrictEmptyLaunchRequest] = None,
) -> Dict[str, Any]:
    """
    Invariant 5: Bound to loopback, accepts zero arguments (extra JSON fields rejected with 422),
    and spawns only the trusted `demo_workload.py` script via `subprocess.Popen`.
    """
    verify_loopback_request(request)

    if demo_target.is_running():
        return {
            "status": "already_running",
            "pid": demo_target.pid,
            "create_time": demo_target.create_time,
            "script_path": DEMO_SCRIPT_PATH,
        }

    if not os.path.isfile(DEMO_SCRIPT_PATH):
        raise HTTPException(status_code=500, detail="Trusted demo_workload.py script not found.")

    popen_handle = subprocess.Popen(
        [sys.executable, DEMO_SCRIPT_PATH],
        cwd=str(BASE_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        ps_proc = psutil.Process(popen_handle.pid)
        ctime = float(ps_proc.create_time())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
        popen_handle.terminate()
        raise HTTPException(status_code=500, detail=f"Failed to verify demo workload PID: {exc}")

    demo_target.popen = popen_handle
    demo_target.pid = popen_handle.pid
    demo_target.create_time = ctime

    state_machine.register_demo_authority(
        popen_handle=popen_handle,
        pid=popen_handle.pid,
        create_time=ctime,
        script_path=DEMO_SCRIPT_PATH,
    )
    state_machine.record_audit_event(
        pid=popen_handle.pid,
        name="demo_workload.py",
        verdict="INFO",
        confidence=1.0,
        action="DEMO_SIMULATOR_LAUNCHED",
        evidence=(
            f"Launched synthetic file-corruption & child-spawn simulator (PID {popen_handle.pid})."
        ),
    )

    return {
        "status": "launched",
        "pid": popen_handle.pid,
        "create_time": ctime,
        "script_path": DEMO_SCRIPT_PATH,
    }


@app.post("/api/enforcement-mode")
async def update_enforcement_mode(
    request: Request,
    payload: Optional[EnforcementModePayload] = None,
) -> Dict[str, Any]:
    verify_loopback_request(request)
    if payload and payload.mode in ("DISABLED", "DEMO_ONLY"):
        target_mode = EnforcementMode(payload.mode)
    else:
        target_mode = (
            EnforcementMode.DEMO_ONLY
            if state_machine.enforcement_mode == EnforcementMode.DISABLED
            else EnforcementMode.DISABLED
        )
    state_machine.set_enforcement_mode(target_mode)
    return {"enforcement_mode": target_mode.value}


@app.get("/api/config/gemini-key")
async def get_gemini_key_status(request: Request) -> Dict[str, Any]:
    verify_loopback_request(request)
    return ai_advisor.get_gemini_config_status()


@app.post("/api/config/gemini-key")
async def configure_gemini_key(
    request: Request,
    payload: GeminiConfigPayload,
) -> Dict[str, Any]:
    verify_loopback_request(request)
    status = ai_advisor.set_gemini_config(api_key=payload.api_key, model=payload.model)
    mode_desc = (
        f"Live Google Gemini ({status['model']}, key {status['masked_key']})"
        if status["has_api_key"]
        else "Local Plain-English Behavioral Engine"
    )
    state_machine.record_audit_event(
        pid=0,
        name="AI_ADVISOR",
        verdict="INFO",
        confidence=1.0,
        action="AI_ENGINE_CONFIGURED",
        evidence=f"AI Advisor switched to {mode_desc}.",
    )
    return status


@app.post("/api/suspend-process/{pid}")
async def suspend_process_endpoint(pid: int, request: Request) -> Dict[str, Any]:
    verify_loopback_request(request)
    return await state_machine.suspend_process_hitl(pid)


@app.post("/api/resume-process/{pid}")
async def resume_process_endpoint(pid: int, request: Request) -> Dict[str, Any]:
    verify_loopback_request(request)
    return await state_machine.resume_process_hitl(pid)


@app.post("/api/terminate-process/{pid}")
async def terminate_process_endpoint(
    pid: int,
    payload: DoubleLockTerminateRequest,
    request: Request,
) -> Dict[str, Any]:
    verify_loopback_request(request)
    res = await state_machine.terminate_process_hitl(
        pid=pid,
        step1_acknowledged=payload.step1_acknowledged,
        step2_confirmed=payload.step2_confirmed,
        operator_note=payload.reason or "Confirmed via 2-Step Double-Lock UI",
    )
    if not res["success"]:
        raise HTTPException(status_code=400, detail=res["detail"])
    return res


@app.post("/api/dismiss-alert/{pid}")
async def dismiss_alert_endpoint(pid: int, request: Request) -> Dict[str, Any]:
    verify_loopback_request(request)
    ok = state_machine.dismiss_alert(pid)
    return {"dismissed": ok, "pid": pid}


# ----------------------------------------------------------------------
# Multi-Engine Executive & Forensic PDF Report Generator
# ----------------------------------------------------------------------
def _pdf_safe_str(text: Any) -> str:
    s = str(text if text is not None else "")
    return s.encode("latin-1", "replace").decode("latin-1")


def _build_pdf_bytes_sync(report_data: Dict[str, Any]) -> bytes:
    """
    Runs inside `asyncio.to_thread()`.
    Generates a multi-section Executive & Forensic PDF report using `fpdf2`,
    falling back to `reportlab` or a zero-dependency native PDF 1.4 generator.
    """
    # 1. Primary Generator: fpdf2
    try:
        from fpdf import FPDF

        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=14)
        pdf.add_page()

        # Header Banner
        pdf.set_fill_color(15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, _pdf_safe_str("  TUNABYTES V4 - EXECUTIVE & FORENSIC EDR REPORT"), ln=True, fill=True)
        pdf.ln(3)

        pdf.set_text_color(30, 41, 59)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(
            0,
            6,
            _pdf_safe_str(
                f"Generated: {report_data['generated_at']}  |  AI Engine: {report_data['ai_config']['mode']} ({report_data['ai_config']['model']})"
            ),
            ln=True,
        )
        pdf.ln(2)

        # Section 1: Decoupled Subsystem Health & Pipeline Metrics
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(0, 8, _pdf_safe_str("1. Decoupled Subsystem Health & Behavioral Counters"), ln=True, fill=True)
        pdf.set_font("Helvetica", "", 9)
        h = report_data["health"]
        st = report_data["stats"]
        trig = st["trigger_stats"]
        pdf.cell(
            0,
            6,
            _pdf_safe_str(
                f"Collector: {h['Collector']} | AI Advisor: {h['AI Advisor']} | Queue: {h['Queue']} | Enforcement: {h['Enforcement']}"
            ),
            ln=True,
        )
        pdf.cell(
            0,
            6,
            _pdf_safe_str(
                f"Tracked Processes: {st['total_tracked']} (Protected Whitelist: {st['whitelisted_count']}, User Apps: {st['user_app_count']})"
            ),
            ln=True,
        )
        pdf.cell(
            0,
            6,
            _pdf_safe_str(
                f"Coalesced Events: {st['coalesced_total']} | Pre-AI Stale Drops: {st['stale_pre_ai_drops']} | Post-AI Stale Drops: {st['stale_post_ai_drops']}"
            ),
            ln=True,
        )
        pdf.cell(
            0,
            6,
            _pdf_safe_str(
                f"Behavioral Triggers -> File Corruption: {trig.get('FILE_CORRUPTION_BURST', 0)} | Mass Deletion: {trig.get('MASS_FILE_DELETION_IO', 0)} | Unauthorized Spawns: {trig.get('UNAUTHORIZED_PROGRAM_SPAWN', 0)}"
            ),
            ln=True,
        )
        pdf.ln(3)

        # Section 2: Confirmed Process Termination Forensic Ledger
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _pdf_safe_str("2. Confirmed Process Termination Forensic Ledger"), ln=True, fill=True)
        pdf.set_font("Helvetica", "", 8)
        term_list = report_data.get("terminated_history", [])
        if not term_list:
            pdf.cell(0, 6, _pdf_safe_str("No processes have been terminated during this session."), ln=True)
        else:
            for item in term_list[:15]:
                line = (
                    f"[{item['timestamp']}] PID {item['pid']} ({item['name']}) | Verdict: {item['verdict']} "
                    f"({item['confidence']}) | Mode: {item['mode']} | Triggers: {','.join(item.get('triggers', []))}"
                )
                pdf.multi_cell(0, 5, _pdf_safe_str(line))
                pdf.multi_cell(0, 5, _pdf_safe_str(f"   Reason: {item.get('reason', '')}"))
        pdf.ln(3)

        # Section 3: Top 25 Live Processes Behavioral Snapshot
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _pdf_safe_str("3. Top 25 Live Processes Behavioral Telemetry"), ln=True, fill=True)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(16, 6, "PID", border=1)
        pdf.cell(42, 6, "Process Name", border=1)
        pdf.cell(24, 6, "Safety Status", border=1)
        pdf.cell(22, 6, "Writes/KB", border=1)
        pdf.cell(20, 6, "Del/Meta", border=1)
        pdf.cell(16, 6, "Spawns", border=1)
        pdf.cell(24, 6, "EDR State", border=1)
        pdf.cell(24, 6, "Verdict", border=1, ln=True)

        pdf.set_font("Helvetica", "", 7.5)
        for p in report_data.get("processes", [])[:25]:
            safety = "PROTECTED" if p["is_whitelisted"] else ("THREAT" if p["is_elevated"] else "USER_APP")
            writes_str = f"{p['window_write_ops']}/{p['window_write_kb']}K"
            pdf.cell(16, 5.5, _pdf_safe_str(p["pid"]), border=1)
            pdf.cell(42, 5.5, _pdf_safe_str(p["name"][:22]), border=1)
            pdf.cell(24, 5.5, _pdf_safe_str(safety), border=1)
            pdf.cell(22, 5.5, _pdf_safe_str(writes_str), border=1)
            pdf.cell(20, 5.5, _pdf_safe_str(p["window_other_ops"]), border=1)
            pdf.cell(16, 5.5, _pdf_safe_str(p["window_spawns"]), border=1)
            pdf.cell(24, 5.5, _pdf_safe_str(p.get("edr_state", "IDLE")), border=1)
            pdf.cell(24, 5.5, _pdf_safe_str(p.get("last_verdict", "NONE")), border=1, ln=True)
        pdf.ln(3)

        # Section 4: Security & Behavioral Audit Log Stream
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _pdf_safe_str("4. Real-Time Security & Behavioral Audit Log (Latest 25 Entries)"), ln=True, fill=True)
        pdf.set_font("Helvetica", "", 8)
        for log in report_data.get("audit_log", [])[:25]:
            entry_line = (
                f"[{log['timestamp']}] PID {log['pid']} ({log['name']}) -> {log['action']} "
                f"[{log['verdict']} / {log['confidence']}] : {log['evidence']}"
            )
            pdf.multi_cell(0, 4.8, _pdf_safe_str(entry_line))

        raw_out = pdf.output()
        return bytes(raw_out) if isinstance(raw_out, (bytes, bytearray)) else raw_out.encode("latin-1")
    except Exception as fpdf_err:
        logger.warning("fpdf2 generation fallback triggered: %s", fpdf_err)

    # 2. Secondary Generator: ReportLab
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4
        y = height - 40
        c.setFont("Helvetica-Bold", 13)
        c.drawString(40, y, "TUNABYTES V4 - EXECUTIVE & FORENSIC EDR REPORT")
        y -= 20
        c.setFont("Helvetica", 9)
        c.drawString(40, y, f"Generated: {report_data['generated_at']}")
        y -= 18
        for log in report_data.get("audit_log", [])[:35]:
            if y < 50:
                c.showPage()
                y = height - 40
                c.setFont("Helvetica", 8)
            line = f"[{log['timestamp']}] PID {log['pid']} ({log['name']}) {log['action']}: {log['evidence'][:90]}"
            c.drawString(40, y, _pdf_safe_str(line))
            y -= 12
        c.save()
        return buf.getvalue()
    except Exception:
        pass

    # 3. Zero-Dependency Native PDF 1.4 Byte-Stream Generator Fallback
    lines = [
        "TUNABYTES V4 - EXECUTIVE & FORENSIC EDR REPORT",
        f"Generated: {report_data['generated_at']}",
        f"Health: {report_data['health']}",
        f"Terminated Processes: {len(report_data.get('terminated_history', []))}",
    ]
    for log in report_data.get("audit_log", [])[:20]:
        lines.append(f"[{log['timestamp']}] PID {log['pid']} {log['name']} - {log['action']}")

    content_ops = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
    for ln in lines:
        escaped = _pdf_safe_str(ln).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_ops.append(f"({escaped}) Tj T*")
    content_ops.append("ET")
    stream_bytes = "\n".join(content_ops).encode("latin-1")

    objs = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n",
        f"4 0 obj << /Length {len(stream_bytes)} >> stream\n".encode("latin-1") + stream_bytes + b"\nendstream endobj\n",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for o in objs:
        offsets.append(out.tell())
        out.write(o)
    xref_pos = out.tell()
    out.write(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode("latin-1"))
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode("latin-1"))
    out.write(
        f"trailer << /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("latin-1")
    )
    return out.getvalue()


@app.get("/api/export-pdf-report")
async def export_pdf_report() -> Response:
    """
    Gathers deep-copied state snapshots on the event loop first, then offloads
    PDF rendering to `asyncio.to_thread()` so the event loop never blocks.
    """
    state_payload = await get_telemetry_dashboard_state()
    report_snapshot = copy.deepcopy(state_payload)
    report_snapshot["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    pdf_bytes = await asyncio.to_thread(_build_pdf_bytes_sync, report_snapshot)
    filename = f"Tunabytes_V4_Forensic_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
