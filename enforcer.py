"""
Tunabytes V4 - Protected OS Enforcer, User Warning Queue & Forensic Recorder (enforcer.py)
- Strictly protects OS system directories (C:\\Windows, C:\\Program Files, etc.), critical
  system services, and common user applications from accidental termination.
- Instead of blindly terminating processes on a CPU spike, creates a `PendingWarning`
  alert containing CPU cycles, RAM, Disk Writes, System Logs, and the Gemini AI verdict.
- Waits for explicit User Confirmation ("Approve & Terminate" vs "Dismiss & Whitelist")
  before instructing the OS to stop a flagged process.
- Stores persistent JSON and PDF forensic reports in `reports/` whenever a confirmed
  malicious app is terminated.
"""

from __future__ import annotations

import asyncio
from collections import deque
import copy
from datetime import datetime, timezone
import io
import json
import logging
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("tunabytes.enforcer")

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
TERMINATED_JSON_PATH = REPORTS_DIR / "terminated_apps_log.json"

# Critical OS processes and essential desktop apps that must NEVER be terminated
CRITICAL_OS_PROCESS_NAMES: Set[str] = {
    "system",
    "idle",
    "registry",
    "memory compression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "securityhealthservice.exe",
    "msmpeng.exe",
    "nisrv.exe",
    "audiodg.exe",
    "conhost.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "ctfmon.exe",
    "lsaiso.exe",
    "wlanext.exe",
    "dashost.exe",
    "applicationframehost.exe",
    "systemsettings.exe",
    "taskmgr.exe",
    "code.exe",
    "devenv.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "systemd",
    "init",
    "kthreadd",
    "launchd",
}

# Protected OS system directories (binaries installed here are trusted unless running an external script)
PROTECTED_PATH_PREFIXES_WIN: Tuple[str, ...] = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
)

PROTECTED_PATH_PREFIXES_POSIX: Tuple[str, ...] = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/lib/",
    "/system/",
)


def is_process_system_protected(
    pid: int,
    name: str,
    exe_path: str,
    cmdline_str: str = "",
    self_pid: Optional[int] = None,
    parent_pid: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Determines whether a process is a protected OS/system binary or part of Tunabytes itself.
    """
    if pid <= 4:
        return True, "OS Kernel Process (PID <= 4)"

    own_pid = self_pid or os.getpid()
    own_ppid = parent_pid or os.getppid()
    if pid in (own_pid, own_ppid):
        return True, "Tunabytes EDR Host Process"

    clean_name = (name or "").strip().lower()
    clean_exe = (exe_path or "").strip().lower()
    clean_cmd = (cmdline_str or "").strip().lower()

    # Never protect the synthetic demo_workload.py test script
    if "demo_workload.py" in clean_cmd or "demo_workload.py" in clean_exe:
        return False, ""

    # Protect Tunabytes' own uvicorn / main.py process
    if "main.py" in clean_cmd or "uvicorn" in clean_cmd:
        return True, "Tunabytes FastAPI Server"

    if clean_name in CRITICAL_OS_PROCESS_NAMES:
        return True, f"Protected OS/System Service ({name})"

    # If it is a scripting interpreter (python/powershell/cmd/node/wscript), check if it runs a user script
    interpreters = ("python", "python.exe", "pythonw.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "node.exe", "wscript.exe", "cscript.exe")
    if clean_name not in interpreters:
        for prefix in PROTECTED_PATH_PREFIXES_WIN:
            if clean_exe.startswith(prefix):
                return True, f"Protected Windows System Directory ({prefix})"
        for prefix in PROTECTED_PATH_PREFIXES_POSIX:
            if clean_exe.startswith(prefix):
                return True, f"Protected OS System Directory ({prefix})"

    return False, ""


def _clean_pdf_text(text: Any, max_len: int = 240) -> str:
    raw = str(text if text is not None else "")
    raw = re.sub(r"[\x00-\x1f\x7f]", " ", raw)
    for k, v in {
        "\u2014": "--",
        "\u2013": "-",
        "\u2022": "*",
        "\u2264": "<=",
        "\u2265": ">=",
        "\u0394": "Delta",
    }.items():
        raw = raw.replace(k, v)
    return raw.encode("latin-1", errors="replace").decode("latin-1")[:max_len]


def _render_single_incident_pdf(record: Dict[str, Any]) -> bytes:
    """Generates a standalone forensic PDF report for a terminated application."""
    try:
        from fpdf import FPDF

        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_fill_color(127, 29, 29)
        pdf.rect(0, 0, 210, 26, style="F")
        pdf.set_xy(10, 7)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(254, 202, 202)
        pdf.cell(125, 7, "TUNABYTES V4 // AI-VERIFIED TERMINATION REPORT", ln=0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(65, 7, _clean_pdf_text(record.get("incident_id", ""), 30), ln=1, align="R")

        pdf.set_xy(10, 15)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(254, 226, 226)
        pdf.cell(
            190,
            5,
            _clean_pdf_text(
                f"Terminated At (UTC): {record.get('terminated_at_utc')}   |   "
                f"AI Engine: {record.get('ai_provider', 'GEMINI_LIVE')}   |   Host: {record.get('host_platform')}"
            ),
            ln=1,
        )
        pdf.ln(10)

        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, "1. TERMINATED APPLICATION & AUTHORIZATION DETAILS", ln=1)
        pdf.set_draw_color(203, 213, 225)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        fields = [
            ("Incident ID", record.get("incident_id")),
            ("Process Name & PID", f"{record.get('process_name')} (PID: {record.get('pid')}, ctime: {record.get('creation_time')})"),
            ("Executable / Command", record.get("exe_path")),
            ("Parent Process", f"{record.get('parent_name', 'unknown')} (PPID: {record.get('parent_pid', 0)})"),
            ("Authorization Source", record.get("trigger_source")),
            ("OS Termination Method", record.get("termination_method")),
            ("OS Termination Status", record.get("os_status")),
        ]
        for label, val in fields:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_fill_color(241, 245, 249)
            pdf.cell(52, 6.5, _clean_pdf_text(label, 30), border=1, fill=True)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.cell(138, 6.5, _clean_pdf_text(val, 95), border=1, ln=1)

        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, "2. GEMINI AI VERDICT, CPU CYCLES, RAM & DISK TELEMETRY", ln=1)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        verdict_fields = [
            ("AI Verdict & Confidence", f"{record.get('verdict')} ({int(round(float(record.get('confidence', 0.0)) * 100))}%) via {record.get('ai_provider', 'GEMINI')}"),
            ("CPU Utilization & Cycles", f"Peak: {float(record.get('peak_cpu_percent', 0.0)):.1f}% | Avg: {float(record.get('avg_cpu_percent', 0.0)):.1f}% | CPU Time: {float(record.get('cpu_cycles_total_s', 0.0)):.2f}s"),
            ("Memory RSS Usage", f"{float(record.get('peak_memory_mb', 0.0)):.2f} MB"),
            ("Disk Write / Read Activity", f"Write Delta: {float(record.get('window_write_kb', 0.0)):.2f} KB | Read Delta: {float(record.get('window_read_kb', 0.0)):.2f} KB"),
        ]
        for label, val in verdict_fields:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_fill_color(254, 242, 242)
            pdf.cell(52, 6.5, _clean_pdf_text(label, 30), border=1, fill=True)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.cell(138, 6.5, _clean_pdf_text(val, 95), border=1, ln=1)

        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.cell(0, 6, "AI Forensic Evidence:", ln=1)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.multi_cell(190, 5.5, _clean_pdf_text(record.get("evidence", ""), 350), border=1)
        pdf.ln(4)

        sys_logs: List[str] = record.get("system_logs", [])
        if sys_logs:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6.5, "3. CAPTURED OS SYSTEM EVENT LOG CONTEXT", ln=1)
            pdf.set_font("Courier", "", 7)
            for log_line in sys_logs[:6]:
                pdf.multi_cell(190, 4.2, _clean_pdf_text(log_line, 200), border=1)

        out = pdf.output()
        return bytes(out) if isinstance(out, (bytes, bytearray)) else str(out).encode("latin-1")
    except Exception:
        # Fallback minimal PDF 1.4
        stream = f"BT /F1 10 Tf 36 780 Td (TUNABYTES TERMINATION REPORT {record.get('incident_id')} - PID {record.get('pid')}) Tj ET".encode("latin-1")
        return b"%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF"


class OSEnforcer:
    """
    Manages:
    1. User Warning & Confirmation Queue (`_pending_warnings`) so the user is always warned
       with full AI + telemetry + system log evidence before an application is shut down.
    2. Process Whitelist (`_whitelisted_keys`) for user-approved safe processes.
    3. Direct OS Termination (`terminate_and_record`) with strict System File protection.
    4. Persistent Forensic Reports (`reports/terminated_apps_log.json` + individual PDFs).
    """

    def __init__(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self._self_pid: int = os.getpid()
        self._parent_pid: int = os.getppid()
        self._history: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._pending_warnings: Dict[str, Dict[str, Any]] = {}
        self._whitelisted_keys: Set[Tuple[int, float]] = set()
        self._incident_counter: int = 0
        self._warning_counter: int = 0
        self._load_existing_history()

    def _load_existing_history(self) -> None:
        if TERMINATED_JSON_PATH.is_file():
            try:
                data = json.loads(TERMINATED_JSON_PATH.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data[:200]:
                        self._history.append(item)
                    self._incident_counter = len(self._history)
            except Exception as exc:
                logger.warning("Could not load existing terminated apps history: %s", exc)

    def is_whitelisted(self, pid: int, creation_time: float) -> bool:
        for w_pid, w_ctime in self._whitelisted_keys:
            if w_pid == pid and abs(w_ctime - creation_time) <= 1.5:
                return True
        return False

    def create_or_update_warning(
        self,
        pid: int,
        creation_time: float,
        process_name: str,
        exe_path: str,
        parent_pid: int,
        parent_name: str,
        verdict: str,
        confidence: float,
        evidence: str,
        ai_provider: str,
        samples: List[Dict[str, Any]],
        system_logs: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Queues a live User Warning asking whether the flagged malicious application
        should be shut down. Never queues protected OS/system processes or whitelisted apps.
        """
        is_prot, _ = is_process_system_protected(
            pid, process_name, exe_path, exe_path, self._self_pid, self._parent_pid
        )
        if is_prot or self.is_whitelisted(pid, creation_time):
            return None

        # Check if there is already an active warning for this (pid, creation_time)
        for wid, existing in list(self._pending_warnings.items()):
            if existing["pid"] == pid and abs(existing["creation_time"] - creation_time) <= 1.5:
                if psutil.pid_exists(pid):
                    existing["confidence"] = round(float(confidence), 4)
                    existing["evidence"] = evidence
                    existing["samples"] = copy.deepcopy(samples)
                    existing["system_logs"] = list(system_logs[:8])
                    existing["updated_at_utc"] = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                    return copy.deepcopy(existing)
                else:
                    del self._pending_warnings[wid]

        self._warning_counter += 1
        now_utc = datetime.now(timezone.utc)
        warning_id = f"WARN-{now_utc.strftime('%H%M%S')}-{self._warning_counter:03d}"

        peak_cpu = max((float(s.get("cpu_percent", 0.0)) for s in samples), default=0.0)
        avg_cpu = sum(float(s.get("cpu_percent", 0.0)) for s in samples) / max(1, len(samples))
        peak_mem = max((float(s.get("memory_rss_mb", 0.0)) for s in samples), default=0.0)
        total_write_kb = round(sum(int(s.get("write_bytes_delta", 0)) for s in samples) / 1024.0, 2)
        total_read_kb = round(sum(int(s.get("read_bytes_delta", 0)) for s in samples) / 1024.0, 2)
        cpu_cycles_s = round(
            max(
                (float(s.get("cpu_user_s", 0.0)) + float(s.get("cpu_system_s", 0.0)) for s in samples),
                default=0.0,
            ),
            2,
        )

        warning_obj: Dict[str, Any] = {
            "warning_id": warning_id,
            "created_at_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "updated_at_utc": now_utc.strftime("%H:%M:%S UTC"),
            "pid": pid,
            "creation_time": creation_time,
            "process_name": process_name,
            "exe_path": exe_path,
            "parent_pid": parent_pid,
            "parent_name": parent_name,
            "verdict": verdict,
            "confidence": round(float(confidence), 4),
            "evidence": evidence,
            "ai_provider": ai_provider,
            "peak_cpu_percent": round(peak_cpu, 1),
            "avg_cpu_percent": round(avg_cpu, 1),
            "cpu_cycles_total_s": cpu_cycles_s,
            "peak_memory_mb": round(peak_mem, 1),
            "window_write_kb": total_write_kb,
            "window_read_kb": total_read_kb,
            "samples": copy.deepcopy(samples),
            "system_logs": list(system_logs[:8]),
        }
        self._pending_warnings[warning_id] = warning_obj
        return copy.deepcopy(warning_obj)

    def get_pending_warnings(self) -> List[Dict[str, Any]]:
        """Return active warnings, automatically pruning any process that has already exited."""
        active_list: List[Dict[str, Any]] = []
        for wid, w in list(self._pending_warnings.items()):
            try:
                p = psutil.Process(int(w["pid"]))
                if abs(p.create_time() - float(w["creation_time"])) <= 1.5 and p.is_running():
                    active_list.append(copy.deepcopy(w))
                else:
                    del self._pending_warnings[wid]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                del self._pending_warnings[wid]
        return active_list

    def dismiss_and_whitelist_warning(self, warning_id: str) -> Optional[Dict[str, Any]]:
        """User chose NOT to shut down the app; whitelist `(pid, creation_time)`."""
        w = self._pending_warnings.pop(warning_id, None)
        if w is None:
            return None
        self._whitelisted_keys.add((int(w["pid"]), float(w["creation_time"])))
        return w

    async def approve_warning_and_terminate(self, warning_id: str) -> Optional[Dict[str, Any]]:
        """User confirmed the warning prompt -> instruct the OS to terminate the flagged app."""
        w = self._pending_warnings.pop(warning_id, None)
        if w is None:
            return None

        return await self.terminate_and_record(
            pid=int(w["pid"]),
            creation_time=float(w["creation_time"]),
            process_name=str(w["process_name"]),
            exe_path=str(w["exe_path"]),
            parent_pid=int(w.get("parent_pid", 0)),
            parent_name=str(w.get("parent_name", "unknown")),
            verdict=str(w["verdict"]),
            confidence=float(w["confidence"]),
            evidence=str(w["evidence"]),
            ai_provider=str(w.get("ai_provider", "GEMINI_LIVE")),
            samples=w.get("samples", []),
            system_logs=w.get("system_logs", []),
            trigger_source=f"USER_CONFIRMED_AI_WARNING ({warning_id})",
        )

    async def terminate_and_record(
        self,
        pid: int,
        creation_time: Optional[float],
        process_name: str,
        exe_path: str,
        parent_pid: int,
        parent_name: str,
        verdict: str,
        confidence: float,
        evidence: str,
        ai_provider: str,
        samples: List[Dict[str, Any]],
        system_logs: List[str],
        trigger_source: str = "USER_CONFIRMED_AI_WARNING",
    ) -> Dict[str, Any]:
        """
        Directly instructs the OS to stop and terminate a verified malicious application
        and writes its forensic JSON + PDF report to `reports/`.
        """
        # Remove any pending warning for this PID
        for wid, w in list(self._pending_warnings.items()):
            if w["pid"] == pid:
                del self._pending_warnings[wid]

        self._incident_counter += 1
        now_utc = datetime.now(timezone.utc)
        incident_id = f"INC-{now_utc.strftime('%Y%m%d-%H%M%S')}-{self._incident_counter:03d}"

        record = await asyncio.to_thread(
            self._execute_os_termination_sync,
            incident_id=incident_id,
            now_utc=now_utc,
            pid=pid,
            expected_ctime=creation_time,
            process_name=process_name,
            exe_path=exe_path,
            parent_pid=parent_pid,
            parent_name=parent_name,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            ai_provider=ai_provider,
            samples=copy.deepcopy(samples),
            system_logs=list(system_logs[:8]),
            trigger_source=trigger_source,
        )

        if record.get("terminated_success"):
            self._history.appendleft(copy.deepcopy(record))
            await asyncio.to_thread(self._persist_history_to_disk_sync, list(self._history), record)

        return record

    def _execute_os_termination_sync(
        self,
        incident_id: str,
        now_utc: datetime,
        pid: int,
        expected_ctime: Optional[float],
        process_name: str,
        exe_path: str,
        parent_pid: int,
        parent_name: str,
        verdict: str,
        confidence: float,
        evidence: str,
        ai_provider: str,
        samples: List[Dict[str, Any]],
        system_logs: List[str],
        trigger_source: str,
    ) -> Dict[str, Any]:
        is_protected, protect_reason = is_process_system_protected(
            pid, process_name, exe_path, exe_path, self._self_pid, self._parent_pid
        )
        if is_protected:
            return {
                "incident_id": incident_id,
                "terminated_success": False,
                "action_code": "BLOCKED_PROTECTED_OS_PROCESS",
                "os_status": f"Protected ({protect_reason})",
                "detail": f"OS Safeguard blocked termination of protected system file {process_name} (PID {pid}): {protect_reason}",
            }

        peak_cpu = max((float(s.get("cpu_percent", 0.0)) for s in samples), default=0.0)
        avg_cpu = sum(float(s.get("cpu_percent", 0.0)) for s in samples) / max(1, len(samples))
        peak_mem = max((float(s.get("memory_rss_mb", 0.0)) for s in samples), default=0.0)
        total_write_kb = round(sum(int(s.get("write_bytes_delta", 0)) for s in samples) / 1024.0, 2)
        total_read_kb = round(sum(int(s.get("read_bytes_delta", 0)) for s in samples) / 1024.0, 2)
        cpu_cycles_s = round(
            max(
                (float(s.get("cpu_user_s", 0.0)) + float(s.get("cpu_system_s", 0.0)) for s in samples),
                default=0.0,
            ),
            2,
        )

        username = "unknown"
        actual_ctime = expected_ctime or 0.0
        full_cmdline = exe_path
        methods_used: List[str] = []
        terminated_ok = False
        os_status_msg = "UNKNOWN"

        try:
            proc = psutil.Process(pid)
            actual_ctime = round(float(proc.create_time()), 3)

            if expected_ctime is not None and expected_ctime > 0:
                if abs(actual_ctime - expected_ctime) > 1.5:
                    return {
                        "incident_id": incident_id,
                        "terminated_success": False,
                        "action_code": "ABORTED_PID_REUSE_DETECTED",
                        "os_status": "PID Reused by OS",
                        "detail": f"Aborted OS kill for PID {pid}: creation_time changed.",
                    }

            try:
                username = proc.username()
            except Exception:
                pass

            try:
                cmdline_list = proc.cmdline()
                if cmdline_list:
                    full_cmdline = " ".join(cmdline_list)[:260]
            except Exception:
                pass

            # Re-verify protection using actual OS exe/cmdline
            prot_check, prot_msg = is_process_system_protected(
                pid, proc.name(), proc.exe(), full_cmdline, self._self_pid, self._parent_pid
            )
            if prot_check:
                return {
                    "incident_id": incident_id,
                    "terminated_success": False,
                    "action_code": "BLOCKED_PROTECTED_OS_PROCESS",
                    "os_status": f"Protected ({prot_msg})",
                    "detail": f"OS Safeguard blocked termination of {proc.name()} (PID {pid}): {prot_msg}",
                }

            # Stage 1: Suspend threads in RAM
            try:
                proc.suspend()
                methods_used.append("psutil.suspend()")
            except Exception:
                pass

            # Stage 2: Standard OS Terminate
            proc.terminate()
            methods_used.append("psutil.terminate()")

            try:
                proc.wait(timeout=1.5)
                terminated_ok = True
                os_status_msg = "TERMINATED_BY_OS (Graceful)"
            except psutil.TimeoutExpired:
                proc.kill()
                methods_used.append("psutil.kill()")
                proc.wait(timeout=1.0)
                terminated_ok = True
                os_status_msg = "FORCE_KILLED_BY_OS"

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            terminated_ok = True
            methods_used.append("process_already_exited")
            os_status_msg = "TERMINATED (Exited During Containment)"
        except psutil.AccessDenied as exc:
            return {
                "incident_id": incident_id,
                "terminated_success": False,
                "action_code": "OS_TERMINATE_ACCESS_DENIED",
                "os_status": f"AccessDenied ({exc})",
                "detail": f"OS denied permission to terminate PID {pid} ({process_name}).",
            }

        pdf_filename = f"Terminated_{incident_id}_PID_{pid}.pdf"
        return {
            "incident_id": incident_id,
            "terminated_success": terminated_ok,
            "action_code": "TERMINATED_MALICIOUS_APP" if terminated_ok else "TERMINATION_FAILED",
            "terminated_at_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "timestamp_iso": now_utc.isoformat(),
            "host_platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "pid": pid,
            "creation_time": actual_ctime,
            "process_name": process_name,
            "exe_path": full_cmdline or exe_path or process_name,
            "parent_pid": parent_pid,
            "parent_name": parent_name,
            "username": username,
            "trigger_source": trigger_source,
            "termination_method": " -> ".join(methods_used) or "OS_TERMINATE",
            "os_status": os_status_msg,
            "verdict": verdict,
            "confidence": round(float(confidence), 4),
            "evidence": evidence,
            "ai_provider": ai_provider,
            "peak_cpu_percent": round(peak_cpu, 2),
            "avg_cpu_percent": round(avg_cpu, 2),
            "cpu_cycles_total_s": cpu_cycles_s,
            "peak_memory_mb": round(peak_mem, 2),
            "window_write_kb": total_write_kb,
            "window_read_kb": total_read_kb,
            "sample_count": len(samples),
            "samples": samples,
            "system_logs": system_logs,
            "report_pdf_filename": pdf_filename,
            "report_pdf_path": str((REPORTS_DIR / pdf_filename).resolve()),
            "detail": (
                f"OS terminated malicious app '{process_name}' (PID {pid}) via "
                f"{' -> '.join(methods_used)}. Forensic report saved to reports/{pdf_filename}."
            ),
        }

    def _persist_history_to_disk_sync(
        self, all_records: List[Dict[str, Any]], latest_record: Dict[str, Any]
    ) -> None:
        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            TERMINATED_JSON_PATH.write_text(
                json.dumps(all_records, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed writing terminated_apps_log.json: %s", exc)

        try:
            pdf_bytes = _render_single_incident_pdf(latest_record)
            pdf_path = REPORTS_DIR / latest_record["report_pdf_filename"]
            pdf_path.write_bytes(pdf_bytes)
        except Exception as exc:
            logger.error("Failed writing individual terminated app PDF: %s", exc)

    def get_terminated_reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [copy.deepcopy(r) for r in list(self._history)[:limit]]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        for r in self._history:
            if r.get("incident_id") == incident_id:
                return copy.deepcopy(r)
        return None

    async def get_or_build_incident_pdf(self, incident_id: str) -> Optional[Tuple[bytes, str]]:
        rec = self.get_incident_by_id(incident_id)
        if rec is None:
            return None
        filename = rec.get("report_pdf_filename") or f"Terminated_{incident_id}.pdf"
        disk_path = REPORTS_DIR / filename
        if disk_path.is_file():
            data = await asyncio.to_thread(disk_path.read_bytes)
            return data, filename
        data = await asyncio.to_thread(_render_single_incident_pdf, rec)
        return data, filename