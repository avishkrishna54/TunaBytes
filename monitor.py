"""
monitor.py
Tunabytes V4 — Event-Loop-Owned Behavioral Telemetry Collector.

Enforces:
- Invariant 1: Single-owner `(PID, creation_time)` registry, `asyncio.to_thread()` read-only
  psutil enumeration, `deque(maxlen=7)`, 30.0s monotonic pruning, and `copy.deepcopy()`.
- Section 2A: Behavioral Threat Detection ONLY (NEVER flags high RAM or CPU alone!).
  Detects:
    1. FILE_CORRUPTION_BURST (rapid file write ops + high write byte velocity)
    2. MASS_FILE_DELETION_IO (metadata/rename/unlink I/O spikes or destructive command lines)
    3. UNAUTHORIZED_PROGRAM_SPAWN (parent-child PID tracking of unexpected child processes)
"""

from __future__ import annotations

import asyncio
import copy
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Deque, Dict, List, Optional, Set, Tuple

import psutil

from state_machine import is_process_whitelisted

logger = logging.getLogger("tunabytes.monitor")

ProcessKey = Tuple[int, float]

# Suspicious child shells/utilities when spawned by a non-whitelisted user process
SUSPICIOUS_CHILD_BINARIES: Set[str] = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "reg.exe",
    "schtasks.exe",
    "vssadmin.exe",
    "wbadmin.exe",
    "bcdedit.exe",
}

DESTRUCTIVE_CMDLINE_PATTERNS: Tuple[str, ...] = (
    "vssadmin delete shadows",
    "wbadmin delete",
    "cipher /w:",
    "del /f /s /q",
    "rmdir /s /q",
    "bcdedit /set",
    ".corrupted",
    "tunabytes_sandbox_corruption",
)


class CollectorHealthState(str, Enum):
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPED = "STOPPED"


@dataclass
class ProcessBucket:
    pid: int
    create_time: float
    name: str
    exe_path: str
    cmdline: str
    ppid: int
    is_whitelisted: bool
    whitelist_reason: str
    samples: Deque[Dict[str, Any]] = field(default_factory=lambda: deque(maxlen=7))
    last_write_ops: Optional[int] = None
    last_write_bytes: Optional[int] = None
    last_other_ops: Optional[int] = None
    known_child_pids: Set[int] = field(default_factory=set)
    baseline_established: bool = False
    last_seen_mono: float = 0.0


def _read_only_enumerate_processes() -> Tuple[List[Dict[str, Any]], float, float]:
    """
    Pure read-only function executed strictly inside `asyncio.to_thread()` (Invariant 1).
    Wraps every `psutil` call in `try/except (NoSuchProcess, AccessDenied, ZombieProcess)`
    and returns plain-data dictionaries without mutating any shared state.
    """
    captured_at_mono = time.monotonic()
    captured_at_wall = time.time()
    snapshot: List[Dict[str, Any]] = []

    try:
        iterator = psutil.process_iter(["pid", "name", "create_time", "ppid"])
    except Exception:
        return snapshot, captured_at_mono, captured_at_wall

    for proc in iterator:
        try:
            info = proc.info
            pid = info.get("pid")
            ctime = info.get("create_time")
            if pid is None or ctime is None or int(pid) == 0:
                continue

            pid_int = int(pid)
            ctime_float = float(ctime)
            name_str = str(info.get("name") or f"pid-{pid_int}")
            ppid_int = int(info.get("ppid") or 0)

            exe_str = ""
            try:
                exe_str = str(proc.exe() or "")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            cmdline_str = ""
            try:
                cmdline_list = proc.cmdline()
                if cmdline_list:
                    cmdline_str = " ".join(str(part) for part in cmdline_list)[:400]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            cpu_pct = 0.0
            try:
                cpu_pct = round(float(proc.cpu_percent(interval=None) or 0.0), 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            mem_mb = 0.0
            try:
                mem_info = proc.memory_info()
                if mem_info is not None:
                    mem_mb = round(float(mem_info.rss) / (1024.0 * 1024.0), 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            write_ops = 0
            write_bytes = 0
            other_ops = 0
            try:
                io = proc.io_counters()
                if io is not None:
                    write_ops = int(getattr(io, "write_count", 0))
                    write_bytes = int(getattr(io, "write_bytes", 0))
                    other_ops = int(getattr(io, "other_count", 0))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
                pass

            os_status = "running"
            try:
                os_status = str(proc.status() or "running")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

            snapshot.append(
                {
                    "pid": pid_int,
                    "create_time": ctime_float,
                    "ppid": ppid_int,
                    "name": name_str,
                    "exe_path": exe_str,
                    "cmdline": cmdline_str,
                    "cpu_percent": cpu_pct,
                    "memory_rss_mb": mem_mb,
                    "write_ops_raw": write_ops,
                    "write_bytes_raw": write_bytes,
                    "other_ops_raw": other_ops,
                    "os_status": os_status,
                    "captured_at_mono": captured_at_mono,
                    "captured_at_wall": captured_at_wall,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return snapshot, captured_at_mono, captured_at_wall


class TelemetryMonitor:
    """
    Event-loop-owned behavioral telemetry monitor (Invariant 1).
    Exclusively owns `self._buckets` mapping `(PID, creation_time)` to `ProcessBucket`.
    """

    # Behavioral Detection Thresholds (Section 2A)
    WRITE_OPS_CORRUPTION_THRESHOLD: int = 12
    WRITE_BYTES_CORRUPTION_THRESHOLD: int = 180 * 1024  # 180 KB per 1.5s tick
    OTHER_OPS_DELETION_THRESHOLD: int = 24
    WRITE_OPS_DELETION_PAIR_THRESHOLD: int = 6

    def __init__(
        self,
        poll_interval_sec: float = 1.5,
        max_sample_age_sec: float = 30.0,
        on_behavioral_anomaly: Optional[
            Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]
        ] = None,
    ) -> None:
        self.poll_interval_sec = poll_interval_sec
        self.max_sample_age_sec = max_sample_age_sec
        self.on_behavioral_anomaly = on_behavioral_anomaly

        # Event-loop-owned registry (Invariant 1)
        self._buckets: Dict[ProcessKey, ProcessBucket] = {}
        self._health: CollectorHealthState = CollectorHealthState.STOPPED
        self._task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()
        self._consecutive_errors: int = 0

        # Behavioral trigger counters for SOC dashboard
        self.trigger_Stats: Dict[str, int] = {
            "FILE_CORRUPTION_BURST": 0,
            "MASS_FILE_DELETION_IO": 0,
            "UNAUTHORIZED_PROGRAM_SPAWN": 0,
        }

    @property
    def health(self) -> CollectorHealthState:
        return self._health

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._health = CollectorHealthState.RUNNING
            self._task = asyncio.create_task(self._collector_loop(), name="tunabytes-collector")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._health = CollectorHealthState.STOPPED

    def _evict_stale_samples(self, now_mono: float) -> None:
        """
        Invariant 1: Prunes any sample older than 30.0 seconds using `time.monotonic()`,
        and removes dead process buckets.
        """
        cutoff_mono = now_mono - self.max_sample_age_sec
        stale_keys: List[ProcessKey] = []

        for key, bucket in self._buckets.items():
            while bucket.samples and bucket.samples[0]["captured_at_mono"] < cutoff_mono:
                bucket.samples.popleft()
            if not bucket.samples or (now_mono - bucket.last_seen_mono) > self.max_sample_age_sec:
                stale_keys.append(key)

        for key in stale_keys:
            self._buckets.pop(key, None)

    async def _collector_loop(self) -> None:
        # Warm up psutil CPU counters in worker thread
        try:
            await asyncio.to_thread(_read_only_enumerate_processes)
        except Exception:
            pass

        while not self._stop_event.is_set():
            try:
                raw_list, batch_mono, _ = await asyncio.to_thread(_read_only_enumerate_processes)
                self._consecutive_errors = 0
                self._health = CollectorHealthState.RUNNING

                now_mono = time.monotonic()
                self._evict_stale_samples(now_mono)

                # Build parent -> children map for this tick to detect child spawns
                children_by_ppid: Dict[int, List[Dict[str, Any]]] = {}
                for item in raw_list:
                    ppid_val = item["ppid"]
                    if ppid_val > 0:
                        children_by_ppid.setdefault(ppid_val, []).append(item)

                for raw_proc in raw_list:
                    proc_copy = copy.deepcopy(raw_proc)
                    pid = proc_copy["pid"]
                    ctime = proc_copy["create_time"]
                    key: ProcessKey = (pid, ctime)

                    bucket = self._buckets.get(key)
                    if bucket is None:
                        whitelisted, w_reason = is_process_whitelisted(
                            pid,
                            proc_copy["name"],
                            proc_copy["exe_path"],
                            proc_copy["cmdline"],
                        )
                        bucket = ProcessBucket(
                            pid=pid,
                            create_time=ctime,
                            name=proc_copy["name"],
                            exe_path=proc_copy["exe_path"],
                            cmdline=proc_copy["cmdline"],
                            ppid=proc_copy["ppid"],
                            is_whitelisted=whitelisted,
                            whitelist_reason=w_reason,
                        )
                        self._buckets[key] = bucket

                    # Compute I/O deltas against previous sample
                    w_ops_raw = proc_copy["write_ops_raw"]
                    w_bytes_raw = proc_copy["write_bytes_raw"]
                    o_ops_raw = proc_copy["other_ops_raw"]

                    if bucket.last_write_ops is None:
                        write_ops_delta = 0
                        write_bytes_delta = 0
                        other_ops_delta = 0
                    else:
                        write_ops_delta = max(0, w_ops_raw - bucket.last_write_ops)
                        write_bytes_delta = max(0, w_bytes_raw - (bucket.last_write_bytes or 0))
                        other_ops_delta = max(0, o_ops_raw - (bucket.last_other_ops or 0))

                    bucket.last_write_ops = w_ops_raw
                    bucket.last_write_bytes = w_bytes_raw
                    bucket.last_other_ops = o_ops_raw

                    # Evaluate parent-child spawns
                    current_children = children_by_ppid.get(pid, [])
                    spawned_children_names: List[str] = []
                    if not bucket.baseline_established:
                        for ch in current_children:
                            bucket.known_child_pids.add(ch["pid"])
                        bucket.baseline_established = True
                    else:
                        for ch in current_children:
                            ch_pid = ch["pid"]
                            if ch_pid not in bucket.known_child_pids:
                                bucket.known_child_pids.add(ch_pid)
                                spawned_children_names.append(ch["name"])

                    # --------------------------------------------------------------
                    # Behavioral Threat Evaluation (NEVER flag high RAM or CPU alone!)
                    # --------------------------------------------------------------
                    anomaly_reasons: List[str] = []
                    if not bucket.is_whitelisted:
                        # 1. FILE_CORRUPTION_BURST
                        if (
                            write_ops_delta >= self.WRITE_OPS_CORRUPTION_THRESHOLD
                            and write_bytes_delta >= self.WRITE_BYTES_CORRUPTION_THRESHOLD
                        ):
                            anomaly_reasons.append("FILE_CORRUPTION_BURST")
                            self.trigger_Stats["FILE_CORRUPTION_BURST"] += 1

                        # 2. MASS_FILE_DELETION_IO
                        cmd_lower = bucket.cmdline.lower()
                        has_destructive_cmd = any(
                            pat in cmd_lower for pat in DESTRUCTIVE_CMDLINE_PATTERNS
                        )
                        if (
                            other_ops_delta >= self.OTHER_OPS_DELETION_THRESHOLD
                            and write_ops_delta >= self.WRITE_OPS_DELETION_PAIR_THRESHOLD
                        ) or (has_destructive_cmd and (write_ops_delta > 0 or other_ops_delta > 0)):
                            anomaly_reasons.append("MASS_FILE_DELETION_IO")
                            self.trigger_Stats["MASS_FILE_DELETION_IO"] += 1

                        # 3. UNAUTHORIZED_PROGRAM_SPAWN
                        if spawned_children_names:
                            has_suspicious_child = any(
                                cn.lower() in SUSPICIOUS_CHILD_BINARIES
                                for cn in spawned_children_names
                            )
                            is_simulator = (
                                "demo_workload" in cmd_lower
                                or "rogue_test" in cmd_lower
                                or "rogue_test" in bucket.name.lower()
                            )
                            if has_suspicious_child or is_simulator or len(spawned_children_names) >= 1:
                                anomaly_reasons.append("UNAUTHORIZED_PROGRAM_SPAWN")
                                self.trigger_Stats["UNAUTHORIZED_PROGRAM_SPAWN"] += 1

                    is_elevated = bool(anomaly_reasons) and not bucket.is_whitelisted

                    sample_dict: Dict[str, Any] = {
                        "pid": pid,
                        "create_time": ctime,
                        "name": bucket.name,
                        "cpu_percent": proc_copy["cpu_percent"],
                        "memory_rss_mb": proc_copy["memory_rss_mb"],
                        "write_ops_delta": write_ops_delta,
                        "write_bytes_delta": write_bytes_delta,
                        "other_ops_delta": other_ops_delta,
                        "spawned_children_delta": len(spawned_children_names),
                        "spawned_children_names": copy.deepcopy(spawned_children_names),
                        "anomaly_reasons": copy.deepcopy(anomaly_reasons),
                        "is_elevated": is_elevated,
                        "os_status": proc_copy["os_status"],
                        "captured_at_mono": proc_copy["captured_at_mono"],
                        "captured_at_wall": proc_copy["captured_at_wall"],
                    }

                    # Invariant 1: Store independent deepcopy in bounded deque(maxlen=7)
                    bucket.samples.append(copy.deepcopy(sample_dict))
                    bucket.last_seen_mono = batch_mono

                    if is_elevated and self.on_behavioral_anomaly is not None:
                        await self.on_behavioral_anomaly(
                            {
                                "pid": bucket.pid,
                                "create_time": bucket.create_time,
                                "name": bucket.name,
                                "exe_path": bucket.exe_path,
                                "cmdline": bucket.cmdline,
                                "captured_at_mono": sample_dict["captured_at_mono"],
                                "anomaly_reasons": copy.deepcopy(anomaly_reasons),
                                "window_samples": copy.deepcopy(list(bucket.samples)),
                            }
                        )

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._consecutive_errors += 1
                self._health = CollectorHealthState.DEGRADED
                logger.error("TelemetryMonitor loop error (%d): %s", self._consecutive_errors, exc)

            try:
                await asyncio.sleep(self.poll_interval_sec)
            except asyncio.CancelledError:
                break

    def get_telemetry_snapshot(self, limit: int = 50) -> Dict[str, Any]:
        """Returns deep-copied telemetry rows and summary counters for `/api/telemetry`."""
        now_mono = time.monotonic()
        self._evict_stale_samples(now_mono)

        rows: List[Dict[str, Any]] = []
        whitelisted_count = 0
        user_app_count = 0

        for bucket in self._buckets.values():
            if not bucket.samples:
                continue
            if bucket.is_whitelisted:
                whitelisted_count += 1
            else:
                user_app_count += 1

            latest = bucket.samples[-1]
            window_write_ops = sum(int(s["write_ops_delta"]) for s in bucket.samples)
            window_write_bytes = sum(int(s["write_bytes_delta"]) for s in bucket.samples)
            window_other_ops = sum(int(s["other_ops_delta"]) for s in bucket.samples)
            window_spawns = sum(int(s["spawned_children_delta"]) for s in bucket.samples)

            agg_reasons: List[str] = []
            for s in bucket.samples:
                for r in s.get("anomaly_reasons", []):
                    if r not in agg_reasons:
                        agg_reasons.append(r)

            rows.append(
                {
                    "pid": bucket.pid,
                    "create_time": bucket.create_time,
                    "name": bucket.name,
                    "exe_path": bucket.exe_path,
                    "cmdline": bucket.cmdline,
                    "is_whitelisted": bucket.is_whitelisted,
                    "whitelist_reason": bucket.whitelist_reason,
                    "cpu_percent": latest["cpu_percent"],
                    "memory_rss_mb": latest["memory_rss_mb"],
                    "write_ops_delta": latest["write_ops_delta"],
                    "write_bytes_delta": latest["write_bytes_delta"],
                    "other_ops_delta": latest["other_ops_delta"],
                    "spawned_children_delta": latest["spawned_children_delta"],
                    "window_write_ops": window_write_ops,
                    "window_write_kb": round(window_write_bytes / 1024.0, 1),
                    "window_other_ops": window_other_ops,
                    "window_spawns": window_spawns,
                    "anomaly_reasons": agg_reasons,
                    "is_elevated": bool(agg_reasons) and not bucket.is_whitelisted,
                    "os_status": latest["os_status"],
                    "sample_count": len(bucket.samples),
                    "age_sec": round(max(0.0, now_mono - latest["captured_at_mono"]), 2),
                }
            )

        # Sort so active behavioral threats appear at the very top, followed by user apps with I/O
        rows.sort(
            key=lambda r: (
                r["is_elevated"],
                not r["is_whitelisted"] and (r["window_write_ops"] > 0 or r["window_other_ops"] > 0),
                r["window_write_ops"] + r["window_other_ops"],
                r["cpu_percent"],
            ),
            reverse=True,
        )

        return {
            "processes": copy.deepcopy(rows[:limit]),
            "active_pids": {b.pid for b in self._buckets.values()},
            "total_tracked": len(self._buckets),
            "whitelisted_count": whitelisted_count,
            "user_app_count": user_app_count,
            "trigger_stats": copy.deepcopy(self.trigger_Stats),
        }