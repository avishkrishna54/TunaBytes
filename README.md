@'
# 🛡️ Tunabytes V4 — AI-Powered Behavioral Antivirus & Human-in-the-Loop EDR

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![Google Gemini AI](https://img.shields.io/badge/AI_Advisor-Google_Gemini_2.5-8E75B2?logo=googlegemini&logoColor=white)
![Architecture](https://img.shields.io/badge/Spec-Frozen_V4_Deterministic-10B981)
![Platform](https://img.shields.io/badge/Platform-Windows_%2F_Cross--Platform-0078D6)

**Tunabytes V4** is a deterministic, AI-Powered Runtime Telemetry Endpoint Detection and Response (EDR) platform built on **Python 3.10+** and **FastAPI**. 

Unlike traditional monitoring tools that trigger false positives on heavy games, compilers, or browsers using high CPU/RAM, Tunabytes V4 monitors **actual destructive OS behaviors** (ransomware-like file corruption bursts, mass metadata/deletion I/O, and unauthorized child shell spawns) and pairs **Google Gemini AI** plain-English explanations with **Human-in-the-Loop (HITL) Quarantine Freeze** and a **2-Step Double-Lock Termination** workflow.

---

## ✨ Key Engineering Highlights

### 1. Zero CPU/RAM False Positives (Behavioral Detection Only)
High memory (`memory_rss_mb`) or high processor usage (`cpu_percent`) **never** flags a process alone. A non-whitelisted process is only elevated to the State Machine when concrete behavioral indicators are observed:
- 🔥 **`FILE_CORRUPTION_BURST`**: High-velocity discrete file write operations (`write_ops_delta >= 12`) paired with rapid payload overwrites (`write_bytes_delta >= 180 KB` per 1.5s tick).
- 🗑️ **`MASS_FILE_DELETION_IO`**: Rapid spikes in filesystem metadata, rename, or unlink operations (`other_ops_delta >= 24` paired with `write_ops_delta >= 6`) or destructive command-line signatures (`vssadmin delete shadows`, `cipher /w:`, `.corrupted`).
- ⚡ **`UNAUTHORIZED_PROGRAM_SPAWN`**: Real-time parent-child PID (`ppid`) tracking catching unexpected background shell/utility spawns (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `mshta.exe`, `certutil.exe`).

### 2. Immutable System, Browser & IDE Whitelist
A non-bypassable safety filter (`is_process_whitelisted`) enforced in both the telemetry collector and state machine protects:
- **Self-Preservation**: Tunabytes' own PID, parent PID, and Uvicorn server worker.
- **OS & Kernel Processes**: PIDs `< 1000`, `System`, `lsass.exe`, `svchost.exe`, `csrss.exe`, `explorer.exe`, and binaries inside `C:\Windows\System32` or `SysWOW64`.
- **Developer Tools & Browsers**: Chrome, Edge, Firefox, Brave, VS Code (`code.exe`), Cursor, Visual Studio, PyCharm, and Windows Terminal.

### 3. Human-in-the-Loop (HITL) Freeze & "Double-Lock" Containment
- **❄️ Quarantine Freeze (`psutil.Process.suspend()`)**: Instantly pauses a suspicious process's threads in RAM so file corruption stops immediately without losing unsaved application state, with one-click **▶️ Resume**.
- **🔒 2-Step Double-Lock Termination**: Eliminates blind auto-kills. Operators review a Step 1 Consequence Warning and Plain-English AI explanation before confirming Step 2 Force-Quit, logging every action into the **Terminated Applications Forensic Ledger**.
- **📄 One-Click Executive & Forensic PDF Report**: Exports decoupled subsystem health, behavioral counters, the forensic termination ledger, live process telemetry, and audit logs via `/api/export-pdf-report`.

---

## 🏛️ The 6 Frozen V4 Architectural Invariants

| Invariant | Component | Engineering Guarantee |
| :--- | :--- | :--- |
| **1. Single-Owner Concurrency** | `monitor.py` | Event loop exclusively owns the `(PID, creation_time)` registry. Blocking `psutil.process_iter()` runs strictly inside `asyncio.to_thread()` returning deep-copied dicts into `deque(maxlen=7)` with `30.0s` `time.monotonic()` eviction. |
| **2. Dual Monotonic Freshness** | `state_machine.py` | Tracks `captured_at_mono` vs `enqueued_at_mono`. Drops observations older than `15.0s` before AI analysis (`DROPPED_STALE_PRE_AI`) and blocks enforcement if older than `30.0s` post-AI (`AUDIT_ONLY_STALE_POST_AI`). |
| **3. Coalescing State Machine** | `state_machine.py` | Per-process `IDLE -> QUEUED -> ANALYZING -> COOLDOWN -> IDLE` lifecycle. Coalesces duplicate spikes in-place, guarantees `queue.task_done()` in `finally:` blocks, and enforces a `60.0s` cooldown with automatic rearming. |
| **4. Bounded AI Advisor** | `ai_client.py` | Shared `httpx.AsyncClient` wrapped in a strict `12.0s` total operation deadline with Pydantic schema validation (`BENIGN \| SUSPICIOUS \| MALICIOUS`, finite `confidence` in `[0.0, 1.0]`, plain-text `evidence <= 250 chars`). Fails safe to `UNKNOWN`. |
| **5. Loopback & Demo Authority** | `main.py` | Control endpoints verify loopback origin (`127.0.0.1`). `/api/launch-demo` accepts zero arguments and tracks `(Popen, PID, creation_time, path)` for safe synthetic workload testing. |
| **6. Bounded Lifespan & `/health`** | `main.py` | FastAPI `lifespan` guarantees clean teardown of collectors, workers, demo subprocesses, and HTTP clients within a hard `5.0s` deadline. Exposes non-blocking `/health`. |

---

## 📂 Project Structure

```text
tunabytes_v4/
├── main.py              # FastAPI app, 5.0s lifespan manager, loopback endpoints & PDF report generator
├── monitor.py           # Event-loop-owned collector, asyncio.to_thread() enumeration & behavioral detectors
├── state_machine.py     # Coalescing lifecycle manager, immutable whitelist, HITL freeze & Double-Lock engine
├── ai_client.py         # Bounded 12.0s Gemini REST client + offline Plain-English behavioral classifier
├── demo_workload.py     # Safe synthetic attack simulator (isolated %TEMP% file corruption & child spawn)
├── rogue_test.py        # Standalone Nuitka-compilable rogue process simulator for live external testing
├── requirements.txt     # Python runtime dependencies
└── static/
    └── index.html       # Responsive dark-mode SOC dashboard with live telemetry, modals & audit stream
