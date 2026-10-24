"""
demo_workload.py
Tunabytes V4 — Trusted Synthetic Behavioral Attack Simulator (Invariant 5).

Safely simulates all three behavioral threat indicators inside an isolated
`%TEMP%\\tunabytes_sandbox_corruption_*` folder:
1. FILE_CORRUPTION_BURST: Rapid discrete file overwrites (>20 write ops & >320 KB per tick).
2. MASS_FILE_DELETION_IO: Rapid file renames to `.corrupted` and batch deletions (>30 metadata ops).
3. UNAUTHORIZED_PROGRAM_SPAWN: Periodically spawns a harmless child process (`cmd.exe /c echo` or Python).
Automatically cleans up the temporary sandbox directory on exit or termination.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

_RUNNING = True


def _sig_handler(_signum: int, _frame: object) -> None:
    global _RUNNING
    _RUNNING = False


for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _sig_handler)
    except Exception:
        pass


def main() -> int:
    sandbox_dir = tempfile.mkdtemp(prefix="tunabytes_sandbox_corruption_")
    corruption_header = b"TUNABYTES_SYNTHETIC_CORRUPTION_BLOCK__" + os.urandom(16 * 1024)
    start_mono = time.monotonic()
    max_duration_sec = 90.0
    cycle = 0

    try:
        while _RUNNING and (time.monotonic() - start_mono) < max_duration_sec:
            cycle += 1
            created_files = []

            # 1. Trigger FILE_CORRUPTION_BURST (22 discrete file writes, ~352 KB per burst)
            for idx in range(22):
                if not _RUNNING:
                    break
                fpath = os.path.join(sandbox_dir, f"user_doc_{cycle}_{idx}.dat")
                with open(fpath, "wb") as f:
                    f.write(corruption_header)
                    f.flush()
                created_files.append(fpath)

            # 2. Trigger MASS_FILE_DELETION_IO (rename to .corrupted + unlink in batch)
            for fpath in created_files:
                if not _RUNNING:
                    break
                corrupted_path = fpath + ".corrupted"
                try:
                    os.replace(fpath, corrupted_path)
                    os.remove(corrupted_path)
                except OSError:
                    pass

            # 3. Trigger UNAUTHORIZED_PROGRAM_SPAWN every 3 cycles
            if cycle % 3 == 1 and _RUNNING:
                try:
                    if os.name == "nt":
                        child = subprocess.Popen(
                            ["cmd.exe", "/c", "echo TUNABYTES_DEMO_CHILD_SPAWN"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    else:
                        child = subprocess.Popen(
                            [sys.executable, "-c", "import time; time.sleep(0.2)"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    child.wait(timeout=1.0)
                except Exception:
                    pass

            time.sleep(0.45)
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())