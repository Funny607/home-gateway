from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_identity(pid: int) -> str:
    """Return a stable-enough PID generation marker for Linux or macOS."""
    if pid <= 0 or not pid_exists(pid):
        return ""
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.is_file():
        try:
            # Field 22 is process start time in clock ticks. The command field may contain spaces.
            content = stat_path.read_text(encoding="utf-8", errors="replace")
            suffix = content.rsplit(")", 1)[1].strip().split()
            start_ticks = suffix[19]
            return f"linux:{pid}:{start_ticks}"
        except (OSError, IndexError):
            return ""
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "lstart=", "-o", "pgid=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    marker = " ".join(result.stdout.split())
    return f"darwin:{pid}:{marker}" if result.returncode == 0 and marker else ""


def process_matches_identity(pid: int, expected: str) -> bool:
    """Fail closed when an old runtime record lacks a generation marker."""
    return bool(expected) and process_identity(pid) == expected


def kill_process_group(pgid: int, sig: int) -> None:
    os.killpg(pgid, sig)


def terminate_process_group(pgid: int) -> None:
    kill_process_group(pgid, signal.SIGTERM)


def force_kill_process_group(pgid: int) -> None:
    kill_process_group(pgid, signal.SIGKILL)
