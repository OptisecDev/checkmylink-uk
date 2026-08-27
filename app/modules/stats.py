"""Anonymous aggregate stats: total scans run, total dangers caught.

No searched content is ever stored - only two running counters, persisted
to a small JSON file so they survive server restarts.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

STATS_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "stats.json"
_lock = threading.Lock()


def _read() -> dict:
    if not STATS_FILE.exists():
        return {"total_scans": 0, "total_dangers": 0}
    try:
        return json.loads(STATS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {"total_scans": 0, "total_dangers": 0}


def _write(data: dict) -> None:
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(json.dumps(data))


def get_stats() -> dict:
    with _lock:
        return _read()


def record_scan(verdict: str) -> dict:
    with _lock:
        data = _read()
        data["total_scans"] = data.get("total_scans", 0) + 1
        if verdict == "DANGER":
            data["total_dangers"] = data.get("total_dangers", 0) + 1
        _write(data)
        return data
