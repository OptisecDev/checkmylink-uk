"""Minimal user-feedback logging.

No database yet, so submissions are appended to a local JSON file. Kept
deliberately simple: no email sending, no external service.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

FEEDBACK_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "feedback.json"
_lock = threading.Lock()


def _read_all() -> list[dict]:
    if not FEEDBACK_FILE.exists():
        return []
    try:
        data = json.loads(FEEDBACK_FILE.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_feedback(name: str, email: str, message: str) -> None:
    entry = {
        "name": (name or "").strip(),
        "email": (email or "").strip(),
        "message": (message or "").strip(),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        entries = _read_all()
        entries.append(entry)
        FEEDBACK_FILE.write_text(json.dumps(entries, indent=2))
