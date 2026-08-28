"""Shared types for every individual safety-check signal.

Split out from scan_engine so phone_check / message_scan can build Signal
objects too, without importing scan_engine and creating an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_DANGER = "danger"
STATUS_CAUTION = "caution"
STATUS_SAFE = "safe"
STATUS_UNKNOWN = "unknown"


@dataclass
class Signal:
    name: str
    status: str  # danger | caution | safe | unknown
    reason: str
    score: int = 0  # contribution to the overall risk score
