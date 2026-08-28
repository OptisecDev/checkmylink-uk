"""Helpers for scanning a full pasted message (SMS/email text), rather than
just a single bare URL: pulling out any links and phone numbers it contains,
and spotting common scam pressure-tactic phrasing."""

from __future__ import annotations

import re

from app.modules.signal_types import STATUS_CAUTION, STATUS_SAFE, Signal

URL_RE = re.compile(
    r"(?:https?://[^\s<>\"')]+)"
    r"|(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:co\.uk|org\.uk|gov\.uk|ac\.uk|com|net|org|info|biz|uk)\b(?:/[^\s<>\"')]*)?)",
    re.IGNORECASE,
)

# Common scam pressure-tactic phrases. This is a mild signal, not a hard
# fail - legitimate messages occasionally use similar wording too.
PRESSURE_PHRASES: list[str] = [
    "act now",
    "verify immediately",
    "account suspended",
    "account has been suspended",
    "your parcel could not be delivered",
    "you have won",
    "you've won",
    "unusual activity detected",
    "unusual activity on your account",
    "confirm your details",
    "urgent action required",
    "your account will be closed",
    "click here immediately",
    "avoid suspension",
]


def extract_urls(text: str) -> list[str]:
    """Find candidate URLs/domains inside free text, de-duplicated and in
    the order they first appear."""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(text):
        candidate = match.strip().rstrip(".,;:!?)")
        if not candidate:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(candidate)
    return found


def check_pressure_phrases(text: str) -> Signal:
    if not text:
        return Signal(
            "Pressure-tactic language",
            STATUS_SAFE,
            "No message text to check for pressure-tactic language.",
            0,
        )
    lowered = text.lower()
    matched = [phrase for phrase in PRESSURE_PHRASES if phrase in lowered]
    if matched:
        return Signal(
            "Pressure-tactic language",
            STATUS_CAUTION,
            f'This message uses urgent, pressuring language often used in scams (e.g. "{matched[0]}").',
            score=10,
        )
    return Signal(
        "Pressure-tactic language",
        STATUS_SAFE,
        "We did not spot common scam pressure phrases in this message.",
        0,
    )
