"""UK phone number detection and scam-pattern matching.

This is a lightweight heuristic, not a live threat feed - there is no free,
reliable, publicly-maintained "known scam numbers" API. Scammers rotate and
spoof numbers constantly, so a number NOT matching anything here is not
proof it's safe. What we *can* usefully check for free is a small set of
publicly-documented, well-known scam *patterns* (not specific numbers):

- UK premium-rate / personal-numbering ranges (09, 084, 087, 070) that
  legitimate Ofcom guidance and consumer bodies (e.g. Which?) repeatedly
  flag as commonly abused in call-back and "you've won a prize" scams.
- A handful of international dialling codes that Ofcom, Action Fraud and UK
  mobile networks have repeatedly warned about in connection with "Wangiri"
  (one-ring-and-cut) missed-call callback scams targeting UK phones.

This list is illustrative and community-maintained, not exhaustive.
"""

from __future__ import annotations

import re

from app.modules.signal_types import STATUS_CAUTION, STATUS_SAFE, STATUS_UNKNOWN, Signal

# Matches UK-style numbers starting +44/0044/0, and other international
# numbers starting with a + country code (needed to catch Wangiri-style
# international missed-call numbers pasted into a message).
PHONE_RE = re.compile(
    r"(?:\+\d{1,3}\s?\d{2,4}|0044\s?\d{2,4}|\b0\d{2,4})[\s\-]?\d{3,4}[\s\-]?\d{0,4}\b"
)

# (prefix, plain-English reason). Prefixes starting with "+" are matched
# against the internationally-formatted number; all others are matched
# against the UK national (0-prefixed) form.
SCAM_PHONE_PATTERNS: list[tuple[str, str]] = [
    ("09", "Numbers starting 09 are premium-rate lines often used in call-back and \"you've won a prize\" scams."),
    ("084", "084 numbers are frequently used in scam call-back schemes that charge you a high rate to call them."),
    ("087", "087 numbers are frequently used in scam call-back schemes that charge you a high rate to call them."),
    ("070", "070 \"personal numbering\" numbers are commonly used to disguise the true origin of a scam call."),
    ("+370", "This is a Lithuanian mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
    ("+371", "This is a Latvian mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
    ("+372", "This is an Estonian mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
    ("+216", "This is a Tunisian mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
    ("+375", "This is a Belarusian mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
    ("+225", "This is an Ivory Coast mobile prefix commonly reported in \"missed call\" (Wangiri) callback scams."),
]


def normalise_phone(raw: str) -> str:
    """Strip formatting and convert 0044.../00... prefixes to a leading +."""
    cleaned = re.sub(r"[\s\-()]", "", raw)
    if cleaned.startswith("0044"):
        cleaned = "+44" + cleaned[4:]
    elif cleaned.startswith("00") and not cleaned.startswith("000"):
        cleaned = "+" + cleaned[2:]
    return cleaned


def extract_phone_numbers(text: str) -> list[str]:
    """Find candidate UK/international phone numbers inside free text,
    de-duplicated and in the order they first appear."""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in PHONE_RE.findall(text):
        candidate = match.strip()
        normalised = normalise_phone(candidate)
        # Require a plausible number of digits to avoid flagging short
        # reference numbers that happen to start with 0.
        digit_count = sum(c.isdigit() for c in normalised)
        if digit_count < 9:
            continue
        if normalised in seen:
            continue
        seen.add(normalised)
        found.append(candidate)
    return found


def check_phone_number(raw_number: str) -> Signal:
    if not raw_number or not raw_number.strip():
        return Signal("Phone number check", STATUS_UNKNOWN, "No phone number to check.", 0)

    try:
        cleaned = normalise_phone(raw_number)
        national = cleaned
        if cleaned.startswith("+44"):
            national = "0" + cleaned[3:]

        for prefix, reason in SCAM_PHONE_PATTERNS:
            if prefix.startswith("+"):
                if cleaned.startswith(prefix):
                    return Signal("Phone number check", STATUS_CAUTION, reason, score=15)
            else:
                if national.startswith(prefix):
                    return Signal("Phone number check", STATUS_CAUTION, reason, score=15)

        return Signal(
            "Phone number check",
            STATUS_SAFE,
            "This phone number does not match any of the known scam-number patterns we check for.",
            0,
        )
    except Exception:
        return Signal(
            "Phone number check",
            STATUS_UNKNOWN,
            "Unable to check this phone number right now.",
            0,
        )
