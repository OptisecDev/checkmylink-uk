"""Core scan engine for CheckMyLink UK.

Combines several free, no-API-key data sources into one plain-English
verdict: SAFE / CAUTION / DANGER. Every individual signal is wrapped so a
network failure, timeout, or rate limit degrades to "unable to check X"
instead of crashing the whole scan.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.modules.typosquat import check_typosquatting

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data"
OPENPHISH_CACHE_FILE = CACHE_DIR / "openphish_cache.txt"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_TTL_SECONDS = 12 * 60 * 60  # feed updates roughly twice a day

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

REQUEST_TIMEOUT = 6.0

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


@dataclass
class ScanResult:
    url: str
    domain: str
    verdict: str  # SAFE | CAUTION | DANGER
    reasons: list[str]
    signals: list[Signal] = field(default_factory=list)
    score: int = 0


def normalise_url(raw: str) -> tuple[str, str]:
    """Return (url_with_scheme, hostname) for whatever the user pasted in."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return raw, domain


# ---------------------------------------------------------------------------
# Individual signal checks - each one is defensive and never raises.
# ---------------------------------------------------------------------------


def check_urlhaus(url: str) -> Signal:
    try:
        resp = httpx.post(URLHAUS_API_URL, data={"url": url}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            threat = data.get("threat", "malware")
            return Signal(
                name="URLhaus malware list",
                status=STATUS_DANGER,
                reason=f"This exact link is on URLhaus's list of known {threat} sites.",
                score=50,
            )
        return Signal(
            name="URLhaus malware list",
            status=STATUS_SAFE,
            reason="Not found on URLhaus's list of known malware sites.",
            score=0,
        )
    except Exception:
        return Signal(
            name="URLhaus malware list",
            status=STATUS_UNKNOWN,
            reason="Unable to check the URLhaus malware list right now.",
            score=0,
        )


def _load_openphish_feed() -> set[str]:
    """Load the OpenPhish community feed, using a local cache to avoid
    re-downloading the whole feed on every single scan."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    is_fresh = (
        OPENPHISH_CACHE_FILE.exists()
        and (time.time() - OPENPHISH_CACHE_FILE.stat().st_mtime) < OPENPHISH_CACHE_TTL_SECONDS
    )
    if not is_fresh:
        resp = httpx.get(OPENPHISH_FEED_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        OPENPHISH_CACHE_FILE.write_text(resp.text)

    text = OPENPHISH_CACHE_FILE.read_text()
    return {line.strip() for line in text.splitlines() if line.strip()}


def check_openphish(url: str) -> Signal:
    try:
        feed = _load_openphish_feed()
        if url in feed or url.rstrip("/") in feed:
            return Signal(
                name="OpenPhish community feed",
                status=STATUS_DANGER,
                reason="This exact link is on the OpenPhish list of confirmed phishing sites.",
                score=50,
            )
        return Signal(
            name="OpenPhish community feed",
            status=STATUS_SAFE,
            reason="Not found on the OpenPhish confirmed-phishing list.",
            score=0,
        )
    except Exception:
        return Signal(
            name="OpenPhish community feed",
            status=STATUS_UNKNOWN,
            reason="Unable to check the OpenPhish feed right now.",
            score=0,
        )


def check_spamhaus_dbl(domain: str) -> Signal:
    if not domain:
        return Signal("Spamhaus domain blocklist", STATUS_UNKNOWN, "No domain to check.", 0)
    query = f"{domain}.dbl.spamhaus.org"
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(REQUEST_TIMEOUT)
        result_ip = socket.gethostbyname(query)
        # Spamhaus returns 127.0.1.x codes when the domain IS listed.
        if result_ip.startswith("127.0.1."):
            return Signal(
                name="Spamhaus domain blocklist",
                status=STATUS_DANGER,
                reason="This domain is listed on the Spamhaus blocklist for spam/scam/malware domains.",
                score=40,
            )
        return Signal(
            name="Spamhaus domain blocklist",
            status=STATUS_CAUTION,
            reason="This domain returned an unexpected Spamhaus response.",
            score=10,
        )
    except socket.gaierror:
        # NXDOMAIN - domain is not on the blocklist. This is the normal/safe case.
        return Signal(
            name="Spamhaus domain blocklist",
            status=STATUS_SAFE,
            reason="Not listed on the Spamhaus domain blocklist.",
            score=0,
        )
    except Exception:
        return Signal(
            name="Spamhaus domain blocklist",
            status=STATUS_UNKNOWN,
            reason="Unable to check the Spamhaus blocklist right now.",
            score=0,
        )
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_domain_age(domain: str) -> Signal:
    if not domain:
        return Signal("Domain age", STATUS_UNKNOWN, "No domain to check.", 0)
    try:
        import whois  # imported lazily so its optional native deps don't block startup

        record = whois.whois(domain)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        if creation_date is None:
            return Signal(
                name="Domain age",
                status=STATUS_UNKNOWN,
                reason="Unable to determine when this domain was registered.",
                score=0,
            )
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        if age_days < 30:
            return Signal(
                name="Domain age",
                status=STATUS_DANGER,
                reason=f"This domain was only registered {max(age_days, 0)} day(s) ago - scammers often use brand-new domains.",
                score=25,
            )
        return Signal(
            name="Domain age",
            status=STATUS_SAFE,
            reason=f"This domain has existed for {age_days} days.",
            score=0,
        )
    except Exception:
        return Signal(
            name="Domain age",
            status=STATUS_UNKNOWN,
            reason="Unable to check domain registration age right now.",
            score=0,
        )


def check_typosquat_signal(domain: str) -> Signal:
    if not domain:
        return Signal("Brand impersonation check", STATUS_UNKNOWN, "No domain to check.", 0)
    try:
        match = check_typosquatting(domain)
        if match:
            if match.kind == "brand_substring":
                reason = (
                    f"This domain contains {match.brand}'s name but is not "
                    f"{match.brand}'s real website ({match.legit_domain}) - a common phishing tactic."
                )
            else:
                reason = f"This domain looks like a near-copy of {match.brand}'s real website ({match.legit_domain})."
            return Signal(
                name="Brand impersonation check",
                status=STATUS_DANGER,
                reason=reason,
                score=50,
            )
        return Signal(
            name="Brand impersonation check",
            status=STATUS_SAFE,
            reason="Domain does not closely resemble a major UK brand.",
            score=0,
        )
    except Exception:
        return Signal(
            name="Brand impersonation check",
            status=STATUS_UNKNOWN,
            reason="Unable to run the brand impersonation check right now.",
            score=0,
        )


def check_ssl_certificate(domain: str, is_typosquat: bool) -> Signal:
    if not domain:
        return Signal("SSL certificate check", STATUS_UNKNOWN, "No domain to check.", 0)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_before = cert.get("notBefore")
        if not not_before:
            return Signal(
                name="SSL certificate check",
                status=STATUS_UNKNOWN,
                reason="Unable to read this site's security certificate.",
                score=0,
            )
        issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - issued).days
        if age_days < 30 and is_typosquat:
            return Signal(
                name="SSL certificate check",
                status=STATUS_DANGER,
                reason="This site is using a brand-new security certificate on a domain impersonating a known brand.",
                score=20,
            )
        return Signal(
            name="SSL certificate check",
            status=STATUS_SAFE,
            reason="Security certificate does not show additional signs of risk.",
            score=0,
        )
    except Exception:
        return Signal(
            name="SSL certificate check",
            status=STATUS_UNKNOWN,
            reason="Unable to check this site's security certificate right now (it may not support HTTPS).",
            score=0,
        )


# ---------------------------------------------------------------------------
# Combine everything into one plain-English verdict.
# ---------------------------------------------------------------------------

DANGER_THRESHOLD = 50
CAUTION_THRESHOLD = 20


def scan_url(raw_input: str) -> ScanResult:
    url, domain = normalise_url(raw_input)

    urlhaus_signal = check_urlhaus(url)
    openphish_signal = check_openphish(url)
    spamhaus_signal = check_spamhaus_dbl(domain)
    age_signal = check_domain_age(domain)
    typosquat_signal = check_typosquat_signal(domain)
    ssl_signal = check_ssl_certificate(domain, is_typosquat=typosquat_signal.status == STATUS_DANGER)

    signals = [urlhaus_signal, openphish_signal, spamhaus_signal, age_signal, typosquat_signal, ssl_signal]

    total_score = sum(s.score for s in signals)

    # A direct, confirmed hit on a curated blocklist is treated as an
    # immediate DANGER verdict regardless of the combined score.
    confirmed_hit = urlhaus_signal.status == STATUS_DANGER or openphish_signal.status == STATUS_DANGER

    if confirmed_hit or total_score >= DANGER_THRESHOLD:
        verdict = "DANGER"
    elif total_score >= CAUTION_THRESHOLD:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    if verdict == "SAFE":
        reasons = [
            "We did not find this link on any known scam or malware list.",
            "The domain does not resemble a well-known UK brand.",
            "Always stay cautious with links from unexpected messages, even if we say it looks safe.",
        ]
    else:
        # Surface the concrete reasons that pushed the score up, most severe first.
        concerning = [s for s in signals if s.status in (STATUS_DANGER, STATUS_CAUTION)]
        concerning.sort(key=lambda s: s.score, reverse=True)
        reasons = [s.reason for s in concerning[:4]]
        unknowns = [s for s in signals if s.status == STATUS_UNKNOWN]
        if unknowns and len(reasons) < 4:
            reasons.append(
                "We could not fully check every source, so please stay extra cautious with this link."
            )

    return ScanResult(
        url=url,
        domain=domain,
        verdict=verdict,
        reasons=reasons,
        signals=signals,
        score=total_score,
    )
