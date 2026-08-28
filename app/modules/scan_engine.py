"""Core scan engine for CheckMyLink UK.

Combines several free, no-API-key data sources into one plain-English
verdict: SAFE / CAUTION / DANGER. Every individual signal is wrapped so a
network failure, timeout, or rate limit degrades to "unable to check X"
instead of crashing the whole scan.

scan_url() checks a single link. scan_message() is the richer entry point
used by the web form: it accepts a full pasted message (SMS/email text),
pulls out any links and phone numbers it contains, and runs everything
through the checks below.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.modules.message_scan import check_pressure_phrases, extract_urls
from app.modules.phone_check import check_phone_number, extract_phone_numbers
from app.modules.signal_types import STATUS_CAUTION, STATUS_DANGER, STATUS_SAFE, STATUS_UNKNOWN, Signal
from app.modules.typosquat import check_typosquatting

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data"
OPENPHISH_CACHE_FILE = CACHE_DIR / "openphish_cache.txt"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_TTL_SECONDS = 12 * 60 * 60  # feed updates roughly twice a day

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

REQUEST_TIMEOUT = 6.0

# Common link-shortening services. When a link uses one of these, we follow
# the redirect chain (with a strict timeout/redirect cap) to find the real
# destination before running the rest of the checks against it.
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SHORTENER_TIMEOUT = 5.0
SHORTENER_MAX_REDIRECTS = 5


@dataclass
class ScanResult:
    url: str
    domain: str
    verdict: str  # SAFE | CAUTION | DANGER
    reasons: list[str]
    signals: list[Signal] = field(default_factory=list)
    score: int = 0
    original_url: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    extracted_phones: list[str] = field(default_factory=list)


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


def check_direct_ip(domain: str) -> Signal:
    """Flag links that use a raw IP address instead of a domain name - a
    common way scam links try to avoid brand/domain-based detection."""
    if not domain:
        return Signal("Direct IP address check", STATUS_UNKNOWN, "No domain to check.", 0)
    try:
        ipaddress.ip_address(domain)
        return Signal(
            name="Direct IP address check",
            status=STATUS_CAUTION,
            reason="This link uses a raw IP address instead of a proper website name, which is unusual for a legitimate site and is often used to hide the true destination.",
            score=20,
        )
    except ValueError:
        return Signal(
            name="Direct IP address check",
            status=STATUS_SAFE,
            reason="This link uses a normal website name, not a raw IP address.",
            score=0,
        )


def resolve_shortener(url: str, domain: str) -> tuple[Signal, str]:
    """If `domain` is a known link-shortening service, follow the redirect
    chain (bounded timeout + redirect cap) to find the real destination.
    Returns (signal, url_to_scan) - url_to_scan is the resolved destination
    on success, or the original shortened url if resolution isn't possible
    or the domain isn't a shortener at all."""
    if domain not in SHORTENER_DOMAINS:
        return (
            Signal(
                name="URL shortener check",
                status=STATUS_SAFE,
                reason="This link does not use a known link-shortening service.",
                score=0,
            ),
            url,
        )
    try:
        with httpx.Client(
            follow_redirects=True,
            max_redirects=SHORTENER_MAX_REDIRECTS,
            timeout=SHORTENER_TIMEOUT,
        ) as client:
            resp = client.get(url)
        final_url = str(resp.url)
        if final_url and final_url != url:
            return (
                Signal(
                    name="URL shortener check",
                    status=STATUS_CAUTION,
                    reason=f"This is a shortened link ({domain}) that redirects to {final_url} - we've checked that real destination too.",
                    score=10,
                ),
                final_url,
            )
        return (
            Signal(
                name="URL shortener check",
                status=STATUS_CAUTION,
                reason="This is a shortened link. Shortened links can hide where they really lead, so please be extra cautious.",
                score=10,
            ),
            url,
        )
    except Exception:
        return (
            Signal(
                name="URL shortener check",
                status=STATUS_CAUTION,
                reason="This is a shortened link and we could not resolve its real destination in time - please be extra cautious.",
                score=15,
            ),
            url,
        )


# ---------------------------------------------------------------------------
# Combine everything into one plain-English verdict.
# ---------------------------------------------------------------------------

DANGER_THRESHOLD = 50
CAUTION_THRESHOLD = 20

# Signals that, on their own, are a confirmed hit and should force a DANGER
# verdict regardless of the combined score.
_CONFIRMED_HIT_SIGNAL_NAMES = {"URLhaus malware list", "OpenPhish community feed"}


def _has_confirmed_hit(signals: list[Signal]) -> bool:
    return any(s.status == STATUS_DANGER and s.name in _CONFIRMED_HIT_SIGNAL_NAMES for s in signals)


def _verdict_from_score(total_score: int, confirmed_hit: bool) -> str:
    if confirmed_hit or total_score >= DANGER_THRESHOLD:
        return "DANGER"
    if total_score >= CAUTION_THRESHOLD:
        return "CAUTION"
    return "SAFE"


def _build_reasons(signals: list[Signal], verdict: str) -> list[str]:
    if verdict == "SAFE":
        return [
            "We did not find this link on any known scam or malware list.",
            "The domain does not resemble a well-known UK brand.",
            "Always stay cautious with links from unexpected messages, even if we say it looks safe.",
        ]
    # Surface the concrete reasons that pushed the score up, most severe first.
    concerning = [s for s in signals if s.status in (STATUS_DANGER, STATUS_CAUTION)]
    concerning.sort(key=lambda s: s.score, reverse=True)
    reasons = [s.reason for s in concerning[:4]]
    unknowns = [s for s in signals if s.status == STATUS_UNKNOWN]
    if unknowns and len(reasons) < 4:
        reasons.append(
            "We could not fully check every source, so please stay extra cautious with this link."
        )
    return reasons


def scan_url(raw_input: str) -> ScanResult:
    original_url, original_domain = normalise_url(raw_input)

    shortener_signal, resolved_url = resolve_shortener(original_url, original_domain)
    if resolved_url != original_url:
        url, domain = normalise_url(resolved_url)
    else:
        url, domain = original_url, original_domain

    urlhaus_signal = check_urlhaus(url)
    openphish_signal = check_openphish(url)
    spamhaus_signal = check_spamhaus_dbl(domain)
    age_signal = check_domain_age(domain)
    typosquat_signal = check_typosquat_signal(domain)
    ssl_signal = check_ssl_certificate(domain, is_typosquat=typosquat_signal.status == STATUS_DANGER)
    ip_signal = check_direct_ip(domain)

    signals = [
        urlhaus_signal,
        openphish_signal,
        spamhaus_signal,
        age_signal,
        typosquat_signal,
        ssl_signal,
        shortener_signal,
        ip_signal,
    ]

    total_score = sum(s.score for s in signals)
    confirmed_hit = _has_confirmed_hit(signals)
    verdict = _verdict_from_score(total_score, confirmed_hit)
    reasons = _build_reasons(signals, verdict)

    return ScanResult(
        url=url,
        domain=domain,
        verdict=verdict,
        reasons=reasons,
        signals=signals,
        score=total_score,
        original_url=original_url,
    )


def scan_message(raw_text: str) -> ScanResult:
    """Top-level entry point used by the web form. Accepts either a single
    pasted link, or a full message (SMS/email text) - in the latter case it
    extracts any links and phone numbers found within it and checks each of
    them, plus looks for common scam pressure-tactic phrasing."""
    raw_text = (raw_text or "").strip()

    if not raw_text:
        return ScanResult(
            url="",
            domain="",
            verdict="SAFE",
            reasons=["Please paste a link, phone number, or message to check."],
            signals=[],
            score=0,
        )

    urls = extract_urls(raw_text)
    phones = extract_phone_numbers(raw_text)

    # A single bare link/domain with nothing else pasted - scan it directly
    # so behaviour matches scanning that link on its own.
    if len(urls) == 1 and not phones and raw_text == urls[0]:
        return scan_url(urls[0])

    pressure_signal = check_pressure_phrases(raw_text)

    if not urls and not phones:
        # Nothing recognised as a link or phone number - fall back to
        # treating the whole input as a single URL/domain (e.g. a bare
        # "amazon.co.uk" that our extraction regex happens to miss), and
        # still fold in the pressure-language check.
        result = scan_url(raw_text)
        result.signals.append(pressure_signal)
        result.score += pressure_signal.score
        result.verdict = _verdict_from_score(result.score, _has_confirmed_hit(result.signals))
        result.reasons = _build_reasons(result.signals, result.verdict)
        return result

    url_results = [scan_url(u) for u in urls]
    phone_signals = [check_phone_number(p) for p in phones]

    signals: list[Signal] = []
    for sr in url_results:
        signals.extend(sr.signals)
    signals.extend(phone_signals)
    signals.append(pressure_signal)

    total_score = sum(s.score for s in signals)
    confirmed_hit = _has_confirmed_hit(signals)
    verdict = _verdict_from_score(total_score, confirmed_hit)
    reasons = _build_reasons(signals, verdict)

    primary = url_results[0] if url_results else None
    return ScanResult(
        url=primary.url if primary else "",
        domain=primary.domain if primary else "",
        verdict=verdict,
        reasons=reasons,
        signals=signals,
        score=total_score,
        original_url=primary.original_url if primary else "",
        extracted_urls=urls,
        extracted_phones=phones,
    )
