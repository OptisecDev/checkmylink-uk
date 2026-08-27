"""Local typosquatting detector.

Compares a domain against a maintained list of major UK brands that are
commonly impersonated in scam links. Uses Levenshtein (edit) distance so it
works fully offline with no external calls or dependencies, and also checks
for the brand name appearing verbatim inside a longer, unrelated hostname
(e.g. "barclays-secure-login.com"), which a pure edit-distance check misses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Brand -> the legitimate domain(s) a scam link would try to imitate.
UK_BRANDS: dict[str, list[str]] = {
    "Barclays": ["barclays.co.uk"],
    "HSBC": ["hsbc.co.uk"],
    "Lloyds Bank": ["lloydsbank.com", "lloyds.co.uk"],
    "NatWest": ["natwest.com"],
    "Santander UK": ["santander.co.uk"],
    "Royal Mail": ["royalmail.com"],
    "HMRC": ["gov.uk", "hmrc.gov.uk"],
    "DVLA": ["gov.uk", "dvla.gov.uk"],
    "TV Licensing": ["tvlicensing.co.uk"],
    "DPD": ["dpd.co.uk"],
    "Evri": ["evri.com"],
}

# Legit "domains" that are too generic to safely anchor a "this hostname is
# just a subdomain of the real thing" allowance (gov.uk is shared by many
# unrelated government services, not just HMRC/DVLA).
_GENERIC_LEGIT_DOMAINS = {"gov.uk"}

# Keyword fragments that are too short/generic to use for brand-substring
# matching even though they fall out of a legit domain's core (e.g. "gov").
_GENERIC_SUBSTRING_KEYWORDS = {"gov", "uk", "co", "com", "net", "org"}


def levenshtein(a: str, b: str) -> int:
    """Classic edit-distance, iterative DP with O(min(len)) memory."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def _strip_suffix(domain: str) -> str:
    """Drop the common TLD suffix so comparisons focus on the brand name part."""
    for suffix in (".co.uk", ".org.uk", ".gov.uk", ".com", ".net", ".uk"):
        if domain.endswith(suffix):
            return domain[: -len(suffix)]
    return domain


def _normalise_keyword(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _build_substring_keywords() -> dict[str, set[str]]:
    """Per-brand keywords used to spot the brand name embedded in a longer,
    unrelated hostname (e.g. "hsbc" inside "hsbc-verify-account.net")."""
    keywords: dict[str, set[str]] = {}
    for brand, legit_domains in UK_BRANDS.items():
        candidates = {_normalise_keyword(brand)}
        for legit in legit_domains:
            candidates.add(_normalise_keyword(_strip_suffix(legit)))
        keywords[brand] = {
            kw for kw in candidates if len(kw) >= 3 and kw not in _GENERIC_SUBSTRING_KEYWORDS
        }
    return keywords


BRAND_SUBSTRING_KEYWORDS: dict[str, set[str]] = _build_substring_keywords()


@dataclass
class TyposquatMatch:
    brand: str
    legit_domain: str
    distance: int
    # "typo_variant": caught by edit-distance (e.g. "barclyas.co.uk").
    # "brand_substring": the real brand name appears verbatim inside a
    # longer/unrelated hostname (e.g. "barclays-secure-login.com").
    kind: str = "typo_variant"


def _is_legit_or_subdomain(domain: str, legit_domains: list[str]) -> bool:
    """True if `domain` is one of the brand's real domains, or a genuine
    subdomain of one - but ignoring overly generic anchors like gov.uk."""
    for legit in legit_domains:
        if legit in _GENERIC_LEGIT_DOMAINS:
            continue
        if domain == legit or domain.endswith("." + legit):
            return True
    return False


def check_typosquatting(domain: str) -> TyposquatMatch | None:
    """Return the closest brand match if `domain` looks like a typosquat.

    A domain that is an *exact* match to a legitimate brand domain is not
    flagged (that's presumably the real site). Two independent signals are
    checked beyond that:

    1. Edit distance: a close-but-not-exact match (edit distance 1-2 on the
       core name, scaled for very short names) is flagged as a likely typo
       (e.g. "barclyas.co.uk", "lloydsbnk.com").
    2. Brand substring: the real brand name appears verbatim inside a
       longer, unrelated hostname (e.g. "barclays-secure-login.com",
       "hsbc-verify-account.net"). This catches impersonation attempts that
       don't misspell the brand at all, so edit distance alone misses them.
       Genuine subdomains of the brand's real domain (e.g.
       "secure.barclays.co.uk") are excluded.
    """
    domain = domain.lower().strip().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    domain_core = _strip_suffix(domain)

    best: TyposquatMatch | None = None

    for brand, legit_domains in UK_BRANDS.items():
        for legit in legit_domains:
            if domain == legit:
                return None  # exact match to the real domain, not a squat

        if _is_legit_or_subdomain(domain, legit_domains):
            continue  # genuine subdomain of the brand's real site

        for legit in legit_domains:
            legit_core = _strip_suffix(legit)
            distance = levenshtein(domain_core, legit_core)

            # Scale the "close enough to be suspicious" threshold with name
            # length so short brand names don't over-match unrelated domains.
            threshold = 1 if len(legit_core) <= 5 else 2
            if 0 < distance <= threshold:
                if best is None or (best.kind == "typo_variant" and distance < best.distance):
                    best = TyposquatMatch(
                        brand=brand, legit_domain=legit, distance=distance, kind="typo_variant"
                    )

        if best is not None and best.brand == brand and best.kind == "typo_variant":
            continue  # already have the strongest possible signal for this brand

        for keyword in BRAND_SUBSTRING_KEYWORDS.get(brand, ()):
            if keyword in domain_core:
                if best is None:
                    specific_domains = [d for d in legit_domains if d not in _GENERIC_LEGIT_DOMAINS]
                    best = TyposquatMatch(
                        brand=brand,
                        legit_domain=(specific_domains or legit_domains)[0],
                        distance=0,
                        kind="brand_substring",
                    )
                break

    return best
