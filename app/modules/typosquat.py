"""Local typosquatting detector.

Compares a domain against a maintained list of major UK brands that are
commonly impersonated in scam links. Uses Levenshtein (edit) distance so it
works fully offline with no external calls or dependencies.
"""

from __future__ import annotations

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


@dataclass
class TyposquatMatch:
    brand: str
    legit_domain: str
    distance: int


def check_typosquatting(domain: str) -> TyposquatMatch | None:
    """Return the closest brand match if `domain` looks like a typosquat.

    A domain that is an *exact* match to a legitimate brand domain is not
    flagged (that's presumably the real site). A close-but-not-exact match
    (edit distance 1-2 on the core name, scaled for very short names) is
    flagged as a likely impersonation attempt.
    """
    domain = domain.lower().strip().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    best: TyposquatMatch | None = None

    for brand, legit_domains in UK_BRANDS.items():
        for legit in legit_domains:
            if domain == legit:
                return None  # exact match to the real domain, not a squat

            legit_core = _strip_suffix(legit)
            domain_core = _strip_suffix(domain)

            distance = levenshtein(domain_core, legit_core)

            # Scale the "close enough to be suspicious" threshold with name
            # length so short brand names don't over-match unrelated domains.
            threshold = 1 if len(legit_core) <= 5 else 2
            if 0 < distance <= threshold:
                if best is None or distance < best.distance:
                    best = TyposquatMatch(brand=brand, legit_domain=legit, distance=distance)

    return best
