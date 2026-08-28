import httpx
import pytest

from app.modules import scan_engine
from app.modules.scan_engine import (
    STATUS_CAUTION,
    STATUS_DANGER,
    STATUS_SAFE,
    Signal,
    check_direct_ip,
    resolve_shortener,
    scan_message,
    scan_url,
)
from app.modules.typosquat import check_typosquatting

# Reuse the "patch every real-signal-check to safe" fixture from the
# existing scan_engine tests rather than redefining it.
from tests.test_scan_engine import all_checks_safe  # noqa: F401


def _safe(name: str) -> Signal:
    return Signal(name=name, status=STATUS_SAFE, reason=f"{name} looks fine.", score=0)


@pytest.fixture
def network_checks_safe(monkeypatch):
    """Patch only the network-dependent checks to safe, leaving the local,
    offline typosquat/IP/shortener checks running for real."""
    monkeypatch.setattr(scan_engine, "check_urlhaus", lambda url: _safe("URLhaus"))
    monkeypatch.setattr(scan_engine, "check_openphish", lambda url: _safe("OpenPhish"))
    monkeypatch.setattr(scan_engine, "check_spamhaus_dbl", lambda domain: _safe("Spamhaus"))
    monkeypatch.setattr(scan_engine, "check_domain_age", lambda domain: _safe("Domain age"))
    monkeypatch.setattr(
        scan_engine, "check_ssl_certificate", lambda domain, is_typosquat: _safe("SSL")
    )


# ---------------------------------------------------------------------------
# Direct IP address detection
# ---------------------------------------------------------------------------


class TestDirectIpDetection:
    @pytest.mark.parametrize("ip", ["192.168.1.1", "8.8.8.8", "203.0.113.42"])
    def test_ipv4_address_is_flagged(self, ip):
        signal = check_direct_ip(ip)
        assert signal.status == STATUS_CAUTION
        assert signal.score > 0

    def test_ipv6_address_is_flagged(self):
        signal = check_direct_ip("2001:db8::1")
        assert signal.status == STATUS_CAUTION

    def test_normal_domain_is_not_flagged(self):
        signal = check_direct_ip("example.com")
        assert signal.status == STATUS_SAFE
        assert signal.score == 0

    def test_empty_domain_is_unknown(self):
        assert check_direct_ip("").status == "unknown"

    def test_raw_ip_url_pushes_verdict_to_at_least_caution(self, all_checks_safe):
        result = scan_url("http://203.0.113.42/login")
        assert result.verdict in ("CAUTION", "DANGER")
        assert any(s.name == "Direct IP address check" and s.status == STATUS_CAUTION for s in result.signals)


# ---------------------------------------------------------------------------
# URL shortener resolution
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, url: str):
        self.url = url


class _FakeClient:
    """Stand-in for httpx.Client that returns a canned final destination."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def get(self, url):
        return _FakeResponse("https://real-destination.example/landing")


class _TimeoutClient:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def get(self, url):
        raise httpx.ConnectTimeout("timed out")


class TestShortenerResolution:
    def test_non_shortener_domain_is_left_alone_and_makes_no_network_call(self):
        signal, resolved = resolve_shortener("https://example.com/page", "example.com")
        assert signal.status == STATUS_SAFE
        assert resolved == "https://example.com/page"

    def test_shortener_domain_resolves_to_real_destination(self, monkeypatch):
        monkeypatch.setattr(httpx, "Client", _FakeClient)
        signal, resolved = resolve_shortener("https://bit.ly/3xample", "bit.ly")
        assert signal.status == STATUS_CAUTION
        assert resolved == "https://real-destination.example/landing"
        assert "real-destination.example" in signal.reason

    def test_shortener_timeout_falls_back_to_original_url_with_caution_note(self, monkeypatch):
        monkeypatch.setattr(httpx, "Client", _TimeoutClient)
        signal, resolved = resolve_shortener("https://tinyurl.com/abc123", "tinyurl.com")
        assert signal.status == STATUS_CAUTION
        assert resolved == "https://tinyurl.com/abc123"
        assert "could not resolve" in signal.reason.lower()

    def test_scan_url_follows_shortener_and_checks_the_real_destination(
        self, all_checks_safe, monkeypatch
    ):
        monkeypatch.setattr(httpx, "Client", _FakeClient)
        result = scan_url("https://bit.ly/3xample")

        assert result.domain == "real-destination.example"
        assert result.original_url == "http://bit.ly/3xample" or "bit.ly" in result.original_url
        assert any(s.name == "URL shortener check" for s in result.signals)

    def test_scan_url_gracefully_degrades_when_shortener_cannot_be_resolved(
        self, all_checks_safe, monkeypatch
    ):
        monkeypatch.setattr(httpx, "Client", _TimeoutClient)
        result = scan_url("https://is.gd/whatever")

        # Falls back to checking the shortener link itself rather than crashing.
        assert result.verdict in ("SAFE", "CAUTION", "DANGER")
        assert result.domain == "is.gd"
        assert any("could not resolve" in s.reason.lower() for s in result.signals)


# ---------------------------------------------------------------------------
# Expanded UK brand list (typosquat.py, 11 -> 30+ brands)
# ---------------------------------------------------------------------------


class TestExpandedBrandList:
    def test_brand_list_has_at_least_thirty_entries(self):
        from app.modules.typosquat import UK_BRANDS

        assert len(UK_BRANDS) >= 30

    @pytest.mark.parametrize(
        "legit_domain",
        [
            "nationwide.co.uk",
            "halifax.co.uk",
            "tsb.co.uk",
            "monzo.com",
            "starlingbank.com",
            "paypal.com",
            "amazon.co.uk",
            "britishgas.co.uk",
            "octopus.energy",
            "nhs.uk",
            "dvsa.gov.uk",
            "aviva.co.uk",
            "yodel.co.uk",
            "parcelforce.com",
        ],
    )
    def test_exact_legitimate_domains_of_new_brands_are_not_flagged(self, legit_domain):
        assert check_typosquatting(legit_domain) is None

    @pytest.mark.parametrize(
        "suspicious_domain",
        [
            "nationwide-secure-login.com",
            "monzo-account-verify.com",
            "paypal-account-verify-now.com",
            "amazon-uk-security-alert.com",
            "britishgas-billing-update.com",
            "nhs-covid-pass-verify.com",
            "octopusenergy-refund-claim.com",
            "starlingbank-suspicious-activity.com",
        ],
    )
    def test_new_brand_names_embedded_in_unrelated_domains_are_flagged(self, suspicious_domain):
        match = check_typosquatting(suspicious_domain)
        assert match is not None, f"{suspicious_domain} should have been flagged"
        assert match.kind == "brand_substring"

    @pytest.mark.parametrize(
        "typo_domain",
        [
            "natiowide.co.uk",  # Nationwide
            "monz0.com",  # Monzo
            "hallfax.co.uk",  # Halifax
        ],
    )
    def test_near_miss_typos_of_new_brands_are_flagged(self, typo_domain):
        match = check_typosquatting(typo_domain)
        assert match is not None, f"{typo_domain} should have been flagged as a near-miss typo"
        assert match.distance > 0

    @pytest.mark.parametrize(
        "legit_subdomain",
        [
            "secure.paypal.com",
            "www.nationwide.co.uk",
            "my.starlingbank.com",
            "www.nhs.uk",
        ],
    )
    def test_genuine_subdomains_of_new_brands_are_not_flagged(self, legit_subdomain):
        assert check_typosquatting(legit_subdomain) is None

    def test_new_brand_typosquat_feeds_into_danger_verdict_via_scan_message(
        self, network_checks_safe
    ):
        result = scan_message(
            "URGENT: your account has been suspended. Verify now at "
            "paypal-account-verify-now.com or call 0901 122 3344"
        )
        assert result.verdict == "DANGER"
        assert any("PayPal" in reason for reason in result.reasons)


# ---------------------------------------------------------------------------
# Full message scanning (URLs + phone numbers + pressure language)
# ---------------------------------------------------------------------------


class TestScanMessage:
    def test_single_bare_url_behaves_like_scan_url(self, all_checks_safe):
        direct = scan_url("example.com")
        via_message = scan_message("example.com")
        assert via_message.verdict == direct.verdict
        assert via_message.domain == direct.domain

    def test_message_with_no_url_or_phone_falls_back_without_crashing(self, all_checks_safe):
        result = scan_message("Hi, just checking if we're still on for lunch tomorrow.")
        assert result.verdict in ("SAFE", "CAUTION", "DANGER")

    def test_empty_input_returns_safe_with_a_helpful_reason(self):
        result = scan_message("")
        assert result.verdict == "SAFE"
        assert len(result.reasons) > 0

    def test_extracts_url_and_phone_and_records_them_on_the_result(self, network_checks_safe):
        result = scan_message(
            "Your parcel could not be delivered. Visit example.com or call 07911 123456."
        )
        assert "example.com" in result.extracted_urls
        assert any("07911" in p.replace(" ", "") for p in result.extracted_phones)

    def test_combines_url_phone_and_pressure_signals_into_one_verdict(self, network_checks_safe):
        message = (
            "Your account has been suspended. Verify immediately at "
            "hmrc-tax-refund-claim.com or call 0901 122 3344 to avoid losing access."
        )
        result = scan_message(message)

        signal_names = {s.name for s in result.signals}
        assert "Brand impersonation check" in signal_names
        assert "Phone number check" in signal_names
        assert "Pressure-tactic language" in signal_names
        assert result.verdict == "DANGER"

    def test_safe_message_with_normal_link_and_number_stays_safe(self, network_checks_safe):
        result = scan_message("Hi, here's the doc: example.com or call 020 7946 0958")
        assert result.verdict == "SAFE"

    def test_message_with_only_a_phone_number_is_handled(self, network_checks_safe):
        result = scan_message("Please call us urgently on 0901 122 3344")
        assert result.extracted_phones and not result.extracted_urls
        assert any(s.name == "Phone number check" and s.status == STATUS_CAUTION for s in result.signals)
        assert result.verdict in ("SAFE", "CAUTION", "DANGER")

    def test_standalone_phone_number_matching_scam_pattern_is_not_silently_safe(self):
        # Regression test: a bare "09..." premium-rate number with no URL or
        # message text used to slip through as a plain "Looks Safe" with no
        # phone-specific reason, because the phone signal's score (15) never
        # crossed CAUTION_THRESHOLD (20) on its own. A confirmed match
        # against a documented scam pattern must surface as CAUTION with the
        # concrete reason, not disappear into the generic SAFE reasons.
        result = scan_message("09012345678")

        assert result.extracted_phones == ["09012345678"]
        assert not result.extracted_urls
        phone_signals = [s for s in result.signals if s.name == "Phone number check"]
        assert len(phone_signals) == 1
        assert phone_signals[0].status == STATUS_CAUTION

        assert result.verdict != "SAFE"
        assert any("09" in reason and "premium-rate" in reason for reason in result.reasons)

    def test_standalone_phone_number_not_matching_any_pattern_is_safe(self):
        # An ordinary UK mobile number with nothing else pasted should stay
        # SAFE - this is the correct, intended behaviour (not a gap).
        result = scan_message("07911123456")

        assert result.extracted_phones == ["07911123456"]
        assert not result.extracted_urls
        phone_signals = [s for s in result.signals if s.name == "Phone number check"]
        assert len(phone_signals) == 1
        assert phone_signals[0].status == STATUS_SAFE

        assert result.verdict == "SAFE"
