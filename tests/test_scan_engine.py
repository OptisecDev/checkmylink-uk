import httpx
import pytest

from app.modules import scan_engine
from app.modules.scan_engine import (
    STATUS_DANGER,
    STATUS_SAFE,
    STATUS_UNKNOWN,
    Signal,
    scan_url,
)
from app.modules.typosquat import check_typosquatting


def _safe_signal(name: str) -> Signal:
    return Signal(name=name, status=STATUS_SAFE, reason=f"{name} looks fine.", score=0)


@pytest.fixture
def all_checks_safe(monkeypatch):
    """Patch every individual signal check to report 'safe' by default."""
    monkeypatch.setattr(scan_engine, "check_urlhaus", lambda url: _safe_signal("URLhaus"))
    monkeypatch.setattr(scan_engine, "check_openphish", lambda url: _safe_signal("OpenPhish"))
    monkeypatch.setattr(scan_engine, "check_spamhaus_dbl", lambda domain: _safe_signal("Spamhaus"))
    monkeypatch.setattr(scan_engine, "check_domain_age", lambda domain: _safe_signal("Domain age"))
    monkeypatch.setattr(
        scan_engine, "check_typosquat_signal", lambda domain: _safe_signal("Typosquat")
    )
    monkeypatch.setattr(
        scan_engine, "check_ssl_certificate", lambda domain, is_typosquat: _safe_signal("SSL")
    )


class TestKnownSafeDomain:
    def test_all_clear_signals_produce_safe_verdict(self, all_checks_safe):
        result = scan_url("https://example.com")

        assert result.verdict == "SAFE"
        assert result.domain == "example.com"
        assert len(result.reasons) > 0

    def test_safe_reasons_are_plain_english_not_a_score_dump(self, all_checks_safe):
        result = scan_url("https://example.com")

        for reason in result.reasons:
            assert isinstance(reason, str)
            assert len(reason) > 0


class TestKnownMaliciousUrl:
    def test_urlhaus_hit_forces_danger_verdict(self, all_checks_safe, monkeypatch):
        monkeypatch.setattr(
            scan_engine,
            "check_urlhaus",
            lambda url: Signal(
                name="URLhaus malware list",
                status=STATUS_DANGER,
                reason="This exact link is on URLhaus's list of known malware sites.",
                score=50,
            ),
        )

        result = scan_url("http://malicious-test-site.example/payload")

        assert result.verdict == "DANGER"
        assert any("URLhaus" in s.name and s.status == STATUS_DANGER for s in result.signals)
        assert any("malware" in reason.lower() for reason in result.reasons)

    def test_combined_moderate_signals_produce_caution_not_danger(self, all_checks_safe, monkeypatch):
        monkeypatch.setattr(
            scan_engine,
            "check_domain_age",
            lambda domain: Signal(
                name="Domain age",
                status=STATUS_DANGER,
                reason="This domain was only registered 3 day(s) ago.",
                score=25,
            ),
        )

        result = scan_url("http://brand-new-domain.example")

        assert result.verdict == "CAUTION"


class TestTyposquattingDetection:
    @pytest.mark.parametrize(
        "suspicious_domain",
        [
            "barclay.co.uk",
            "lloydsbnk.com",
            "natwests.com",
            "royalmial.com",
            "hmrc1.gov.uk",
        ],
    )
    def test_close_variants_of_uk_brands_are_flagged(self, suspicious_domain):
        match = check_typosquatting(suspicious_domain)
        assert match is not None
        assert match.distance > 0

    def test_exact_legitimate_domain_is_not_flagged(self):
        assert check_typosquatting("barclays.co.uk") is None
        assert check_typosquatting("royalmail.com") is None

    def test_unrelated_domain_is_not_flagged(self):
        assert check_typosquatting("example.com") is None

    def test_typosquat_signal_feeds_into_danger_verdict(self, all_checks_safe, monkeypatch):
        monkeypatch.setattr(
            scan_engine,
            "check_typosquat_signal",
            lambda domain: Signal(
                name="Brand impersonation check",
                status=STATUS_DANGER,
                reason="This domain looks like a near-copy of Barclays's real website (barclays.co.uk).",
                score=50,
            ),
        )

        result = scan_url("http://barclay.co.uk/login")

        assert result.verdict == "DANGER"
        assert any("Barclays" in reason for reason in result.reasons)


class TestGracefulDegradation:
    def test_urlhaus_network_failure_returns_unknown_not_a_crash(self, monkeypatch):
        def raise_connect_error(url, data, timeout):
            raise httpx.ConnectError("network unreachable")

        monkeypatch.setattr(httpx, "post", raise_connect_error)

        signal = scan_engine.check_urlhaus("https://example.com")

        assert signal.status == STATUS_UNKNOWN
        assert "unable to check" in signal.reason.lower()

    def test_spamhaus_dns_failure_returns_unknown_not_a_crash(self, monkeypatch):
        import socket

        def raise_timeout(*args, **kwargs):
            raise socket.timeout("dns timed out")

        monkeypatch.setattr(socket, "gethostbyname", raise_timeout)

        signal = scan_engine.check_spamhaus_dbl("example.com")

        assert signal.status == STATUS_UNKNOWN

    def test_whole_scan_completes_when_one_source_is_unreachable(self, all_checks_safe, monkeypatch):
        monkeypatch.setattr(
            scan_engine,
            "check_openphish",
            lambda url: Signal(
                name="OpenPhish community feed",
                status=STATUS_UNKNOWN,
                reason="Unable to check the OpenPhish feed right now.",
                score=0,
            ),
        )

        result = scan_url("https://example.com")

        assert result.verdict in ("SAFE", "CAUTION", "DANGER")
        assert any(s.status == STATUS_UNKNOWN for s in result.signals)
