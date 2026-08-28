import pytest

from app.modules.message_scan import PRESSURE_PHRASES, check_pressure_phrases, extract_urls
from app.modules.signal_types import STATUS_CAUTION, STATUS_SAFE


class TestExtractUrls:
    def test_finds_full_https_url(self):
        text = "Click here: https://bit.ly/3xample to claim your refund"
        assert extract_urls(text) == ["https://bit.ly/3xample"]

    def test_finds_bare_domain_without_scheme(self):
        text = "Your parcel could not be delivered. Visit royal-mail-redelivery.com to reschedule."
        assert extract_urls(text) == ["royal-mail-redelivery.com"]

    def test_finds_domain_with_www_and_path(self):
        text = "Visit www.dvla.gov.uk/renew for more info."
        assert extract_urls(text) == ["www.dvla.gov.uk/renew"]

    def test_finds_multiple_distinct_urls(self):
        text = "Check hmrc-tax-refund-claim.com or https://bit.ly/abc for details"
        found = extract_urls(text)
        assert "hmrc-tax-refund-claim.com" in found
        assert "https://bit.ly/abc" in found
        assert len(found) == 2

    def test_deduplicates_repeated_urls(self):
        text = "amazon.co.uk and again amazon.co.uk"
        assert extract_urls(text) == ["amazon.co.uk"]

    def test_no_url_in_plain_text_returns_empty(self):
        assert extract_urls("Hi John, see you at 3pm.") == []

    def test_empty_text_returns_empty_list(self):
        assert extract_urls("") == []

    def test_trailing_punctuation_is_stripped(self):
        text = "Is this safe? Try amazon.co.uk."
        found = extract_urls(text)
        assert found == ["amazon.co.uk"]


class TestCheckPressurePhrases:
    @pytest.mark.parametrize("phrase", PRESSURE_PHRASES)
    def test_each_known_pressure_phrase_is_detected(self, phrase):
        signal = check_pressure_phrases(f"Important notice: {phrase} to avoid losing access.")
        assert signal.status == STATUS_CAUTION
        assert signal.score > 0

    def test_detection_is_case_insensitive(self):
        signal = check_pressure_phrases("URGENT: Your Account Has Been Suspended, ACT NOW")
        assert signal.status == STATUS_CAUTION

    def test_ordinary_message_is_not_flagged(self):
        signal = check_pressure_phrases("Hi, just checking if we're still on for lunch tomorrow.")
        assert signal.status == STATUS_SAFE
        assert signal.score == 0

    def test_empty_text_is_safe(self):
        signal = check_pressure_phrases("")
        assert signal.status == STATUS_SAFE
