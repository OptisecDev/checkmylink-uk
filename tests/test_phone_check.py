import pytest

from app.modules.phone_check import (
    check_phone_number,
    extract_phone_numbers,
    normalise_phone,
)
from app.modules.signal_types import STATUS_CAUTION, STATUS_SAFE, STATUS_UNKNOWN


class TestExtractPhoneNumbers:
    def test_finds_uk_mobile_with_plus44(self):
        assert extract_phone_numbers("Call +44 7911 123456 now") == ["+44 7911 123456"]

    def test_finds_uk_mobile_with_leading_zero(self):
        assert extract_phone_numbers("Call 07911 123456 now") == ["07911 123456"]

    def test_finds_uk_landline(self):
        assert extract_phone_numbers("Ring us on 0161 496 0000 today") == ["0161 496 0000"]

    def test_finds_number_with_0044_prefix(self):
        found = extract_phone_numbers("Dial 0044 7911 123456 to claim")
        assert found == ["0044 7911 123456"]

    def test_finds_international_wangiri_style_number(self):
        found = extract_phone_numbers("You had a missed call from +370 612 34567")
        assert found == ["+370 612 34567"]

    def test_ignores_short_reference_numbers(self):
        assert extract_phone_numbers("Your order reference is 012345") == []

    def test_ignores_text_with_no_phone_number(self):
        assert extract_phone_numbers("See you at 3pm for lunch") == []

    def test_deduplicates_repeated_numbers(self):
        text = "Call 07911 123456 or call 07911 123456 again"
        assert extract_phone_numbers(text) == ["07911 123456"]

    def test_empty_text_returns_empty_list(self):
        assert extract_phone_numbers("") == []


class TestNormalisePhone:
    def test_strips_spaces_and_dashes(self):
        assert normalise_phone("0791-1 123 456") == "07911123456"

    def test_converts_0044_to_plus44(self):
        assert normalise_phone("0044 7911 123456") == "+447911123456"

    def test_leaves_plus44_unchanged(self):
        assert normalise_phone("+44 7911 123456") == "+447911123456"


class TestCheckPhoneNumber:
    @pytest.mark.parametrize("number", ["09011223344", "0901 122 3344"])
    def test_flags_premium_rate_09_numbers(self, number):
        signal = check_phone_number(number)
        assert signal.status == STATUS_CAUTION
        assert signal.score > 0

    @pytest.mark.parametrize("prefix", ["084", "087", "070"])
    def test_flags_known_premium_and_personal_number_prefixes(self, prefix):
        number = f"{prefix}1 234 5678"
        signal = check_phone_number(number)
        assert signal.status == STATUS_CAUTION

    def test_flags_wangiri_international_prefix(self):
        signal = check_phone_number("+370 612 34567")
        assert signal.status == STATUS_CAUTION
        assert "missed call" in signal.reason.lower() or "wangiri" in signal.reason.lower()

    def test_ordinary_uk_mobile_number_is_safe(self):
        signal = check_phone_number("+44 7700 900123")
        assert signal.status == STATUS_SAFE
        assert signal.score == 0

    def test_ordinary_uk_landline_is_safe(self):
        signal = check_phone_number("020 7946 0958")
        assert signal.status == STATUS_SAFE

    def test_empty_number_returns_unknown(self):
        signal = check_phone_number("")
        assert signal.status == STATUS_UNKNOWN

    def test_scam_prefix_check_also_matches_national_form_of_plus44_number(self):
        # +44 84... is the same physical number as 084... nationally.
        signal = check_phone_number("+44 84 1234 5678")
        assert signal.status == STATUS_CAUTION
