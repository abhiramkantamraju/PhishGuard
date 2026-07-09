import pytest

from detector import (
    analyze_text,
    check_domain_spoofing,
    extract_urls,
    get_hostname,
    get_risk_level,
    get_root_domain,
    levenshtein_distance,
)


class TestLevenshteinDistance:
    def test_identical_strings(self):
        assert levenshtein_distance("paypal", "paypal") == 0

    def test_one_substitution(self):
        assert levenshtein_distance("paypa1", "paypal") == 1

    def test_one_insertion(self):
        assert levenshtein_distance("paypall", "paypal") == 1

    def test_completely_different(self):
        assert levenshtein_distance("abc", "xyz") == 3


class TestUrlHelpers:
    def test_extract_urls_finds_http_and_www(self):
        text = "Visit http://example.com or www.example.org for details"
        urls = extract_urls(text)
        assert urls == ["http://example.com", "www.example.org"]

    def test_extract_urls_none_present(self):
        assert extract_urls("No links in this message.") == []

    def test_get_hostname_strips_www(self):
        assert get_hostname("http://www.paypal.com/login") == "paypal.com"

    def test_get_hostname_without_scheme(self):
        assert get_hostname("paypal.com/login") == "paypal.com"

    def test_get_root_domain_with_subdomain(self):
        assert get_root_domain("mail.google.com") == "google.com"

    def test_get_root_domain_single_label(self):
        assert get_root_domain("localhost") == "localhost"


class TestDomainSpoofing:
    def test_legitimate_domain_is_not_flagged(self):
        assert check_domain_spoofing("https://www.paypal.com/signin") == []

    def test_brand_name_in_unrelated_domain_is_flagged(self):
        flags = check_domain_spoofing("http://paypal-secure-login.com")
        assert any("impersonation" in flag for flag in flags)

    def test_typo_squatting_is_flagged(self):
        flags = check_domain_spoofing("http://paypa1.com")
        assert any("typo-squatting" in flag or "misspelled" in flag for flag in flags)

    def test_unrelated_domain_is_not_flagged(self):
        assert check_domain_spoofing("https://example.com") == []


class TestAnalyzeText:
    def test_benign_email_has_no_flags(self):
        flags, score = analyze_text("Hi, just checking in about lunch tomorrow.")
        assert flags == []
        assert score == 0

    def test_urgent_language_is_flagged(self):
        flags, score = analyze_text("Act now, your account will be closed!")
        assert score > 0
        assert any("Urgent language" in flag for flag in flags)

    def test_personal_info_request_is_flagged(self):
        flags, score = analyze_text("Please confirm your password to continue.")
        assert any("personal information" in flag for flag in flags)

    def test_ip_based_url_is_flagged(self):
        flags, score = analyze_text("Login here: http://192.168.1.1/login")
        assert any("IP address" in flag for flag in flags)

    def test_shortened_url_is_flagged(self):
        flags, score = analyze_text("Check this out: http://bit.ly/abc123")
        assert any("Shortened URL" in flag for flag in flags)

    def test_combined_signals_increase_score(self):
        text = (
            "Urgent: verify your account now by visiting "
            "http://paypa1.com/login or your account will be terminated."
        )
        flags, score = analyze_text(text)
        assert score >= 5
        assert get_risk_level(score) == "Dangerous"


class TestGetRiskLevel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "Safe"),
            (1, "Suspicious"),
            (4, "Suspicious"),
            (5, "Dangerous"),
            (10, "Dangerous"),
        ],
    )
    def test_risk_level_thresholds(self, score, expected):
        assert get_risk_level(score) == expected
