from datetime import datetime, timedelta

import pytest
import requests

from detector import (
    analyze_text,
    analyze_urls_network,
    check_domain_age,
    check_domain_spoofing,
    check_safe_browsing,
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

    def test_prize_scam_language_is_flagged(self):
        flags, score = analyze_text("You have won $500,000. Click here to claim.")
        assert score > 0
        assert any("Prize/lottery scam" in flag for flag in flags)

    def test_password_expiry_urgency_is_flagged(self):
        flags, score = analyze_text("Dear user, your email password expires today. Reset now.")
        assert score > 0
        assert any("Urgent language" in flag for flag in flags)


class FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


class TestCheckSafeBrowsing:
    def test_no_api_key_returns_no_flags_without_calling_network(self):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("should not be called without an API key")

        flags = check_safe_browsing(["http://evil.com"], api_key=None, http_post=fail_if_called)
        assert flags == []

    def test_match_is_flagged(self):
        def fake_post(url, params, json, timeout):
            return FakeResponse({
                "matches": [
                    {"threat": {"url": "http://evil.com"}, "threatType": "SOCIAL_ENGINEERING"}
                ]
            })

        flags = check_safe_browsing(["http://evil.com"], api_key="fake-key", http_post=fake_post)
        assert len(flags) == 1
        assert "evil.com" in flags[0]
        assert "social engineering" in flags[0]

    def test_no_match_returns_no_flags(self):
        def fake_post(url, params, json, timeout):
            return FakeResponse({})

        flags = check_safe_browsing(["http://example.com"], api_key="fake-key", http_post=fake_post)
        assert flags == []

    def test_network_failure_is_swallowed(self):
        def raising_post(url, params, json, timeout):
            raise requests.exceptions.ConnectionError("network down")

        flags = check_safe_browsing(["http://example.com"], api_key="fake-key", http_post=raising_post)
        assert flags == []


class TestCheckDomainAge:
    def test_recently_registered_domain_is_flagged(self):
        def fake_whois(hostname):
            return type("Record", (), {"creation_date": datetime.now() - timedelta(days=2)})()

        flags = check_domain_age("evil.com", whois_lookup=fake_whois)
        assert len(flags) == 1
        assert "evil.com" in flags[0]

    def test_old_domain_is_not_flagged(self):
        def fake_whois(hostname):
            return type("Record", (), {"creation_date": datetime.now() - timedelta(days=3650)})()

        assert check_domain_age("paypal.com", whois_lookup=fake_whois) == []

    def test_missing_creation_date_is_not_flagged(self):
        def fake_whois(hostname):
            return type("Record", (), {"creation_date": None})()

        assert check_domain_age("example.com", whois_lookup=fake_whois) == []

    def test_lookup_failure_is_swallowed(self):
        def raising_whois(hostname):
            raise Exception("WHOIS server unreachable")

        assert check_domain_age("example.com", whois_lookup=raising_whois) == []


class TestAnalyzeUrlsNetwork:
    def test_combines_safe_browsing_and_domain_age_signals(self):
        def fake_post(url, params, json, timeout):
            return FakeResponse({
                "matches": [{"threat": {"url": "http://evil.com"}, "threatType": "MALWARE"}]
            })

        def fake_whois(hostname):
            return type("Record", (), {"creation_date": datetime.now() - timedelta(days=1)})()

        flags, score = analyze_urls_network(
            ["http://evil.com"], api_key="fake-key", http_post=fake_post, whois_lookup=fake_whois
        )
        assert len(flags) == 2
        assert score == 7

    def test_no_api_key_still_checks_domain_age(self):
        def fake_whois(hostname):
            return type("Record", (), {"creation_date": datetime.now() - timedelta(days=1)})()

        flags, score = analyze_urls_network(
            ["http://evil.com"], api_key=None, whois_lookup=fake_whois
        )
        assert len(flags) == 1
        assert score == 2

    def test_deduplicates_repeated_root_domains(self):
        calls = []

        def fake_whois(hostname):
            calls.append(hostname)
            return type("Record", (), {"creation_date": None})()

        analyze_urls_network(
            ["http://a.example.com/1", "http://b.example.com/2"],
            api_key=None,
            whois_lookup=fake_whois,
        )
        assert calls == ["example.com"]


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
