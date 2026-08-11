"""URL and domain inspection: extraction, normalisation, spoofing detection."""

import pytest

from phishguard.urls import (
    check_domain_spoofing,
    extract_urls,
    get_hostname,
    get_root_domain,
    get_tld,
    has_userinfo_trick,
    is_punycode,
    levenshtein_distance,
    normalize_confusables,
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


class TestUrlExtraction:
    def test_finds_http_and_www(self):
        urls = extract_urls("Visit http://example.com or www.example.org for details")
        assert urls == ["http://example.com", "www.example.org"]

    def test_none_present(self):
        assert extract_urls("No links in this message.") == []

    def test_trailing_punctuation_is_not_part_of_the_url(self):
        # A URL written inside prose or parentheses must not absorb the closing
        # bracket, or the hostname comparison downstream sees a different domain.
        assert extract_urls("see (http://example.com/a) for more") == ["http://example.com/a"]
        assert extract_urls("read http://example.com/page'") == ["http://example.com/page"]


class TestHostname:
    def test_strips_www(self):
        assert get_hostname("http://www.paypal.com/login") == "paypal.com"

    def test_without_scheme(self):
        assert get_hostname("paypal.com/login") == "paypal.com"

    def test_strips_port(self):
        assert get_hostname("http://example.com:8080/path") == "example.com"

    def test_strips_userinfo(self):
        # Everything before the '@' is decoration; the browser goes to the host
        # after it, and so must the analysis.
        assert get_hostname("http://www.paypal.com@203.0.113.4/login") == "203.0.113.4"

    @pytest.mark.parametrize(
        "url", ["http://[bad", "http://a[b].com/x", "http://]", "www.[]"],
        ids=["unbalanced", "bracket-in-host", "close-only", "empty-brackets"],
    )
    def test_malformed_urls_do_not_raise(self, url):
        """
        Regression: `urlparse` raises ValueError("Invalid IPv6 URL") on anything
        with an unbalanced bracket, which crashed analysis on real pasted email
        (a wrapped line, a stray bracket from a quoted reply). Analysis must
        degrade to a best-effort hostname, never propagate the error.
        """
        assert isinstance(get_hostname(url), str)

    def test_root_domain_with_subdomain(self):
        assert get_root_domain("mail.google.com") == "google.com"

    def test_root_domain_single_label(self):
        assert get_root_domain("localhost") == "localhost"

    def test_tld(self):
        assert get_tld("example.co") == "co"
        assert get_tld("localhost") == ""


class TestUserinfoTrick:
    def test_userinfo_before_host_is_detected(self):
        assert has_userinfo_trick("http://www.paypal.com@203.0.113.4/login")

    def test_at_sign_in_the_path_is_not_flagged(self):
        # A mailto-style address or an @handle in a path is ordinary.
        assert not has_userinfo_trick("http://example.com/users/@abhiram")

    def test_plain_url_is_not_flagged(self):
        assert not has_userinfo_trick("https://example.com/login")


class TestConfusables:
    def test_cyrillic_is_normalised_to_latin(self):
        assert normalize_confusables("pа" + "ypal") == "paypal"

    def test_punycode_is_detected(self):
        assert is_punycode("xn--pple-43d.com")
        assert not is_punycode("apple.com")


class TestDomainSpoofing:
    def test_legitimate_domain_is_not_flagged(self):
        assert check_domain_spoofing("https://www.paypal.com/signin") == []

    def test_unrelated_domain_is_not_flagged(self):
        assert check_domain_spoofing("https://example.com") == []

    def test_brand_name_in_unrelated_domain_is_flagged(self):
        flags = check_domain_spoofing("http://paypal-secure-login.com")
        assert any("impersonation" in flag for flag in flags)

    def test_typo_squatting_is_flagged(self):
        flags = check_domain_spoofing("http://paypa1.com")
        assert any("typo-squatting" in flag or "misspelled" in flag for flag in flags)

    def test_cyrillic_homograph_is_flagged(self):
        # "а" here is Cyrillic U+0430, visually identical to Latin "a".
        flags = check_domain_spoofing("http://pаypal.com/login")
        assert any("homograph" in flag for flag in flags)
        assert any("misspelled" in flag for flag in flags)

    def test_punycode_domain_is_flagged(self):
        flags = check_domain_spoofing("http://xn--pple-43d.com")
        assert any("punycode" in flag for flag in flags)

    def test_plain_ascii_domain_has_no_homograph_or_punycode_flag(self):
        flags = check_domain_spoofing("https://example.com")
        assert not any("homograph" in flag for flag in flags)
        assert not any("punycode" in flag for flag in flags)

    def test_subdomain_of_official_domain_is_not_flagged(self):
        assert check_domain_spoofing("https://mail.google.com/inbox") == []
