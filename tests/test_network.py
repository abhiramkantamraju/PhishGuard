"""
The network-backed checks (Google Safe Browsing, WHOIS domain age).

No test here touches the network: the HTTP post and the WHOIS lookup are both
injected, which is why `check_safe_browsing` and `check_domain_age` take them as
parameters at all. The behaviour that matters most is the failure behaviour —
every one of these calls happens on a live scan, so any of them failing has to
mean "no extra flag", never "the scan breaks".
"""

from datetime import datetime, timedelta

import requests

from phishguard import (
    analyze_urls_network,
    check_domain_age,
    check_safe_browsing,
    network_findings,
)


class FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


def whois_returning(creation_date):
    def fake_whois(hostname):
        return type("Record", (), {"creation_date": creation_date})()

    return fake_whois


class TestCheckSafeBrowsing:
    def test_no_api_key_returns_no_flags_without_calling_network(self):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("should not be called without an API key")

        assert check_safe_browsing(
            ["http://evil.com"], api_key=None, http_post=fail_if_called
        ) == []

    def test_no_urls_returns_no_flags_without_calling_network(self):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("should not be called with no URLs")

        assert check_safe_browsing([], api_key="key", http_post=fail_if_called) == []

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

    def test_repeated_match_for_one_url_is_reported_once(self):
        def fake_post(url, params, json, timeout):
            return FakeResponse({
                "matches": [
                    {"threat": {"url": "http://evil.com"}, "threatType": "MALWARE"},
                    {"threat": {"url": "http://evil.com"}, "threatType": "SOCIAL_ENGINEERING"},
                ]
            })

        assert len(check_safe_browsing(["http://evil.com"], "key", http_post=fake_post)) == 1

    def test_no_match_returns_no_flags(self):
        flags = check_safe_browsing(
            ["http://example.com"], api_key="fake-key",
            http_post=lambda url, params, json, timeout: FakeResponse({}),
        )
        assert flags == []

    def test_network_failure_is_swallowed(self):
        def raising_post(url, params, json, timeout):
            raise requests.exceptions.ConnectionError("network down")

        assert check_safe_browsing(["http://example.com"], "key", http_post=raising_post) == []

    def test_http_error_is_swallowed(self):
        flags = check_safe_browsing(
            ["http://example.com"], "key",
            http_post=lambda url, params, json, timeout: FakeResponse({}, status_code=429),
        )
        assert flags == []

    def test_malformed_json_is_swallowed(self):
        class BadJson(FakeResponse):
            def json(self):
                raise ValueError("not json")

        flags = check_safe_browsing(
            ["http://example.com"], "key",
            http_post=lambda url, params, json, timeout: BadJson({}),
        )
        assert flags == []


class TestCheckDomainAge:
    def test_recently_registered_domain_is_flagged(self):
        flags = check_domain_age(
            "evil.com", whois_lookup=whois_returning(datetime.now() - timedelta(days=2))
        )
        assert len(flags) == 1
        assert "evil.com" in flags[0]

    def test_old_domain_is_not_flagged(self):
        assert check_domain_age(
            "paypal.com", whois_lookup=whois_returning(datetime.now() - timedelta(days=3650))
        ) == []

    def test_missing_creation_date_is_not_flagged(self):
        assert check_domain_age("example.com", whois_lookup=whois_returning(None)) == []

    def test_list_of_creation_dates_uses_the_first(self):
        # Some registries return several dates; python-whois passes them through.
        dates = [datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=900)]
        assert check_domain_age("evil.com", whois_lookup=whois_returning(dates)) != []

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

        flags, score = analyze_urls_network(
            ["http://evil.com"], api_key="fake-key", http_post=fake_post,
            whois_lookup=whois_returning(datetime.now() - timedelta(days=1)),
        )
        assert len(flags) == 2
        assert score == 7

    def test_no_api_key_still_checks_domain_age(self):
        flags, score = analyze_urls_network(
            ["http://evil.com"], api_key=None,
            whois_lookup=whois_returning(datetime.now() - timedelta(days=1)),
        )
        assert len(flags) == 1
        assert score == 2

    def test_deduplicates_repeated_root_domains(self):
        calls = []

        def counting_whois(hostname):
            calls.append(hostname)
            return type("Record", (), {"creation_date": None})()

        analyze_urls_network(
            ["http://a.example.com/1", "http://b.example.com/2"],
            api_key=None, whois_lookup=counting_whois,
        )
        assert calls == ["example.com"]

    def test_domain_lookups_are_capped(self):
        """
        An email can contain dozens of links; a WHOIS lookup each would make the
        request unbounded. At most three unique domains are checked.
        """
        calls = []

        def counting_whois(hostname):
            calls.append(hostname)
            return type("Record", (), {"creation_date": None})()

        analyze_urls_network(
            [f"http://site{index}.example{index}.com" for index in range(10)],
            api_key=None, whois_lookup=counting_whois,
        )
        assert len(calls) == 3

    def test_no_urls_produces_nothing(self):
        assert analyze_urls_network([], api_key=None) == ([], 0)


class TestNetworkFindings:
    def test_returns_findings_with_the_link_category(self):
        findings, score = network_findings(
            ["http://evil.com"], api_key=None,
            whois_lookup=whois_returning(datetime.now() - timedelta(days=1)),
        )
        assert score == 2
        assert [f.category for f in findings] == ["link_manipulation"]
        assert findings[0].category_label
        assert findings[0].advice

    def test_scores_match_the_flat_variant(self):
        def fake_post(url, params, json, timeout):
            return FakeResponse({
                "matches": [{"threat": {"url": "http://evil.com"}, "threatType": "MALWARE"}]
            })

        whois = whois_returning(datetime.now() - timedelta(days=1))
        flags, flat_score = analyze_urls_network(
            ["http://evil.com"], "key", http_post=fake_post, whois_lookup=whois
        )
        findings, structured_score = network_findings(
            ["http://evil.com"], "key", http_post=fake_post, whois_lookup=whois
        )
        assert flat_score == structured_score
        assert flags == [f.message for f in findings]
