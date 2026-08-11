"""
The scoring model: which categories fire, how they add up, where the risk
thresholds sit.
"""

import pytest

from phishguard import (
    DANGEROUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    analyze,
    analyze_text,
    get_risk_level,
)
from phishguard.rules import CATEGORIES


def categories_of(text):
    return {finding.category for finding in analyze(text).findings}


def scoring_categories_of(text):
    return set(analyze(text).scored_categories)


class TestAnalyzeText:
    def test_benign_email_has_no_flags(self):
        flags, score = analyze_text("Hi, just checking in about lunch tomorrow.")
        assert flags == []
        assert score == 0

    def test_urgent_language_is_flagged(self):
        flags, score = analyze_text("Act now, your account will be closed!")
        assert score > 0
        assert "urgency" in scoring_categories_of("Act now, your account will be closed!")
        assert any("Urgent language" in flag for flag in flags)

    def test_generic_administrative_language_is_not_flagged(self):
        # "immediately"/"important notice"/"action required" were removed from
        # the urgency list after measurement: they fire on ordinary legitimate
        # mail with no phishing-specific signal (see README).
        _, score = analyze_text(
            "Important notice: our office will be closed for the holidays. "
            "No action required, this change is effective immediately."
        )
        assert score == 0

    def test_personal_info_request_is_flagged(self):
        flags, _ = analyze_text("Please confirm your password to continue.")
        assert any("personal information" in flag for flag in flags)

    def test_ip_based_url_is_flagged(self):
        flags, _ = analyze_text("Login here: http://192.168.1.1/login")
        assert any("IP address" in flag for flag in flags)

    def test_shortened_url_is_flagged(self):
        flags, _ = analyze_text("Check this out: http://bit.ly/abc123")
        assert any("Shortened URL" in flag for flag in flags)

    def test_risky_attachment_mention_is_flagged(self):
        flags, score = analyze_text("Please see the attached invoice-2024.exe for details.")
        assert score > 0
        assert any("risky attachment" in flag for flag in flags)

    def test_com_extension_is_not_flagged_as_attachment(self):
        flags, _ = analyze_text("Visit example.com for more information.")
        assert not any("risky attachment" in flag for flag in flags)

    def test_prize_scam_language_is_flagged(self):
        flags, score = analyze_text("You have won $500,000. Click here to claim.")
        assert score > 0
        assert any("Prize/lottery scam" in flag for flag in flags)

    def test_password_expiry_urgency_is_flagged(self):
        text = "Dear user, your email password expires today. Reset now."
        flags, score = analyze_text(text)
        assert score > 0
        assert any("Urgent language" in flag for flag in flags)
        assert "greeting" in scoring_categories_of(text)

    def test_advance_fee_scam_language_is_flagged(self):
        flags, score = analyze_text(
            "Dear friend, I am the next of kin to a dormant account holding a "
            "large sum of money. Please assist me to transfer these funds."
        )
        assert score > 0
        assert any("Advance-fee scam" in flag for flag in flags)

    def test_account_validation_phrasing_is_flagged(self):
        flags, score = analyze_text(
            "Security alert: please validate your account by clicking the link below."
        )
        assert score > 0
        assert any("personal information" in flag for flag in flags)

    def test_identity_number_request_is_flagged(self):
        text = "Urgent: Update your BVN immediately to avoid restriction."
        assert {"credentials", "account_threat"} <= scoring_categories_of(text)
        assert get_risk_level(analyze(text).score) != "Safe"

    def test_combined_signals_reach_the_dangerous_band(self):
        analysis = analyze(
            "Urgent: verify your account now by visiting "
            "http://paypa1.com/login or your account will be terminated."
        )
        assert analysis.score >= DANGEROUS_THRESHOLD
        assert analysis.risk_level == "Dangerous"


class TestInformationalFindings:
    def test_links_alone_are_not_scored(self):
        flags, score = analyze_text("See the agenda here: http://example.com/agenda")
        assert score == 0
        assert any("link" in flag for flag in flags)
        assert any("HTTP" in flag for flag in flags)

    def test_informational_findings_are_still_reported(self):
        analysis = analyze("See the agenda here: http://example.com/agenda")
        assert analysis.findings
        assert analysis.scored_categories == []

    def test_credential_looking_path_is_informational_only(self):
        # Real login pages use /login too, so the path alone must not score.
        analysis = analyze("Your invoice is ready: https://example.com/account/login")
        assert analysis.score == 0


class TestCategoryWeighting:
    def test_a_category_counts_once_however_many_of_its_rules_match(self):
        """
        The core of the scoring model. Both texts trip the credentials category;
        the second trips four different phrasings of it. They must score the
        same, so a verbose sender can't inflate the score.
        """
        one_phrasing = analyze("Please verify your account.")
        many_phrasings = analyze(
            "Please verify your account, confirm your details, validate your account "
            "and enter your password to restore your account."
        )
        assert "credentials" in one_phrasing.scored_categories
        assert one_phrasing.score == many_phrasings.score

    def test_score_is_the_sum_of_distinct_category_weights(self):
        analysis = analyze("Act now, your account will be closed!")
        expected = sum(CATEGORIES[key].weight for key in set(analysis.scored_categories))
        assert analysis.score == expected

    def test_duplicate_phrase_is_reported_once_per_category(self):
        """
        "verify your account" appears in both the credentials phrase list and the
        broader verify/update pattern. It should be listed once, not twice.
        """
        analysis = analyze("Please verify your account.")
        credential_messages = [
            f.message for f in analysis.findings if f.category == "credentials"
        ]
        assert len(credential_messages) == len(set(credential_messages))
        assert len(credential_messages) == 1

    def test_grouped_orders_by_weight_with_informational_last(self):
        analysis = analyze(
            "Dear Customer, your account will be suspended. Verify your account "
            "at http://paypa1.com/login within 24 hours."
        )
        weights = [category.weight for category, _ in analysis.grouped()]
        assert weights == sorted(weights, reverse=True)
        assert weights[-1] == 0

    def test_flags_property_matches_finding_messages(self):
        analysis = analyze("Act now, your account will be closed!")
        assert analysis.flags == [f.message for f in analysis.findings]


class TestBrandLinkMismatch:
    def test_brand_text_with_unrelated_link_is_flagged_when_credentials_requested(self):
        analysis = analyze(
            "Dear Customer, please verify your account with Netflix here: "
            "http://billing-update.example.org/login"
        )
        assert any(f.rule == "brand_link_mismatch" for f in analysis.findings)

    def test_brand_mention_without_a_credential_request_is_not_flagged(self):
        # A news digest linking to coverage of a brand is completely ordinary.
        analysis = analyze(
            "Today's roundup: Netflix earnings beat expectations. "
            "Read more at https://news.example.org/story/1"
        )
        assert not any(f.rule == "brand_link_mismatch" for f in analysis.findings)

    def test_link_to_the_real_brand_domain_is_not_flagged(self):
        analysis = analyze(
            "Please verify your account at https://www.netflix.com/account to continue."
        )
        assert not any(f.rule == "brand_link_mismatch" for f in analysis.findings)


class TestGetRiskLevel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "Safe"),
            (SUSPICIOUS_THRESHOLD - 1, "Safe"),
            (SUSPICIOUS_THRESHOLD, "Suspicious"),
            (DANGEROUS_THRESHOLD - 1, "Suspicious"),
            (DANGEROUS_THRESHOLD, "Dangerous"),
            (DANGEROUS_THRESHOLD + 10, "Dangerous"),
        ],
    )
    def test_risk_level_thresholds(self, score, expected):
        assert get_risk_level(score) == expected

    def test_thresholds_are_ordered(self):
        assert 0 < SUSPICIOUS_THRESHOLD < DANGEROUS_THRESHOLD

    def test_a_single_weak_signal_is_not_called_phishing(self):
        """
        The calibration decision, pinned as a test: one urgency phrase on its own
        must stay Safe. Marketing copy reuses that language constantly, and
        scoring it as Suspicious is what produced a 40% false-positive rate on
        the legitimate-marketing stress set.
        """
        analysis = analyze("Act now — limited time offer, our sale expires soon!")
        assert analysis.scored_categories == ["urgency"]
        assert analysis.risk_level == "Safe"


class TestDeterminism:
    def test_analysis_is_pure(self):
        text = "Dear Customer, verify your account at http://paypa1.com/login"
        first, second = analyze(text), analyze(text)
        assert first.score == second.score
        assert first.flags == second.flags

    def test_empty_input_is_safe_and_silent(self):
        analysis = analyze("")
        assert analysis.findings == []
        assert analysis.score == 0
        assert analysis.risk_level == "Safe"
