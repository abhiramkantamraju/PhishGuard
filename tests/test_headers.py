"""
Sender-header inspection.

The evaluation corpora are subject-and-body only, so these rules can't show up
in the README's benchmark numbers — this file is where they're held to account
instead. Each test states the mismatch it is about and the ordinary case that
must *not* be flagged, because a header rule that fires on genuine mail is worse
than no header rule at all.
"""

from phishguard import analyze, check_sender_headers, extract_headers
from phishguard.headers import split_address


class TestExtractHeaders:
    def test_reads_the_leading_header_block(self):
        headers = extract_headers(
            "From: Alice <alice@example.com>\n"
            "Subject: Lunch\n"
            "\n"
            "Are we still on for Friday?"
        )
        assert headers["from"] == "Alice <alice@example.com>"
        assert headers["subject"] == "Lunch"

    def test_bare_body_has_no_headers(self):
        assert extract_headers("Just a normal paragraph of text.") == {}

    def test_body_line_that_looks_like_a_header_is_ignored(self):
        """
        Only the leading run of header lines counts. A quoted reply further down
        ("Subject: ..." inside the body) must not be mistaken for the real
        headers, or the sender checks would compare the wrong addresses.
        """
        headers = extract_headers(
            "From: Alice <alice@example.com>\n"
            "\n"
            "Forwarding this on:\n"
            "From: Bob <bob@elsewhere.example>\n"
        )
        assert headers["from"] == "Alice <alice@example.com>"

    def test_split_address_handles_both_forms(self):
        assert split_address("Alice <alice@example.com>") == ("Alice", "alice@example.com")
        assert split_address("alice@example.com") == ("", "alice@example.com")
        assert split_address('"Support Team" <s@example.com>') == ("Support Team", "s@example.com")


class TestSenderConsistency:
    def test_consistent_headers_produce_no_findings(self):
        assert check_sender_headers(
            "From: Alice Smith <alice@example.com>\n"
            "Reply-To: alice@example.com\n"
            "Subject: Notes\n\nHere they are."
        ) == []

    def test_reply_to_on_another_domain_is_flagged(self):
        findings = check_sender_headers(
            "From: Billing <billing@example.com>\n"
            "Reply-To: collector@mail.ru\n"
            "Subject: Invoice\n\nSee attached."
        )
        assert any(key == "reply_to_mismatch" for key, _ in findings)

    def test_display_name_naming_another_brand_is_flagged(self):
        findings = check_sender_headers(
            "From: PayPal Service <service@paypal-secure-billing.tk>\n\nDear Customer,"
        )
        assert any(key == "display_name_brand_mismatch" for key, _ in findings)

    def test_real_brand_domain_is_not_flagged(self):
        findings = check_sender_headers(
            "From: PayPal <service@paypal.com>\n\nYour receipt is ready."
        )
        assert findings == []

    def test_display_name_containing_a_different_address_is_flagged(self):
        findings = check_sender_headers(
            "From: support@bank.example <thief@evil.example>\n\nPlease log in."
        )
        assert any(key == "display_name_address_mismatch" for key, _ in findings)

    def test_organisation_writing_from_free_webmail_is_flagged(self):
        findings = check_sender_headers(
            "From: Customer Support Team <helpdesk.official@gmail.com>\n\nDear User,"
        )
        assert any(key == "organisation_from_free_mail" for key, _ in findings)

    def test_a_person_writing_from_free_webmail_is_not_flagged(self):
        # Using Gmail is not suspicious; claiming to be a company's support desk
        # while using Gmail is.
        assert check_sender_headers("From: Abhiram <abhiram@gmail.com>\n\nHi!") == []

    def test_subdomain_of_the_sending_domain_is_not_a_mismatch(self):
        assert check_sender_headers(
            "From: Alerts <alerts@mail.example.com>\n"
            "Reply-To: support@example.com\n\nHello."
        ) == []


class TestHeadersInAnalysis:
    def test_header_findings_reach_the_score(self):
        analysis = analyze(
            "From: PayPal Service <service@paypal-secure-billing.tk>\n"
            "Reply-To: recovery@mail.ru\n"
            "Subject: Account limited\n\n"
            "Dear Customer, please verify your account."
        )
        assert "sender" in analysis.scored_categories
        assert analysis.risk_level == "Dangerous"

    def test_a_pasted_body_without_headers_is_unaffected(self):
        analysis = analyze("Hi Abhiram, notes attached. See you Friday.")
        assert analysis.findings == []
        assert analysis.score == 0
