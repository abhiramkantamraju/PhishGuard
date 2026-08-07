"""
Automated tests for PhishGuard's must-have workflow: a user pastes an email
and gets back a risk verdict (user story US1).

Two things have to hold for that workflow to be trustworthy:

  1. Valid input produces the correct verdict. A benign email must come back
     Safe with nothing flagged, and an obvious phishing email must come back
     Dangerous with the specific reasons listed. If either direction breaks,
     the whole product claim breaks.

  2. Invalid input is rejected safely. Empty, whitespace-only, missing or
     oversized submissions must be turned away with a clear message, never
     analyzed, and never written to the database as a junk row.

These tests call the logic directly rather than driving the web page, so they
say nothing about layout or styling — only about behaviour.
"""

import pytest

from detector import analyze_text, get_risk_level
from validation import (
    EMPTY_INPUT_MESSAGE,
    MAX_EMAIL_LENGTH,
    validate_email_input,
)


# --- Test 1: valid behaviour -------------------------------------------------


def test_valid_phishing_email_is_scored_and_explained():
    """
    A realistic phishing email should pass validation, score above the
    Dangerous threshold, and explain itself.

    The sample below deliberately combines three independent signals that a
    real credential-phishing email uses together: urgency, a request for
    account credentials, and a link whose host is a raw IP address rather
    than a domain. Each contributes to the score, so the total must land in
    the Dangerous band (5 or above).
    """
    email = (
        "URGENT: your account has been suspended. "
        "Verify your password now at http://192.168.10.44/login "
        "or your access will be permanently terminated."
    )

    cleaned, error = validate_email_input(email)
    assert error is None, "a normal phishing email must not be rejected as invalid"
    assert cleaned == email

    flags, score = analyze_text(cleaned)

    assert get_risk_level(score) == "Dangerous"
    assert score >= 5
    # The verdict must come with reasons, not just a number.
    assert len(flags) >= 2
    assert all(isinstance(flag, str) and flag.strip() for flag in flags)


def test_valid_benign_email_is_scored_safe_with_no_flags():
    """
    The opposite direction of the same workflow, and the one that matters most
    for real use: ordinary correspondence must not be flagged. A tool that
    calls everything dangerous is as useless as one that calls nothing
    dangerous.
    """
    email = (
        "Hi Abhiram, thanks for sending the notes from Tuesday's session. "
        "I've added them to the shared folder. See you at the seminar on Friday."
    )

    cleaned, error = validate_email_input(email)
    assert error is None

    flags, score = analyze_text(cleaned)

    assert score == 0
    assert flags == []
    assert get_risk_level(score) == "Safe"


def test_surrounding_whitespace_is_stripped_before_analysis():
    """
    Pasting from a mail client usually drags along leading and trailing
    whitespace. That must be cleaned off, and must not change the verdict.
    """
    email = "Please confirm your bank account details to avoid suspension."

    cleaned, error = validate_email_input(f"\n\n  {email}  \t\n")

    assert error is None
    assert cleaned == email
    assert analyze_text(cleaned) == analyze_text(email)


# --- Test 2: invalid input and failure cases ---------------------------------


@pytest.mark.parametrize(
    "submitted",
    [
        "",  # user clicked Check with an empty box
        "   ",  # only spaces
        "\n\n\t  \n",  # only newlines and tabs
        None,  # the form field was missing entirely
    ],
    ids=["empty-string", "spaces-only", "whitespace-only", "missing-field"],
)
def test_empty_submissions_are_rejected(submitted):
    """
    Every way of submitting "nothing" must be rejected with the same clear
    message.

    This matters beyond tidiness: without the check, empty text scores 0,
    which get_risk_level() reports as "Safe". The user would be told an email
    they never pasted is safe, and a meaningless empty row would be saved to
    their history.
    """
    cleaned, error = validate_email_input(submitted)

    assert error == EMPTY_INPUT_MESSAGE
    assert cleaned == ""


def test_oversized_input_is_rejected_with_the_limit_stated():
    """
    Input past the length cap must be refused, and the message must tell the
    user what the limit actually is instead of failing vaguely.
    """
    too_long = "a" * (MAX_EMAIL_LENGTH + 1)

    _, error = validate_email_input(too_long)

    assert error is not None
    assert str(MAX_EMAIL_LENGTH) in error


def test_input_exactly_at_the_limit_is_accepted():
    """
    Guards the boundary itself: the cap is inclusive, so an email of exactly
    MAX_EMAIL_LENGTH characters is valid. An off-by-one here would reject
    legitimate input, which is the more damaging direction of the two.
    """
    at_limit = "a" * MAX_EMAIL_LENGTH

    cleaned, error = validate_email_input(at_limit)

    assert error is None
    assert len(cleaned) == MAX_EMAIL_LENGTH


def test_length_is_measured_after_stripping_whitespace():
    """
    A submission that is only over the limit because of padding is genuinely
    within it. Measuring before stripping would reject a valid email.
    """
    padded = "   " + ("a" * MAX_EMAIL_LENGTH) + "   "

    cleaned, error = validate_email_input(padded)

    assert error is None
    assert len(cleaned) == MAX_EMAIL_LENGTH


def test_rejected_input_is_never_analyzed_or_stored():
    """
    The contract the route depends on: when validate_email_input() returns an
    error, the caller stops. This asserts the two-part signal that makes that
    safe to rely on — an error is present and the cleaned text is empty, so
    there is nothing to analyze and nothing to insert.
    """
    for bad_input in ["", "   ", None]:
        cleaned, error = validate_email_input(bad_input)

        assert error is not None
        assert cleaned == ""
        # Nothing meaningful could be scored from it even if it were analyzed.
        assert analyze_text(cleaned) == ([], 0)
