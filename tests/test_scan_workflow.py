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

import re
import sqlite3

import pytest

import app as app_module
from detector import analyze_text, get_risk_level
from validation import (
    EMPTY_INPUT_MESSAGE,
    MAX_EMAIL_LENGTH,
    validate_email_input,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    A Flask test client backed by a throwaway database.

    DATABASE is redirected into pytest's tmp_path so these tests never read or
    write the real phishguard.db. CSRF and rate limiting are disabled because
    neither is what these tests are checking — they are covered separately in
    test_app.py.
    """
    db_path = tmp_path / "test_phishguard.db"
    monkeypatch.setattr(app_module, "DATABASE", str(db_path))
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.app.config["RATELIMIT_ENABLED"] = False
    with app_module.app.test_client() as test_client:
        yield test_client, str(db_path)


def submit_scan(client, email_text):
    """Posts the scan form the same way the browser does."""
    page = client.get("/")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post("/", data={"email_text": email_text, "csrf_token": token})


def rows_in_scans(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM scans").fetchall()
    finally:
        conn.close()


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


# --- Saving the record: the Create half of the workflow ----------------------
#
# The two tests above prove the verdict is correct and that bad input is
# refused. These two prove the workflow actually persists what it decided —
# a scan the user cannot find again in their history has not really been saved.


def test_valid_scan_is_saved_with_its_verdict(client):
    """
    Valid behaviour, end to end: submitting an email through the form must
    write exactly one row holding the email itself and the verdict that was
    calculated from it.

    Asserting the stored score and risk_level matter more than asserting the
    row count. If the analysis and the insert ever drifted apart, history
    would show a verdict that the detector never actually produced.
    """
    test_client, db_path = client
    email = (
        "URGENT: your account has been suspended. "
        "Verify your password now at http://192.168.10.44/login"
    )

    response = submit_scan(test_client, email)
    assert response.status_code == 200

    rows = rows_in_scans(db_path)
    assert len(rows) == 1

    saved = rows[0]
    expected_flags, expected_score = analyze_text(email)

    assert saved["email_text"] == email
    assert saved["score"] == expected_score
    assert saved["risk_level"] == get_risk_level(expected_score) == "Dangerous"
    # Flags are stored newline-joined, so the saved reasoning must round-trip.
    assert saved["flags"].split("\n") == expected_flags
    # Defaults the history and network-check features rely on.
    assert saved["note"] == ""
    assert saved["network_checked"] == 0
    assert saved["created_at"]


def test_rejected_scan_is_not_saved(client):
    """
    Failure case, end to end: an empty submission must be turned away with a
    message and must leave the database untouched.

    This is the half a unit test cannot prove. validate_email_input() returning
    an error only matters if the route actually stops on it — without that, the
    user would be shown an error while a junk row was quietly saved anyway.
    """
    test_client, db_path = client

    response = submit_scan(test_client, "   ")

    assert response.status_code == 200
    assert "Please paste an email message" in response.text
    assert rows_in_scans(db_path) == []


def test_each_valid_scan_is_saved_as_its_own_record(client):
    """
    Two different emails must produce two separate rows with their own
    verdicts, not one row overwritten twice. This is what makes the history
    list (and therefore the Read, Update and Delete operations) meaningful.
    """
    test_client, db_path = client

    submit_scan(test_client, "Hi, are we still on for lunch tomorrow?")
    submit_scan(test_client, "Confirm your bank account details immediately to avoid suspension.")

    rows = rows_in_scans(db_path)

    assert len(rows) == 2
    assert len({row["id"] for row in rows}) == 2
    assert rows[0]["risk_level"] == "Safe"
    assert rows[1]["risk_level"] in {"Suspicious", "Dangerous"}
