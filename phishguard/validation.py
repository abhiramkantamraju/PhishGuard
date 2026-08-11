"""
Input validation for the scan workflow.

This lives outside app.py on purpose. The rules below decide whether a
submitted email is allowed to reach the detection engine at all, which makes
them part of the must-have "paste an email and get a risk score" workflow
(user story US1) rather than presentation logic. Keeping them in a plain
function with no Flask imports means they can be tested directly, without a
request context, a test client, or a running server — the same reason
detector.analyze_text() is kept pure.

app.py imports validate_email_input() and renders whatever error message it
returns; it no longer decides what counts as valid input itself.
"""

# Chosen to bound what a single request can write to the database and to keep
# the history page renderable. Real phishing emails are far shorter than this.
MAX_EMAIL_LENGTH = 20000

EMPTY_INPUT_MESSAGE = "Please paste an email message before checking it."


def too_long_message(max_length=MAX_EMAIL_LENGTH):
    """The message shown when a submission exceeds the length cap."""
    return f"Email text is too long (max {max_length} characters)."


def validate_email_input(email_text, max_length=MAX_EMAIL_LENGTH):
    """
    Validates raw email text submitted to the scan form.

    Returns a (cleaned_text, error) tuple:
      - cleaned_text is the input with surrounding whitespace stripped, and is
        what should be analyzed and stored when the input is valid.
      - error is None when the input is acceptable, otherwise a plain-English
        message suitable for display to the user.

    Rejects three cases:
      1. Nothing submitted at all (None, e.g. a missing form field).
      2. Empty or whitespace-only input, which would otherwise be scored as
         "Safe" and saved as a meaningless empty history row.
      3. Input longer than max_length, measured after stripping.

    The caller is expected to stop and show `error` when it is not None, so no
    analysis is run and nothing is written to the database for invalid input.
    """
    if email_text is None:
        return "", EMPTY_INPUT_MESSAGE

    cleaned = email_text.strip()

    if not cleaned:
        return "", EMPTY_INPUT_MESSAGE

    if len(cleaned) > max_length:
        return cleaned, too_long_message(max_length)

    return cleaned, None
