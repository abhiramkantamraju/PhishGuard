"""
Integrity of the rule registry itself.

These are cheap structural guards rather than detection tests: they catch the
mistakes that are easy to make when adding a rule (a typo'd category, a
duplicate key, a message template that forgets `{match}`) and that would
otherwise surface as a confusing KeyError at scan time.
"""

import re

import pytest

from phishguard import CATEGORIES, TEXT_RULES


def test_every_rule_points_at_a_real_category():
    unknown = {rule.key: rule.category for rule in TEXT_RULES if rule.category not in CATEGORIES}
    assert unknown == {}


def test_rule_keys_are_unique():
    keys = [rule.key for rule in TEXT_RULES]
    duplicates = {key for key in keys if keys.count(key) > 1}
    assert duplicates == set()


@pytest.mark.parametrize("rule", TEXT_RULES, ids=lambda rule: rule.key)
def test_rule_is_well_formed(rule):
    assert isinstance(rule.pattern, re.Pattern)
    assert rule.pattern.flags & re.IGNORECASE, "rules must match case-insensitively"
    assert "{match}" in rule.message, "the message must quote what actually matched"
    assert rule.message.strip() == rule.message


def test_informational_category_is_the_only_unscored_one():
    unscored = {key for key, category in CATEGORIES.items() if category.weight == 0}
    assert unscored == {"informational"}


def test_scoring_categories_carry_advice():
    """
    Every category that moves the score is shown to the user with a sentence of
    advice on the result page, so an empty one would render a blank block.
    """
    missing = [
        key for key, category in CATEGORIES.items()
        if category.weight > 0 and not category.advice.strip()
    ]
    assert missing == []


def test_no_rule_fires_on_ordinary_correspondence():
    """
    A canary for over-broad patterns. None of these should match anything: they
    are the kinds of sentence that made earlier keyword lists unusable
    ("no action required" matching "action required", "effective immediately"
    matching "immediately").
    """
    ordinary = [
        "Hi Abhiram, thanks for the notes — see you Friday.",
        "Important notice: the office is closed for the holidays. No action required.",
        "This change is effective immediately; nothing to do on your side.",
        "Your order has been delivered. Thank you for shopping with us.",
        "Meeting scheduled for tomorrow at 10am in room 4.",
        "Please find attached the monthly report.",
        "Manage your plan or update payment details anytime from your account settings.",
    ]
    for text in ordinary:
        fired = [rule.key for rule in TEXT_RULES if rule.find(text)]
        assert fired == [], f"{fired} should not fire on: {text!r}"
