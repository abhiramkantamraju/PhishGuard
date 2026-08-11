"""
Turning rule matches into a score and a risk level.

`analyze()` is the single entry point for offline analysis: pure, no I/O, and
therefore usable identically by the web app, the pytest suite and
`evaluate_dataset.py`. The network-backed checks live in `phishguard.network`
and are merged in afterwards by the app.

Scoring model
-------------
Each rule that matches produces a `Finding`. A finding's *category* — not the
individual rule — carries the weight, and each category can contribute its
weight at most once per email. So an email that trips four different
"verify your account" phrasings scores the same 3 points as one that trips a
single phrasing: the score approximates how many *independent* reasons there
are to distrust the message rather than how verbosely the sender repeated one
of them.

The thresholds below are calibrated against the evaluation corpora
(`scripts/calibrate.py`), choosing the boundary that maximised F1 on the
phishing-focused benchmark while keeping the false-positive rate on real
legitimate business mail low. `SUSPICIOUS_THRESHOLD` is greater than 1 on
purpose: it means a single weak signal — an impersonal greeting, one urgent
phrase — is reported to the user but is not by itself enough to call an email
phishing, which is what keeps false positives down on ordinary marketing mail.
"""

import re
from dataclasses import dataclass, field

from .headers import check_sender_headers
from .rules import ATTACHMENT_MENTION_PATTERN, CATEGORIES, TEXT_RULES
from .urls import (
    CREDENTIAL_PATH_PATTERN,
    IP_URL_PATTERN,
    LEGITIMATE_BRAND_DOMAINS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    check_domain_spoofing,
    extract_urls,
    get_hostname,
    get_root_domain,
    get_tld,
    has_userinfo_trick,
)

SUSPICIOUS_THRESHOLD = 3
DANGEROUS_THRESHOLD = 6

SAFE = "Safe"
SUSPICIOUS = "Suspicious"
DANGEROUS = "Dangerous"


@dataclass(frozen=True)
class Finding:
    """One thing PhishGuard noticed, ready to show to the user."""

    rule: str
    category: str
    message: str
    match: str = ""

    @property
    def category_label(self):
        return CATEGORIES[self.category].label

    @property
    def category_weight(self):
        return CATEGORIES[self.category].weight

    @property
    def advice(self):
        return CATEGORIES[self.category].advice


@dataclass
class Analysis:
    """The full result of offline analysis."""

    findings: list = field(default_factory=list)
    score: int = 0

    @property
    def risk_level(self):
        return get_risk_level(self.score)

    @property
    def flags(self):
        """Backwards-compatible flat list of messages."""
        return [finding.message for finding in self.findings]

    @property
    def scored_categories(self):
        """Category keys that contributed to the score, highest weight first."""
        keys = {f.category for f in self.findings if f.category_weight > 0}
        return sorted(keys, key=lambda key: -CATEGORIES[key].weight)

    def grouped(self):
        """
        Findings grouped for display: a list of
        `(Category, [Finding, ...])` ordered by weight, informational last.
        """
        groups = {}
        for finding in self.findings:
            groups.setdefault(finding.category, []).append(finding)
        return [
            (CATEGORIES[key], groups[key])
            for key in sorted(groups, key=lambda key: (-CATEGORIES[key].weight, key))
        ]


def _dedupe(findings):
    """Drop findings that quote a phrase already reported in the same category."""
    kept = []
    seen = set()
    for finding in findings:
        key = (finding.category, finding.match.lower())
        if finding.match and key in seen:
            continue
        seen.add(key)
        kept.append(finding)
    return kept


def _brand_mentioned(text_lower):
    for brand in LEGITIMATE_BRAND_DOMAINS:
        if brand in text_lower:
            return brand
    return None


def _url_findings(email_text, urls):
    """Structural findings about the URLs in an email."""
    findings = []
    seen_messages = set()

    def add(rule, category, message):
        if message not in seen_messages:
            seen_messages.add(message)
            findings.append(Finding(rule, category, message))

    if urls:
        # Informational: nearly every real email contains links, so this
        # carries no risk signal on its own (see README).
        add("has_links", "informational",
            f"Contains {len(urls)} link(s), which should be checked carefully")

    if re.search(IP_URL_PATTERN, email_text):
        add("ip_url", "link_manipulation",
            "Contains a link that uses a raw IP address instead of a normal domain name")

    for url in urls:
        hostname = get_hostname(url)
        root_domain = get_root_domain(hostname)

        if root_domain in SHORTENER_DOMAINS:
            add("shortener", "link_manipulation",
                f"Shortened URL detected: '{url}' uses {root_domain}, "
                "which hides the real destination")

        if has_userinfo_trick(url):
            add("userinfo_trick", "link_manipulation",
                f"The link '{url}' hides its real destination using an '@' — everything "
                "before the '@' is ignored by the browser")

        if get_tld(root_domain) in SUSPICIOUS_TLDS:
            add("suspicious_tld", "link_manipulation",
                f"The link '{url}' uses the '.{get_tld(root_domain)}' domain ending, "
                "which is heavily used for throwaway phishing sites")

        for message in check_domain_spoofing(url):
            add("domain_spoofing", "link_manipulation", message)

    if urls and CREDENTIAL_PATH_PATTERN.search(email_text):
        # Informational: real login pages use these paths too, so on its own
        # this says nothing — it is context for the flags above.
        add("credential_path", "informational",
            "A link points at a login, verification or account page — check the domain "
            "carefully before entering anything")

    if "http://" in email_text.lower():
        # Informational: plenty of legitimate (if dated) sites and mailing-list
        # archives still link over plain http.
        add("insecure_http", "informational", "Contains an insecure HTTP link")

    return findings


def _brand_link_mismatch(text_lower, urls):
    """
    "The text says PayPal, the link goes somewhere else."

    Only raised when the email also asks for credentials or threatens the
    account: a brand name next to an unrelated link is completely ordinary in
    normal correspondence (a news digest linking to coverage of Amazon), so
    requiring the phishing context is what makes this usable — measured on its
    own it produced more false positives than true ones.
    """
    if not urls:
        return None
    brand = _brand_mentioned(text_lower)
    if brand is None:
        return None
    official = LEGITIMATE_BRAND_DOMAINS[brand]
    linked = {get_root_domain(get_hostname(url)) for url in urls}
    if linked & official:
        return None
    return Finding(
        "brand_link_mismatch", "link_manipulation",
        f"The message talks about {brand.title()} but every link points somewhere else "
        f"({', '.join(sorted(linked)[:3])}) — a classic impersonation pattern",
    )


def analyze(email_text):
    """
    Run every offline check over `email_text` and return an `Analysis`.

    Pure: no network, no database, no clock. Deterministic for a given input.
    """
    findings = []
    text_lower = email_text.lower()

    for rule in TEXT_RULES:
        match = rule.find(email_text)
        if match is not None:
            findings.append(Finding(
                rule.key, rule.category, rule.message.format(match=match), match,
            ))

    # Two rules in the same category can quote the same phrase (a phrase list
    # and a broader pattern overlapping). Report it once.
    findings = _dedupe(findings)

    attachment_match = ATTACHMENT_MENTION_PATTERN.search(email_text)
    if attachment_match:
        findings.append(Finding(
            "risky_attachment", "attachment",
            f"Mentions a risky attachment type: '{attachment_match.group(0)}'",
            attachment_match.group(0),
        ))

    for rule_key, message in check_sender_headers(email_text):
        findings.append(Finding(rule_key, "sender", message))

    urls = extract_urls(email_text)
    findings.extend(_url_findings(email_text, urls))

    category_keys = {finding.category for finding in findings}
    if category_keys & {"credentials", "account_threat"}:
        mismatch = _brand_link_mismatch(text_lower, urls)
        if mismatch is not None:
            findings.append(mismatch)

    score = sum(
        CATEGORIES[key].weight
        for key in {finding.category for finding in findings}
    )
    return Analysis(findings=findings, score=score)


def analyze_text(email_text):
    """
    `(flags, score)` for callers that only need the flat list of messages.

    Kept as the module's original signature so `evaluate_dataset.py` and the
    existing tests are unaffected by the structured `analyze()` result.
    """
    analysis = analyze(email_text)
    return analysis.flags, analysis.score


def get_risk_level(score):
    """Bucket a score into Safe / Suspicious / Dangerous."""
    if score < SUSPICIOUS_THRESHOLD:
        return SAFE
    if score < DANGEROUS_THRESHOLD:
        return SUSPICIOUS
    return DANGEROUS
