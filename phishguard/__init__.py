"""
PhishGuard — rule-based phishing analysis for pasted emails.

Import everything from this package rather than from the submodules; the layout
below is the intended reading order.

    validation  — is this input even analysable?
    rules       — what we look for, and what each finding is worth
    urls        — URL/domain inspection (offline)
    headers     — sender-header consistency (offline)
    scoring     — combine matches into findings, a score and a risk level
    network     — Safe Browsing + WHOIS (the only module that touches the network)
"""

from .headers import check_sender_headers, extract_headers
from .network import (
    analyze_urls_network,
    check_domain_age,
    check_safe_browsing,
    network_findings,
)
from .rules import CATEGORIES, TEXT_RULES
from .scoring import (
    DANGEROUS,
    DANGEROUS_THRESHOLD,
    SAFE,
    SUSPICIOUS,
    SUSPICIOUS_THRESHOLD,
    Analysis,
    Finding,
    analyze,
    analyze_text,
    get_risk_level,
)
from .urls import (
    check_domain_spoofing,
    extract_urls,
    get_hostname,
    get_root_domain,
    levenshtein_distance,
)
from .validation import MAX_EMAIL_LENGTH, validate_email_input

__version__ = "2.0.0"

__all__ = [
    "Analysis",
    "CATEGORIES",
    "DANGEROUS",
    "DANGEROUS_THRESHOLD",
    "Finding",
    "MAX_EMAIL_LENGTH",
    "SAFE",
    "SUSPICIOUS",
    "SUSPICIOUS_THRESHOLD",
    "TEXT_RULES",
    "analyze",
    "analyze_text",
    "analyze_urls_network",
    "check_domain_age",
    "check_domain_spoofing",
    "check_safe_browsing",
    "check_sender_headers",
    "extract_headers",
    "extract_urls",
    "get_hostname",
    "get_risk_level",
    "get_root_domain",
    "levenshtein_distance",
    "network_findings",
    "validate_email_input",
]
