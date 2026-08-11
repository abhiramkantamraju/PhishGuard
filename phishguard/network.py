"""
Network-backed URL checks: Google Safe Browsing and WHOIS domain age.

Kept strictly separate from `phishguard.scoring` because these make outbound
calls: the pytest suite and `evaluate_dataset.py` must stay fast, offline and
deterministic, so they never reach this module (its own tests inject fakes).

Every failure mode here — missing API key, connection error, WHOIS timeout,
malformed response — is swallowed and reported as "no signal" rather than
raised. A scan must still succeed when Safe Browsing or WHOIS is unreachable.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

from .scoring import Finding
from .urls import extract_urls, get_hostname, get_root_domain

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_TIMEOUT_SECONDS = 5
WHOIS_TIMEOUT_SECONDS = 5
NEW_DOMAIN_THRESHOLD_DAYS = 30
MAX_DOMAINS_CHECKED = 3

SAFE_BROWSING_WEIGHT = 5
NEW_DOMAIN_WEIGHT = 2


def check_safe_browsing(urls, api_key, http_post=requests.post):
    """Flags URLs Google Safe Browsing lists as malware/phishing/unwanted software."""
    if not api_key or not urls:
        return []

    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }

    try:
        response = http_post(
            SAFE_BROWSING_API_URL,
            params={"key": api_key},
            json=body,
            timeout=SAFE_BROWSING_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
    except (requests.RequestException, ValueError):
        return []

    flags = []
    seen = set()
    for match in matches:
        url = match.get("threat", {}).get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        threat_type = match.get("threatType", "threat").lower().replace("_", " ")
        flags.append(f"Google Safe Browsing flagged '{url}' as a known {threat_type} site")

    return flags


def check_domain_age(hostname, whois_lookup=None):
    """Flags domains registered very recently, a common phishing indicator."""
    if whois_lookup is None:
        import whois as whois_module

        whois_lookup = whois_module.whois

    # python-whois doesn't reliably honour socket timeouts (some lookups shell
    # out to a system `whois` binary), so run it on a worker thread and stop
    # waiting after WHOIS_TIMEOUT_SECONDS rather than blocking the request.
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(whois_lookup, hostname)
        record = future.result(timeout=WHOIS_TIMEOUT_SECONDS)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return []
        age_days = (datetime.now() - creation_date).days
    except Exception:
        return []
    finally:
        executor.shutdown(wait=False)

    if age_days < NEW_DOMAIN_THRESHOLD_DAYS:
        return [
            f"Domain '{hostname}' was registered only {age_days} day(s) ago, "
            "which is common for phishing sites"
        ]
    return []


def analyze_urls_network(urls, api_key=None, http_post=requests.post, whois_lookup=None):
    """
    `(flags, score)` from the network checks, to be merged into a prior
    `analyze()` result. Best-effort: degrades to `([], 0)` rather than raising.
    """
    flags = []
    score = 0

    for flag in check_safe_browsing(urls, api_key, http_post=http_post):
        flags.append(flag)
        score += SAFE_BROWSING_WEIGHT

    checked_domains = set()
    for url in urls:
        if len(checked_domains) >= MAX_DOMAINS_CHECKED:
            break
        root_domain = get_root_domain(get_hostname(url))
        if root_domain in checked_domains:
            continue
        checked_domains.add(root_domain)

        for flag in check_domain_age(root_domain, whois_lookup=whois_lookup):
            flags.append(flag)
            score += NEW_DOMAIN_WEIGHT

    return flags, score


def network_findings(urls, api_key=None, http_post=requests.post, whois_lookup=None):
    """
    The same checks as `analyze_urls_network`, returned as `Finding` objects so
    the web app can render them in the same grouped layout as offline findings.
    """
    findings = []
    score = 0

    for flag in check_safe_browsing(urls, api_key, http_post=http_post):
        findings.append(Finding("safe_browsing", "link_manipulation", flag))
        score += SAFE_BROWSING_WEIGHT

    checked_domains = set()
    for url in urls:
        if len(checked_domains) >= MAX_DOMAINS_CHECKED:
            break
        root_domain = get_root_domain(get_hostname(url))
        if root_domain in checked_domains:
            continue
        checked_domains.add(root_domain)
        for flag in check_domain_age(root_domain, whois_lookup=whois_lookup):
            findings.append(Finding("new_domain", "link_manipulation", flag))
            score += NEW_DOMAIN_WEIGHT

    return findings, score


__all__ = [
    "analyze_urls_network",
    "check_domain_age",
    "check_safe_browsing",
    "extract_urls",
    "network_findings",
]
