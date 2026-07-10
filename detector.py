import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import requests

# --- Phishing keywords that trigger red flags ---
URGENT_KEYWORDS = [
    "act now", "urgent", "immediately", "your account will be closed",
    "verify your account", "confirm your details", "click here now",
    "limited time", "expires soon", "action required", "important notice",
    "password expires", "your password will expire", "account will expire",
    "expires today"
]

PRIZE_SCAM_KEYWORDS = [
    "you have won", "you've won", "you have been awarded", "claim your prize",
    "claim your winnings", "lottery winner", "winning notification",
    "claim your reward"
]

PERSONAL_INFO_KEYWORDS = [
    "enter your password", "confirm your password", "enter your credit card",
    "bank account details", "social security", "date of birth",
    "enter your pin", "verify your identity", "verify your account",
    "confirm your details", "login details", "account password"
]

THREAT_KEYWORDS = [
    "your account has been suspended", "unusual activity detected",
    "unauthorized access", "your account will be terminated",
    "failure to respond", "legal action", "you have been selected"
]

URL_PATTERN = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"
IP_URL_PATTERN = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
]

LEGITIMATE_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
}


def extract_urls(email_text):
    return re.findall(URL_PATTERN, email_text, flags=re.IGNORECASE)


def get_hostname(url):
    parsed_url = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
    hostname = parsed_url.netloc.lower()
    return hostname[4:] if hostname.startswith("www.") else hostname


def get_root_domain(hostname):
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def normalize_lookalikes(value):
    replacements = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
    })
    return value.translate(replacements)


def levenshtein_distance(left, right):
    if left == right:
        return 0

    previous_row = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current_row = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current_row[right_index - 1] + 1
            delete_cost = previous_row[right_index] + 1
            replace_cost = previous_row[right_index - 1] + (left_char != right_char)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row

    return previous_row[-1]


def is_legitimate_brand_domain(hostname, brand):
    root_domain = get_root_domain(hostname)
    return root_domain in LEGITIMATE_BRAND_DOMAINS[brand]


def check_domain_spoofing(url):
    hostname = get_hostname(url)
    root_domain = get_root_domain(hostname)
    domain_name = root_domain.split(".")[0]
    normalized_domain_name = normalize_lookalikes(domain_name)
    flags = []

    for brand in LEGITIMATE_BRAND_DOMAINS:
        if is_legitimate_brand_domain(hostname, brand):
            continue

        if brand in hostname:
            flags.append(
                f"Possible brand impersonation: '{hostname}' mentions {brand.title()} but is not an official {brand.title()} domain"
            )
            continue

        if normalized_domain_name == brand:
            flags.append(
                f"Possible misspelled domain: '{root_domain}' looks like {brand.title()} but is not the official domain"
            )
            continue

        if len(brand) >= 5 and levenshtein_distance(normalized_domain_name, brand) == 1:
            flags.append(
                f"Possible typo-squatting: '{root_domain}' is very similar to {brand.title()}'s official domain"
            )

    return flags

def analyze_text(email_text):
    """
    Analyzes email text for phishing keywords.
    Returns a list of flags and a risk score.
    """
    flags = []
    score = 0
    text = email_text.lower()

    # Check urgent keywords.
    for keyword in URGENT_KEYWORDS:
        if keyword in text:
            flags.append(f"Urgent language detected: '{keyword}'")
            score += 2
            break

    # Check personal information requests.
    for keyword in PERSONAL_INFO_KEYWORDS:
        if keyword in text:
            flags.append(f"Requests personal information: '{keyword}'")
            score += 3
            break

    # Check threatening language.
    for keyword in THREAT_KEYWORDS:
        if keyword in text:
            flags.append(f"Threatening language detected: '{keyword}'")
            score += 2
            break

    # Check prize/lottery scam language.
    for keyword in PRIZE_SCAM_KEYWORDS:
        if keyword in text:
            flags.append(f"Prize/lottery scam language detected: '{keyword}'")
            score += 3
            break

    urls = extract_urls(email_text)
    if urls:
        flags.append(f"Contains {len(urls)} link(s), which should be checked carefully")
        score += 1

    if re.search(IP_URL_PATTERN, email_text):
        flags.append("Contains a link that uses an IP address instead of a normal domain")
        score += 3

    for url in urls:
        hostname = get_hostname(url)

        if hostname in SHORTENER_DOMAINS:
            flags.append(f"Shortened URL detected: '{url}' uses {hostname}, which can hide the real destination")
            score += 2

        domain_flags = check_domain_spoofing(url)
        for domain_flag in domain_flags:
            flags.append(domain_flag)
            score += 3

    if "http://" in text:
        flags.append("Contains an insecure HTTP link")
        score += 1

    return flags, score


def get_risk_level(score):
    """
    Converts a numeric score into a risk label.
    """
    if score == 0:
        return "Safe"
    elif score <= 4:
        return "Suspicious"
    else:
        return "Dangerous"


# --- Network-based URL checks (Google Safe Browsing + WHOIS domain age) ---
#
# These make outbound HTTP/WHOIS calls, so they are kept out of analyze_text()
# on purpose: evaluate_dataset.py and the pytest suite must stay fast, offline,
# and deterministic. app.py calls analyze_urls_network() separately for live
# scans only. Every failure mode (missing API key, network error, WHOIS
# lookup failure) is swallowed and treated as "no signal" rather than raised,
# so a live scan still works if Safe Browsing/WHOIS are unreachable.

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_TIMEOUT_SECONDS = 5
WHOIS_TIMEOUT_SECONDS = 5
NEW_DOMAIN_THRESHOLD_DAYS = 30
MAX_DOMAINS_CHECKED = 3


def check_safe_browsing(urls, api_key, http_post=requests.post):
    """Flags URLs that Google Safe Browsing lists as malware/phishing/unwanted software."""
    if not api_key or not urls:
        return []

    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
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

    # python-whois doesn't reliably honor socket timeouts (some lookups shell
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
    Runs the network-based URL checks (Safe Browsing + WHOIS domain age) and
    returns (flags, score) to be merged into a prior analyze_text() result.
    Best-effort: designed to degrade to (empty, 0) rather than raise.
    """
    flags = []
    score = 0

    for flag in check_safe_browsing(urls, api_key, http_post=http_post):
        flags.append(flag)
        score += 5

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
            score += 2

    return flags, score
