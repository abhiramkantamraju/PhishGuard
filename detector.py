import re
from urllib.parse import urlparse

# --- Phishing keywords that trigger red flags ---
URGENT_KEYWORDS = [
    "act now", "urgent", "immediately", "your account will be closed",
    "verify your account", "confirm your details", "click here now",
    "limited time", "expires soon", "action required", "important notice"
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
