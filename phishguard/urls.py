"""
URL and domain inspection.

Everything here is pure, offline string analysis: no DNS, no HTTP, no WHOIS.
That is deliberate — these checks run on every scan and inside the dataset
evaluation harness, so they must be fast and deterministic. The network-backed
counterparts live in `phishguard.network`.
"""

import re
from urllib.parse import urlparse

# Trailing `)`, `'` and `,` are excluded so that a URL written inside prose or
# parentheses ("see (http://example.com/a)") doesn't absorb the punctuation.
URL_PATTERN = r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+"
IP_URL_PATTERN = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
    "bit.do", "soo.gd", "t.ly", "lnkd.in",
}

# TLDs with a persistently high share of abuse relative to legitimate use
# (free-registration and novelty TLDs). Deliberately excludes the large
# generic TLDs (.com/.net/.org/.info/.biz) and country codes in ordinary
# commercial use, which would generate constant false positives.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "zip", "mov", "country", "kim", "science", "party", "gdn", "review",
    "loan", "men", "stream", "bid", "date", "quest", "cam", "rest", "sbs",
}

# Brand -> the domains that brand actually sends mail from. Used both to
# suppress false positives on real brand domains and to detect the classic
# "text says PayPal, link goes somewhere else" pattern.
LEGITIMATE_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "ebay": {"ebay.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com",
                  "office365.com", "msn.com", "sharepoint.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "barclays": {"barclays.com", "barclays.co.uk"},
    "santander": {"santander.com", "santander.co.uk"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

# Path/query fragments that indicate a page asking for credentials. On their
# own these are unremarkable (real login pages use them too); they matter in
# combination with the other signals, so the weight assigned in
# `phishguard.rules` is intentionally low.
CREDENTIAL_PATH_PATTERN = re.compile(
    r"https?://[^\s<>\"']*?/[^\s<>\"']*?"
    r"(?:login|log-?in|signin|sign-?in|verify|verification|secure|account"
    r"|update|confirm|webscr|password|passwd|auth|billing|unlock|recover"
    r"|validate|session)",
    re.IGNORECASE,
)

# Digits and punctuation that stand in for Latin letters ("paypa1", "g00gle").
LOOKALIKE_TRANSLATIONS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a", "8": "b",
})

# Characters from non-Latin scripts that are visually near-identical to Latin
# letters (a "homograph" attack) — e.g. Cyrillic 'а' (U+0430) vs Latin 'a'
# (U+0061). Not exhaustive, but covers the characters attackers reach for
# first because between them they cover the whole Latin alphabet.
CONFUSABLE_CHARS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "һ": "h", "ԁ": "d", "ѡ": "w", "ј": "j", "ᴠ": "v",
    "ⅰ": "i", "ⅼ": "l", "ь": "b", "м": "m", "т": "t", "к": "k", "п": "n",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "υ": "u", "κ": "k", "ѵ": "v",
    "ε": "e", "ι": "i", "τ": "t", "ϲ": "c",
}


def extract_urls(email_text):
    """Every http(s):// or www. URL in the text, in order of appearance."""
    return re.findall(URL_PATTERN, email_text, flags=re.IGNORECASE)


def get_hostname(url):
    """
    Hostname of a URL, lowercased, with a leading `www.` removed.

    Never raises. `urlparse` throws `ValueError` on inputs it considers
    malformed IPv6 (anything with an unbalanced `[`), and real pasted email
    contains plenty of mangled URLs — a wrapped line, a stray bracket from
    a quoted reply. Analysis must degrade to "no hostname" rather than 500,
    so the authority section is recovered by hand in that case.
    """
    candidate = url if url.startswith(("http://", "https://")) else f"http://{url}"
    try:
        hostname = urlparse(candidate).netloc.lower()
    except ValueError:
        authority = re.split(r"[/?#]", candidate[len("http://"):], maxsplit=1)[0]
        hostname = authority.lower()
    # Strip any userinfo ("user@host") and port so callers compare hostnames.
    if "@" in hostname:
        hostname = hostname.rsplit("@", 1)[1]
    hostname = hostname.split(":", 1)[0]
    return hostname[4:] if hostname.startswith("www.") else hostname


def get_root_domain(hostname):
    """
    Last two labels of a hostname ("mail.google.com" -> "google.com").

    A deliberate simplification: it treats "example.co.uk" as "co.uk". Using a
    real public-suffix list would need a third-party dependency and a bundled
    data file, which is more machinery than this project needs — the practical
    effect is limited to slightly coarser matching on multi-part country TLDs.
    """
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def get_tld(hostname):
    return hostname.rsplit(".", 1)[-1] if "." in hostname else ""


def normalize_lookalikes(value):
    return value.translate(LOOKALIKE_TRANSLATIONS)


def normalize_confusables(value):
    return "".join(CONFUSABLE_CHARS.get(char, char) for char in value)


def is_punycode(hostname):
    return any(label.startswith("xn--") for label in hostname.split("."))


def has_confusable_characters(value):
    return any(char in CONFUSABLE_CHARS for char in value)


def levenshtein_distance(left, right):
    """Edit distance, iterative two-row implementation (no dependencies)."""
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
    return get_root_domain(hostname) in LEGITIMATE_BRAND_DOMAINS[brand]


def has_userinfo_trick(url):
    """
    True for URLs that put text before an `@` in the authority section, e.g.
    `http://www.paypal.com@203.0.113.4/login` — browsers navigate to the host
    after the `@`, but a reader sees the trusted name before it.
    """
    without_scheme = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    authority = re.split(r"[/?#]", without_scheme, maxsplit=1)[0]
    return "@" in authority


def check_domain_spoofing(url):
    """
    Ways a hostname can be dressed up to look like a brand it isn't:
    punycode encoding, non-Latin lookalike characters, the brand name buried
    in an unrelated domain, and one-character typo-squats.
    """
    hostname = get_hostname(url)
    root_domain = get_root_domain(hostname)
    domain_name = root_domain.split(".")[0]
    normalized_domain_name = normalize_lookalikes(normalize_confusables(domain_name))
    flags = []

    if is_punycode(hostname):
        flags.append(
            f"Domain '{hostname}' uses punycode (internationalized domain encoding), "
            "which can be used to visually spoof a trusted domain"
        )

    if has_confusable_characters(domain_name):
        flags.append(
            f"Domain '{root_domain}' contains non-Latin characters that closely resemble "
            "Latin letters (e.g. Cyrillic 'а' instead of 'a'), a homograph technique used "
            "to impersonate trusted domains"
        )

    for brand in LEGITIMATE_BRAND_DOMAINS:
        if is_legitimate_brand_domain(hostname, brand):
            continue

        if brand in hostname:
            flags.append(
                f"Possible brand impersonation: '{hostname}' mentions {brand.title()} "
                f"but is not an official {brand.title()} domain"
            )
            continue

        if normalized_domain_name == brand:
            flags.append(
                f"Possible misspelled domain: '{root_domain}' looks like {brand.title()} "
                "but is not the official domain"
            )
            continue

        if len(brand) >= 5 and levenshtein_distance(normalized_domain_name, brand) == 1:
            flags.append(
                f"Possible typo-squatting: '{root_domain}' is very similar to "
                f"{brand.title()}'s official domain"
            )

    return flags
