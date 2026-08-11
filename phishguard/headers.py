"""
Sender-header inspection for pasted emails.

When someone pastes a whole email — headers included — the headers carry the
strongest single signal available offline: a mismatch between the name the
reader sees, the domain that actually sent the message, and the address a reply
would go to. Forged mail routinely disagrees with itself here, and genuine mail
almost never does.

These checks only run when header lines are actually present, so pasting a bare
body behaves exactly as before. Note that the evaluation corpora in
`data/` are subject+body only, which means these rules cannot inflate the
benchmark numbers in the README — they are a live-app improvement, measured
instead by the unit tests in `tests/test_headers.py`.
"""

import re

from .urls import LEGITIMATE_BRAND_DOMAINS, get_root_domain

HEADER_PATTERN = re.compile(
    r"^\s*(from|reply-to|return-path|sender|to|cc|subject|date)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
ADDRESS_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
    "aol.com", "live.com", "msn.com", "yandex.com", "mail.com", "gmx.com",
    "protonmail.com", "proton.me", "rediffmail.com", "zoho.com", "inbox.com",
    "consultant.com", "engineer.com", "accountant.com", "post.com",
}

# Words that mean "this is an organisation writing to you", used to decide
# whether a free-webmail sending address is incongruous.
ORGANISATION_WORDS = (
    "support", "service", "services", "team", "security", "billing", "admin",
    "administrator", "helpdesk", "help desk", "notification", "notifications",
    "no-reply", "noreply", "customer care", "customer service", "account",
    "accounts", "bank", "department", "office", "official",
)


def extract_headers(email_text):
    """
    Header name -> value for the header block at the top of a pasted email.

    Only the leading run of header-looking lines is considered: a body line
    that happens to read like "Subject: ..." further down shouldn't be treated
    as a header. Returns an empty dict when the text has no header block.
    """
    headers = {}
    for line in email_text.splitlines():
        if not line.strip():
            if headers:
                break  # blank line ends the header block
            continue
        match = HEADER_PATTERN.match(line)
        if match:
            headers.setdefault(match.group(1).lower(), match.group(2).strip())
        elif headers:
            break
        else:
            break
    return headers


def split_address(value):
    """
    ("display name", "address") for a header value.

    Handles both `Name <user@example.com>` and a bare `user@example.com`.
    """
    if not value:
        return "", ""
    match = re.match(r"^(.*?)<([^>]*)>\s*$", value.strip())
    if match:
        display = match.group(1).strip().strip('"').strip()
        address = match.group(2).strip()
    else:
        display, address = "", value.strip()
    found = ADDRESS_PATTERN.search(address)
    return display, (found.group(0).lower() if found else "")


def address_domain(address):
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def check_sender_headers(email_text):
    """
    Findings about the sender headers, as `(rule_key, message)` pairs.

    Empty when there is no header block, or when the headers are consistent.
    """
    headers = extract_headers(email_text)
    if not headers or "from" not in headers:
        return []

    findings = []
    from_display, from_address = split_address(headers.get("from", ""))
    from_domain = get_root_domain(address_domain(from_address))
    display_lower = from_display.lower()

    # 1. The display name contains a whole different email address or domain
    #    than the address actually sending the message.
    display_address = ADDRESS_PATTERN.search(from_display)
    if display_address and from_domain:
        shown_domain = get_root_domain(address_domain(display_address.group(0)))
        if shown_domain and shown_domain != from_domain:
            findings.append((
                "display_name_address_mismatch",
                f"The sender's display name shows '{display_address.group(0)}' but the "
                f"message was actually sent from '{from_address}'",
            ))

    # 2. The display name names a brand the sending domain does not belong to.
    if from_domain:
        for brand, official_domains in LEGITIMATE_BRAND_DOMAINS.items():
            if brand in display_lower.replace(" ", "") and from_domain not in official_domains:
                findings.append((
                    "display_name_brand_mismatch",
                    f"The sender's name claims to be {brand.title()}, but the message was "
                    f"sent from '{from_domain}', which is not an official "
                    f"{brand.title()} domain",
                ))
                break

    # 3. A reply would go somewhere other than the apparent sender.
    for header_name, label in (("reply-to", "Reply-To"), ("return-path", "Return-Path")):
        _, other_address = split_address(headers.get(header_name, ""))
        other_domain = get_root_domain(address_domain(other_address))
        if other_domain and from_domain and other_domain != from_domain:
            findings.append((
                f"{header_name.replace('-', '_')}_mismatch",
                f"The {label} address '{other_address}' is on a different domain than the "
                f"sender '{from_address}' — a reply would not go back to the apparent sender",
            ))

    # 4. An "organisation" writing from a free webmail account.
    if address_domain(from_address) in FREE_MAIL_DOMAINS and any(
        word in display_lower for word in ORGANISATION_WORDS
    ):
        findings.append((
            "organisation_from_free_mail",
            f"The sender presents itself as an organisation ('{from_display}') but writes "
            f"from a free webmail address '{from_address}'",
        ))

    return findings
