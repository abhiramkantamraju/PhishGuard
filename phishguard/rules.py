"""
The rule registry: what PhishGuard looks for, and how much each finding counts.

Two ideas drive the shape of this file.

**Declarative rules.** Every check is a `Rule` — an id, the category it belongs
to, a regular expression, and the plain-English sentence shown to the user.
Adding a check means adding a row here, not editing the analysis function, and
every rule can be measured individually against the evaluation corpora (see
`README.md` → "How the rules were chosen").

**Categories carry the weight, not individual rules.** A phishing email often
trips five variations of the same idea ("verify your account", "confirm your
details", "update your records"). Scoring each one separately would let a
single theme dominate the score, so each *category* contributes its weight at
most once no matter how many of its rules matched. That keeps the score a rough
count of *independent* reasons to be suspicious, which is what the risk
thresholds in `phishguard.scoring` are calibrated against.

Rules whose category weight is 0 are informational: they are shown to the user
as context but never move the score. "This email contains links" is the
canonical example — nearly every real email contains links, so scoring it
flagged ordinary mail as phishing (see README).
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Category:
    """A theme of phishing behaviour, and how much it contributes to the score."""

    key: str
    label: str
    weight: int
    advice: str


CATEGORIES = {
    category.key: category
    for category in [
        Category(
            "credentials", "Requests credentials or personal data", 3,
            "Legitimate organisations do not ask you to send or re-enter passwords, "
            "PINs or card details by email. Never reply with them.",
        ),
        Category(
            "account_threat", "Threatens your account or warns of consequences", 3,
            "Threats of closure, suspension or legal action are used to rush you. "
            "Open the service yourself in a new tab and check the account there.",
        ),
        Category(
            "link_manipulation", "Deceptive or unsafe link", 3,
            "The link's real destination differs from what the text implies, or the "
            "domain is disguised. Hover over links and read the domain before clicking.",
        ),
        Category(
            "advance_fee", "Advance-fee or inheritance scam framing", 3,
            "An unexpected offer of a large sum in exchange for your help or a fee is "
            "a long-running fraud. There is no money.",
        ),
        Category(
            "prize", "Prize, lottery or reward scam", 3,
            "You cannot win a lottery you never entered. These messages exist to "
            "collect a 'processing fee' or your personal details.",
        ),
        Category(
            "attachment", "Mentions a risky attachment", 3,
            "Executable and macro-enabled attachments are a common malware delivery "
            "route. Do not open one you were not expecting.",
        ),
        Category(
            "sender", "Sender or reply address doesn't match", 3,
            "The visible sender, the real sending domain and the reply-to address "
            "disagree — a strong sign the message is forged.",
        ),
        Category(
            "impersonation", "Impersonates a service, brand or authority", 2,
            "The message claims to be from a provider, bank or IT department. Verify "
            "through a channel you already trust, not through this email.",
        ),
        Category(
            "urgency", "Urgency or time pressure", 2,
            "Deadlines and countdowns are there to stop you checking. Slow down; a "
            "real notice will still be valid in an hour.",
        ),
        Category(
            "greeting", "Impersonal or generic greeting", 2,
            "A provider that holds your account normally knows your name. "
            "'Dear Customer' suggests a message sent to thousands of addresses.",
        ),
        Category(
            "reply_channel", "Unusual reply channel", 1,
            "Business correspondence that asks you to reply to a free webmail address "
            "or an unrelated phone number is unlikely to be genuine.",
        ),
        Category("informational", "Worth checking yourself", 0, ""),
    ]
}


@dataclass(frozen=True)
class Rule:
    """One pattern PhishGuard looks for."""

    key: str
    category: str
    pattern: re.Pattern
    message: str  # `{match}` is substituted with the matched text.

    def find(self, text):
        match = self.pattern.search(text)
        return match.group(0).strip() if match else None


def _keyword_rule(key, category, keywords, message):
    """A rule built from a phrase list, matched as case-insensitive substrings."""
    pattern = re.compile("|".join(re.escape(keyword) for keyword in keywords), re.IGNORECASE)
    return Rule(key, category, pattern, message)


def _rule(key, category, pattern, message):
    return Rule(key, category, re.compile(pattern, re.IGNORECASE), message)


# --- Phrase lists -----------------------------------------------------------
#
# "immediately", "important notice" and "action required" were removed from
# URGENT_KEYWORDS after measurement: they fire constantly on ordinary
# legitimate mail ("no action required", "effective immediately",
# administrative notices) with no phishing-specific signal. "act now",
# "urgent" and "limited time" are kept even though real marketing copy uses
# them too — removing them would blind the detector to genuine urgency-based
# phishing. That precision/recall tension is inherent to phrase matching and is
# documented in the README rather than tuned away.

# "verify your account" and "confirm your details" used to live here as well as
# in PERSONAL_INFO_KEYWORDS, which meant one phrase was reported twice under two
# different headings ("Urgent language" and "Requests personal information").
# They are credential requests, not urgency, so they are kept only in the
# credentials list.
URGENT_KEYWORDS = [
    "act now", "urgent", "your account will be closed", "click here now",
    "limited time", "expires soon",
    "password expires", "your password will expire", "account will expire",
    "expires today",
]

PERSONAL_INFO_KEYWORDS = [
    "enter your password", "confirm your password", "enter your credit card",
    "bank account details", "social security", "date of birth",
    "enter your pin", "verify your identity", "verify your account",
    "confirm your details", "login details", "account password",
    "validate your account", "account validation", "unusual sign-in activity",
    "update your account information", "restore your account",
    "verify your email address", "your mailbox is almost full",
    "security alert",
]

THREAT_KEYWORDS = [
    "your account has been suspended", "unusual activity detected",
    "unauthorized access", "your account will be terminated",
    "failure to respond", "legal action", "you have been selected",
]

PRIZE_SCAM_KEYWORDS = [
    "you have won", "you've won", "you have been awarded", "claim your prize",
    "claim your winnings", "lottery winner", "winning notification",
    "claim your reward",
]

# Advance-fee ("419") phrasing. Each phrase was checked against the Enron
# legitimate business corpus and kept only where it essentially never appears
# there, so recall is not bought with new false positives.
ADVANCE_FEE_SCAM_KEYWORDS = [
    "next of kin", "beneficiary", "dear friend", "foreign partner",
    "strictly confidential", "assist me", "bank account number",
    "dormant account", "my late father", "my late husband",
    "contact me immediately", "security company", "sum of",
]

# ".com" is deliberately absent: it is a common TLD in ordinary body text
# ("example.com"), which would false-positive constantly.
RISKY_ATTACHMENT_EXTENSIONS = [
    "exe", "scr", "bat", "cmd", "pif", "vbs", "js", "jar",
    "msi", "zip", "rar", "7z", "docm", "xlsm", "pptm", "iso", "img", "lnk",
    "hta", "ps1",
]

FREE_MAIL_PROVIDERS = [
    "yahoo", "hotmail", "gmail", "aol", "live", "outlook", "yandex",
    "mail", "gmx", "protonmail", "rediffmail", "msn",
]


# --- The registry -----------------------------------------------------------
#
# Measured firing rates against the evaluation corpora are noted per rule as
# `phishing% / legitimate%` (Nazario + Nigerian-fraud phishing vs. Enron,
# SpamAssassin and CEAS legitimate mail). They are the evidence for each
# rule's inclusion; see README → "How the rules were chosen".

TEXT_RULES = [
    # --- Credential and personal-data requests ---
    _keyword_rule(
        "personal_info_phrases", "credentials", PERSONAL_INFO_KEYWORDS,
        "Requests personal information: '{match}'",
    ),
    # The possessive ("your"/"the") is required rather than optional: without
    # it this matched ordinary service mail like "update payment details anytime
    # from your account settings". Requiring it cost 0.3pp of recall on the
    # phishing corpora and removed that false positive class outright.
    _rule(  # 9.9% / 0.3%
        "verify_records", "credentials",
        r"(?:verify|confirm|update|validate|re-?confirm|re-?activate|reactivate)\s+"
        r"(?:your|the)\s+(?:account|identity|records?|information|details|e-?mail"
        r"|mailbox|password|billing|payment\s+details|profile|membership|subscription)"
        r"|(?:verify|confirm|validate|re-?activate|reactivate)\s+"
        r"(?:account|identity|e-?mail|mailbox)\b",
        "Asks you to verify or update account details: '{match}'",
    ),
    # Only the imperative forms. A bare mention of "username and password" was
    # every single false positive this rule produced on the legitimate corpora —
    # normal account-setup and mailing-list mail names the pair without asking
    # for it. Asking the reader to *type* it is the phishing behaviour.
    _rule(  # 0.9% / 0.0%
        "enter_credentials", "credentials",
        r"(?:enter|provide|supply|submit|input|type|re-?enter|send\s+us)\s+(?:your\s+)?"
        r"(?:user\s?name|username|user\s?id|login|log-?in|password|pin\b|passcode"
        r"|security\s+(?:question|answer))",
        "Asks you to type in login credentials: '{match}'",
    ),
    # Asking the reader to "update" a national or banking identifier. Rare in
    # the evaluation corpora (0.2%) because they are 2000s-era mail, but BVN /
    # Aadhaar / OTP / CVV requests are a staple of current phishing, and the
    # rule produced zero false positives across 3,000 legitimate emails — so it
    # is kept on the strength of precision rather than corpus frequency.
    _rule(  # 0.2% / 0.0%
        "identity_number_request", "credentials",
        r"(?:update|verify|confirm|validate|provide|submit|enter|re-?activate)\s+"
        r"(?:your\s+|the\s+)?(?:bvn\b|nin\b|ssn\b|social\s+security\s+number"
        r"|national\s+id(?:entity)?(?:\s+number)?|aadhaar|tax\s+id(?:entification)?(?:\s+number)?"
        r"|\biban\b|\bcvv\b|\botp\b|one-?time\s+(?:password|code|pin)|security\s+code"
        r"|card\s+(?:number|details)|atm\s+(?:pin|card))",
        "Asks for a banking or national identity number: '{match}'",
    ),
    _rule(  # 0.8% / 0.1%
        "reply_with_details", "credentials",
        r"reply\s+(?:to\s+this\s+(?:e-?mail|message)\s+)?with\s+(?:your|the\s+following)"
        r"|(?:send|forward|provide|furnish|fill\s+in)\s+(?:us\s+|me\s+|the\s+)?"
        r"(?:following|your)\s+(?:details|information|data|particulars|info)",
        "Asks you to reply with personal details: '{match}'",
    ),

    # --- Threats and consequences ---
    _keyword_rule(
        "threat_phrases", "account_threat", THREAT_KEYWORDS,
        "Threatening language detected: '{match}'",
    ),
    _rule(  # 5.8% / 0.0%
        "account_state", "account_threat",
        r"(?:your\s+)?(?:account|mailbox|access|profile)\s+(?:has\s+been\s+|was\s+|is\s+)?"
        r"(?:suspend|lock|disabl|limit|restrict|deactivat|block|clos|terminat|compromis)\w*"
        r"|(?:suspended|limited|locked|blocked|disabled)\s+your\s+(?:account|access|mailbox)",
        "Claims your account is suspended or restricted: '{match}'",
    ),
    _rule(  # 5.6% / 0.0%
        "account_will_close", "account_threat",
        r"(?:account|mailbox|e-?mail|subscription)\s+will\s+be\s+"
        r"(?:closed|suspended|deactivated|deleted|disabled|terminated|blocked|locked)"
        r"|(?:closure|deactivation|suspension|termination)\s+of\s+your\s+(?:account|mailbox)"
        r"|(?:permanently\s+)?(?:shut\s?down|de-?activate|delete)\s+your\s+(?:account|mailbox)",
        "Warns your account will be closed or suspended: '{match}'",
    ),
    _rule(  # 4.0% / 0.0%
        "failure_consequence", "account_threat",
        r"failure\s+to\s+(?:do\s+so|comply|respond|update|verify|confirm|act)"
        r"|if\s+you\s+(?:do\s+not|don'?t|fail\s+to)\s+"
        r"(?:respond|verify|update|confirm|comply|reply|act)"
        r"|otherwise\s+your\s+account",
        "Threatens a consequence if you don't act: '{match}'",
    ),
    _rule(  # 0.8% / 0.0%
        "avoid_consequence", "account_threat",
        r"(?:to\s+avoid|avoid|prevent)\s+(?:any\s+|further\s+|the\s+)?"
        r"(?:restriction|suspension|closure|deactivation|de-?activation|termination"
        r"|penalt\w*|interruption|blocking|being\s+(?:blocked|suspended|closed)"
        r"|loss\s+of\s+(?:access|your\s+account))",
        "Frames the request as avoiding a penalty: '{match}'",
    ),
    _rule(  # 3.1% / 0.0%
        "unusual_signin", "account_threat",
        r"unusual\s+(?:sign-?in|log-?in|activity|attempt)"
        r"|suspicious\s+(?:sign-?in|log-?in|activity|attempt)"
        r"|(?:we|our\s+(?:system|team)|it)\s+(?:have\s+|has\s+)?"
        r"(?:detected|noticed|observed|identified)\s+(?:some\s+)?"
        r"(?:unusual|suspicious|unauthori[sz]ed|irregular)",
        "Claims suspicious activity was detected on your account: '{match}'",
    ),
    _rule(  # 4.3% / 0.0%
        "mailbox_quota", "account_threat",
        r"(?:mail|mailbox|e-?mail)\s?box\s+(?:is\s+)?(?:almost\s+)?(?:full|exceeded)"
        r"|(?:exceeded|reached)\s+(?:your|the)\s+(?:storage\s+|e-?mail\s+)?(?:quota|limit)"
        r"|storage\s+(?:limit|quota)\s+(?:exceeded|reached)"
        r"|(?:re-?validate|upgrade)\s+your\s+mailbox",
        "Claims your mailbox is full or over quota: '{match}'",
    ),

    # --- Urgency ---
    _keyword_rule(
        "urgent_phrases", "urgency", URGENT_KEYWORDS,
        "Urgent language detected: '{match}'",
    ),
    _rule(  # 7.6% / 0.6%
        "short_deadline", "urgency",
        r"within\s+(?:the\s+next\s+)?(?:\d{1,2}|twenty-?four|forty-?eight|seventy-?two)\s*"
        r"(?:-\s*\d{1,2}\s*)?(?:hours?|hrs?|days?|working\s+days?)"
        r"|in\s+the\s+next\s+\d{1,2}\s*(?:hours?|days?)"
        r"|(?:expire|deactivated|suspended|closed)\s+within\s+\d{1,2}",
        "Sets a short deadline to pressure you: '{match}'",
    ),
    _rule(  # 13.0% / 0.0%
        "urgent_response_demand", "urgency",
        r"urgent\s+(?:reply|response|attention|assistance|action|consideration)"
        r"|your\s+urgent\s+(?:reply|response|attention|assistance)"
        r"|treat\s+(?:this\s+)?as\s+(?:very\s+)?urgent"
        r"|awaiting\s+your\s+urgent",
        "Demands an urgent reply: '{match}'",
    ),

    # --- Impersonation ---
    _rule(  # 6.0% / 0.4%
        "it_support_impersonation", "impersonation",
        r"(?:webmail|web\s?mail|e-?mail|account)\s+"
        r"(?:team|admin|administrator|support\s+team|service\s+team|help\s?desk)"
        r"|system\s+administrator"
        r"|(?:it|technical)\s+(?:help\s?desk|department|support\s+team|service\s+desk)"
        r"|(?:from\s+the\s+)?(?:security|abuse)\s+team",
        "Claims to be from IT support or an email administrator: '{match}'",
    ),
    _rule(  # 3.9% / 0.3%
        "authority_impersonation", "impersonation",
        r"central\s+bank|reserve\s+bank|ministry\s+of\s+finance|federal\s+ministry"
        r"|world\s+bank|\bimf\b|monetary\s+unit|federal\s+bureau|\bfbi\b"
        r"|internal\s+revenue|\birs\b\s+(?:notice|refund|department)",
        "Claims to be from a bank, ministry or government agency: '{match}'",
    ),

    # --- Greeting ---
    _rule(  # 28.9% / 0.1%
        "generic_greeting", "greeting",
        r"\bdear\s+(?:valued\s+)?(?:customer|client|user|member|subscriber"
        r"|account\s+holder|card\s?holder|sir|madam|sir/madam|sir\s+or\s+madam"
        r"|friend|winner|beneficiary|applicant|e-?mail\s+(?:user|account\s+owner)"
        r"|webmail\s+user|web\s?mail\s+subscriber)\b"
        r"|\battention\s*:?\s*(?:e-?mail|account)\s+(?:user|owner|holder)\b",
        "Impersonal greeting instead of your name: '{match}'",
    ),

    # --- Advance-fee / inheritance framing ---
    _keyword_rule(
        "advance_fee_phrases", "advance_fee", ADVANCE_FEE_SCAM_KEYWORDS,
        "Advance-fee scam language detected: '{match}'",
    ),
    _rule(  # 29.6% / 0.2%
        "fund_transfer", "advance_fee",
        r"transfer\s+of\s+(?:the\s+)?(?:fund|money|sum)|the\s+sum\s+of\b"
        r"|wire\s+transfer\s+of|\bnext\s+of\s+kin\b|\binheritance\b"
        r"|unclaimed\s+(?:fund|estate|deposit)|\bdormant\s+account\b",
        "Describes an unsolicited transfer of funds: '{match}'",
    ),
    _rule(  # 20.7% / 0.1%
        "large_sum", "advance_fee",
        r"(?:us\s?\$|usd|\$|£|€)\s?\d{1,3}(?:[,.]\d{3}){2,}"
        r"|\b\d{1,3}(?:[.,]\d+)?\s*(?:million|billion)\s*(?:us\s*)?"
        r"(?:dollars|usd|pounds|euros|gbp|eur)",
        "Mentions an unusually large sum of money: '{match}'",
    ),
    _rule(  # 19.2% / 0.0%
        "percentage_cut", "advance_fee",
        r"\b(?:\d{1,2}|ten|fifteen|twenty|twenty-?five|thirty|forty|fifty)\s?"
        r"(?:%|per\s?cent(?:age)?)\s+(?:of\s+(?:the\s+)?(?:total\s+)?"
        r"(?:sum|fund|money|amount)|for\s+you|will\s+be\s+for|shall\s+be)",
        "Offers you a percentage of a large sum: '{match}'",
    ),
    _rule(  # 23.5% / 0.0%
        "self_introduction", "advance_fee",
        r"\bi\s+am\s+(?:mr|mrs|miss|ms|dr|barrister|chief|engr|prof|rev|sir|madam)\b"
        r"|\bmy\s+name\s+is\s+(?:mr|mrs|miss|ms|dr|barrister|chief|engr|prof|rev)\b"
        r"|\bi\s+am\s+the\s+(?:only\s+)?(?:son|daughter|wife|widow)\s+of\b",
        "Opens with a formal self-introduction typical of scam letters: '{match}'",
    ),
    _rule(  # 14.7% / 0.1%
        "bereavement_story", "advance_fee",
        r"\bmy\s+(?:late|deceased)\s+(?:father|husband|mother|wife|client|uncle|brother)"
        r"|\bpassed\s+away\b|\bwidow\s+of\b|\bcancer\s+of\s+the\b"
        r"|\bdied\s+(?:in|of|on|after)\b|\bterminally\s+ill\b",
        "Uses a death or illness story to justify the request: '{match}'",
    ),
    _rule(  # 6.9% / 0.0%
        "secrecy_demand", "advance_fee",
        r"strictly\s+confidential|utmost\s+confiden\w*|absolute\s+confiden\w*"
        r"|keep\s+(?:this|it)\s+(?:as\s+)?(?:a\s+)?(?:top\s+)?secret"
        r"|treat\s+(?:this\s+)?(?:as\s+|with\s+)?(?:top\s+)?(?:secret|confidential)",
        "Demands secrecy: '{match}'",
    ),

    # --- Prize scams ---
    _keyword_rule(
        "prize_phrases", "prize", PRIZE_SCAM_KEYWORDS,
        "Prize/lottery scam language detected: '{match}'",
    ),
    _rule(
        "lottery_reference", "prize",
        r"(?:won|winner|winning)[^\n]{0,40}(?:lottery|lotto|draw|sweepstake|raffle|promotion)"
        r"|lucky\s+winner|batch\s+number|winning\s+(?:number|ticket|reference)"
        r"|ticket\s+number[^\n]{0,20}(?:won|winning)",
        "References a lottery or prize draw you did not enter: '{match}'",
    ),

    # --- Reply channel ---
    _rule(  # 1.4% / 0.0%
        "free_mail_reply", "reply_channel",
        r"(?:reply|contact|write|respond|e-?mail|call)\s+(?:back\s+)?(?:to\s+)?"
        r"(?:me|us)\s+(?:at|on|via|through|directly\s+at)[^\n]{0,40}@(?:"
        + "|".join(FREE_MAIL_PROVIDERS) + r")\.",
        "Asks you to reply to a free webmail address: '{match}'",
    ),
    # Two rules were measured and deliberately *not* kept, recorded here so the
    # reasoning isn't lost:
    #
    # - "international phone/fax number" (5.8% phishing / 0.9% legitimate) —
    #   every legitimate match was an ordinary European business signature. It
    #   only separated the classes when narrowed to specific country dialling
    #   codes, which is geographic profiling rather than phishing detection, and
    #   the advance-fee category already catches those emails on much stronger
    #   evidence.
    # - "words spaced out to evade filters" (0.2% phishing / 0.3% legitimate) —
    #   fired more often on legitimate mail than phishing (ASCII-art
    #   signatures, spaced headings), so it carried no signal at all.
]


# Rules that need more than a regex over the raw text (URL structure, sender
# headers) are implemented in `phishguard.scoring` and `phishguard.headers`.
ATTACHMENT_MENTION_PATTERN = re.compile(
    r"\b[\w-]+\.(?:" + "|".join(RISKY_ATTACHMENT_EXTENSIONS) + r")\b",
    re.IGNORECASE,
)
