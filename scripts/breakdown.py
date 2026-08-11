"""
Recall broken down by source corpus.

Answers the question the mixed benchmark's aggregate accuracy hides: *what* is
PhishGuard missing? The mixed benchmark labels every row its source corpus
marked as spam-or-phishing as "phishing", which lumps credential-theft phishing
together with pharmaceutical ads and stock pump-and-dumps. This script measures
each corpus separately so the difference is visible instead of asserted.

    python scripts/breakdown.py
"""

import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import SUSPICIOUS_THRESHOLD, analyze  # noqa: E402
from scripts.corpora import (  # noqa: E402
    MIXED_SAMPLE_SIZE,
    MIXED_SEED,
    PHISHING_SOURCES,
    SOURCES,
    read_source,
)


def build_labelled_sample():
    """The mixed benchmark, but keeping which corpus each row came from."""
    rows = []
    for source in SOURCES:
        for label, email_text in read_source(source):
            if label not in ("0", "1"):
                continue
            rows.append({
                "source": source,
                "label": "phishing" if label == "1" else "legitimate",
                "email_text": email_text,
            })
    random.seed(MIXED_SEED)
    random.shuffle(rows)
    return rows[:MIXED_SAMPLE_SIZE]


def flagged(row):
    return analyze(row["email_text"]).score >= SUSPICIOUS_THRESHOLD


def main():
    sample = build_labelled_sample()
    phishing = [row for row in sample if row["label"] == "phishing"]
    legitimate = [row for row in sample if row["label"] == "legitimate"]

    print(f"Mixed benchmark: {len(sample)} emails "
          f"({len(phishing)} labelled phishing / {len(legitimate)} labelled legitimate)")

    print("\nRows labelled 'phishing', by source corpus")
    print(f"{'corpus':18s} {'rows':>6s} {'share':>7s} {'caught':>7s} {'recall':>8s}")
    counts = Counter(row["source"] for row in phishing)
    for source, count in counts.most_common():
        rows = [row for row in phishing if row["source"] == source]
        caught = sum(1 for row in rows if flagged(row))
        kind = "phishing" if source in PHISHING_SOURCES else "spam"
        print(f"{source:18s} {count:>6d} {count / len(phishing):>6.1%} "
              f"{caught:>7d} {caught / count:>7.1%}   ({kind})")

    true_phishing = [row for row in phishing if row["source"] in PHISHING_SOURCES]
    generic_spam = [row for row in phishing if row["source"] not in PHISHING_SOURCES]

    def recall(rows):
        return sum(1 for row in rows if flagged(row)) / len(rows) if rows else 0.0

    print("\nGrouped")
    print(f"  credential-theft / advance-fee phishing: {len(true_phishing):>5d} rows "
          f"({len(true_phishing) / len(phishing):.1%} of the positive class), "
          f"recall {recall(true_phishing):.2%}")
    print(f"  generic commercial spam:                 {len(generic_spam):>5d} rows "
          f"({len(generic_spam) / len(phishing):.1%} of the positive class), "
          f"recall {recall(generic_spam):.2%}")
    print("\nThe gap between those two numbers is the scope difference: PhishGuard is "
          "built to\ndetect phishing, and this benchmark's positive class is "
          "overwhelmingly spam.")


if __name__ == "__main__":
    main()
