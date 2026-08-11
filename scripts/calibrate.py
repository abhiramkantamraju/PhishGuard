"""
Threshold calibration and per-rule measurement.

The tool behind README → "How the rules were chosen". A development aid, not
part of the app: it reads the phishing-focused benchmark splits written by
`build_realistic_dataset.py` and reports what each candidate score threshold
would buy.

Choices are made on the tuning split; the numbers quoted for the record come
from the holdout split, which nothing was fitted to.

    python scripts/calibrate.py            # threshold sweep on both splits
    python scripts/calibrate.py --rules    # per-rule firing rates (tuning split)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import CATEGORIES, DANGEROUS_THRESHOLD, SUSPICIOUS_THRESHOLD, analyze  # noqa: E402
from phishguard.rules import TEXT_RULES  # noqa: E402
from scripts.corpora import (  # noqa: E402
    FOCUSED_HOLDOUT_PATH,
    FOCUSED_TUNING_PATH,
    read_dataset,
)

MAX_THRESHOLD = 12


def load_split(path):
    if not path.exists():
        raise SystemExit(f"{path} not found — run `python build_realistic_dataset.py` first.")
    rows = read_dataset(path)
    phishing = [r["email_text"] for r in rows if r["label"] == "phishing"]
    legitimate = [r["email_text"] for r in rows if r["label"] == "legitimate"]
    return phishing, legitimate


def sweep(split_name, phishing, legitimate):
    phishing_scores = [analyze(text).score for text in phishing]
    legitimate_scores = [analyze(text).score for text in legitimate]

    print(f"\n=== {split_name}: {len(phishing)} phishing / {len(legitimate)} legitimate ===")
    print(f"{'threshold':>9} {'precision':>10} {'recall':>8} {'F1':>8} "
          f"{'accuracy':>9} {'FP rate':>8}")
    for threshold in range(1, MAX_THRESHOLD + 1):
        true_positive = sum(1 for s in phishing_scores if s >= threshold)
        false_negative = len(phishing_scores) - true_positive
        false_positive = sum(1 for s in legitimate_scores if s >= threshold)
        true_negative = len(legitimate_scores) - false_positive

        predicted_positive = true_positive + false_positive
        actual_positive = true_positive + false_negative
        precision = true_positive / predicted_positive if predicted_positive else 0
        recall = true_positive / actual_positive if actual_positive else 0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
        accuracy = (true_positive + true_negative) / (len(phishing_scores) + len(legitimate_scores))
        fp_rate = false_positive / len(legitimate_scores)

        marker = ""
        if threshold == SUSPICIOUS_THRESHOLD:
            marker = "  <- Suspicious threshold (in use)"
        elif threshold == DANGEROUS_THRESHOLD:
            marker = "  <- Dangerous threshold"
        print(f"{threshold:>9} {precision:>9.2%} {recall:>7.2%} {f1:>7.2%} "
              f"{accuracy:>8.2%} {fp_rate:>7.2%}{marker}")


def per_rule(phishing, legitimate):
    print(f"\n{'rule':28s} {'category':16s} {'w':>2s} {'phish%':>7s} {'legit%':>7s} {'ratio':>7s}")
    rows = []
    for rule in TEXT_RULES:
        tp = sum(1 for t in phishing if rule.find(t)) / len(phishing) * 100
        fp = sum(1 for t in legitimate if rule.find(t)) / len(legitimate) * 100
        rows.append((rule, tp, fp))
    for rule, tp, fp in sorted(rows, key=lambda r: (r[0].category, -r[1])):
        ratio = f"{tp / fp:7.1f}" if fp else "    inf"
        print(f"{rule.key:28s} {rule.category:16s} {CATEGORIES[rule.category].weight:>2d} "
              f"{tp:7.2f} {fp:7.2f} {ratio}")


def main():
    parser = argparse.ArgumentParser(description="Calibrate PhishGuard's score thresholds.")
    parser.add_argument("--rules", action="store_true",
                        help="Show per-rule firing rates instead of the threshold sweep.")
    args = parser.parse_args()

    if args.rules:
        per_rule(*load_split(FOCUSED_TUNING_PATH))
        return

    for name, path in (("tuning", FOCUSED_TUNING_PATH), ("holdout", FOCUSED_HOLDOUT_PATH)):
        sweep(name, *load_split(path))


if __name__ == "__main__":
    main()
