"""
Builds the evaluation benchmarks from real, public email corpora.

Run once, then evaluate:

    python build_realistic_dataset.py
    python evaluate_dataset.py data/realistic_phishing/phishing_focused_holdout.csv --quiet
    python evaluate_dataset.py data/realistic_phishing/realistic_emails.csv --quiet

Three CSVs are produced under `data/realistic_phishing/` (all gitignored — they
are derived from third-party corpora, not project source):

    realistic_emails.csv            4,000-email mixed-source benchmark; keeps
                                    each corpus's own spam/ham label, so generic
                                    commercial spam counts as phishing. Harder
                                    than PhishGuard's actual scope, kept as an
                                    honest upper bound on difficulty.
    phishing_focused_tuning.csv     3,000 emails; the split the rules and score
                                    thresholds were developed against.
    phishing_focused_holdout.csv    3,000 emails, disjoint from the above; the
                                    split the README's headline numbers come
                                    from, so they aren't self-graded.

See `scripts/corpora.py` for the sources, the sampling seeds, and why the
phishing-focused benchmark is defined the way it is.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scripts.corpora import (  # noqa: E402
    FOCUSED_HOLDOUT_PATH,
    FOCUSED_TUNING_PATH,
    MIXED_PATH,
    build_focused_splits,
    build_mixed_sample,
    download_sources,
    write_dataset,
)


def main():
    download_sources()

    print("\nMixed-source benchmark")
    write_dataset(MIXED_PATH, build_mixed_sample())

    print("\nPhishing-focused benchmark")
    splits = build_focused_splits()
    write_dataset(FOCUSED_TUNING_PATH, splits["tuning"])
    write_dataset(FOCUSED_HOLDOUT_PATH, splits["holdout"])

    print("\nDone. Evaluate with:")
    print(f"  python evaluate_dataset.py {FOCUSED_HOLDOUT_PATH.as_posix()} --quiet")


if __name__ == "__main__":
    main()
