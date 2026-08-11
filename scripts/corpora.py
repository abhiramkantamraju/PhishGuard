"""
Downloading and splitting the public email corpora used for evaluation.

Shared by `build_realistic_dataset.py` (which writes the benchmark CSVs) and
`scripts/calibrate.py` (which measures against them), so the two can't drift
apart about what "the tuning split" means.

Sources — all public, downloaded on demand, none committed to git (`data/` is
gitignored), compiled by https://github.com/rokibulroni/Phishing-Email-Dataset:

    CEAS_08         CEAS 2008 Spam Challenge corpus (mixed spam / ham)
    Enron           Enron-Spam business email corpus (mixed)
    SpamAssasin     Apache SpamAssassin public corpus (mixed)
    Nazario         Jose Nazario's phishing corpus (all phishing)
    Nigerian_Fraud  advance-fee ("419") scam corpus (all phishing)

Two different benchmarks are built from them, because they answer different
questions:

*The mixed benchmark* keeps each corpus's own label, so everything the source
data calls "1" counts as phishing — including generic commercial spam
(pharmaceutical ads, stock pump-and-dumps, replica goods). It measures
PhishGuard against a broader target than it is built for, and is kept because
lowering the bar for your own evaluation is how projects end up reporting
flattering numbers.

*The phishing-focused benchmark* narrows the positive class to the two corpora
that are actually credential-theft and financial-fraud phishing, and the
negative class to mail the source corpora label legitimate. That matches the
scope in the user-story backlog, so it is the benchmark the headline numbers
come from.

The focused benchmark is split in two. Rules and thresholds are chosen against
`tuning`; the numbers reported in the README come from `holdout`, which nothing
was fitted to. Keeping them separate is the difference between "this threshold
scored best on our data" and "this is how well it generalises".
"""

import csv
import random
import sys
import urllib.request
from pathlib import Path

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

RAW_BASE_URL = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"
SOURCES = ["CEAS_08", "Enron", "Nazario", "Nigerian_Fraud", "SpamAssasin"]

# Corpora whose every row is phishing, and those whose label-0 rows are real
# legitimate mail. Used only by the phishing-focused benchmark.
PHISHING_SOURCES = ["Nazario", "Nigerian_Fraud"]
LEGITIMATE_SOURCES = ["Enron", "SpamAssasin", "CEAS_08"]

MIXED_SAMPLE_SIZE = 4000
MIXED_SEED = 42
FOCUSED_SEED = 11
FOCUSED_PER_CLASS_PER_SPLIT = 1500

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "realistic_phishing"
SOURCES_DIR = DATA_DIR / "_sources"

MIXED_PATH = DATA_DIR / "realistic_emails.csv"
FOCUSED_TUNING_PATH = DATA_DIR / "phishing_focused_tuning.csv"
FOCUSED_HOLDOUT_PATH = DATA_DIR / "phishing_focused_holdout.csv"

DOWNLOAD_ATTEMPTS = 4
CHUNK_BYTES = 1 << 20


def download_sources(log=print):
    """
    Fetch any corpus not already on disk.

    Downloads are streamed and retried: these files are tens of megabytes each
    and a truncated response is silently useless — it would quietly shrink the
    benchmark instead of failing. A file is only accepted once its size matches
    the length the server advertised.
    """
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    for source in SOURCES:
        destination = SOURCES_DIR / f"{source}.csv"
        if destination.exists() and destination.stat().st_size > 0:
            log(f"Already downloaded: {destination.name}")
            continue

        url = f"{RAW_BASE_URL}/{source}.csv"
        for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
            log(f"Downloading {url} (attempt {attempt}/{DOWNLOAD_ATTEMPTS})")
            try:
                with urllib.request.urlopen(url, timeout=120) as response:
                    expected = int(response.headers.get("Content-Length") or 0)
                    with open(destination, "wb") as out:
                        while True:
                            chunk = response.read(CHUNK_BYTES)
                            if not chunk:
                                break
                            out.write(chunk)
                written = destination.stat().st_size
                if expected and written != expected:
                    raise OSError(f"truncated: got {written} of {expected} bytes")
                log(f"  -> {destination.name} ({written:,} bytes)")
                break
            except Exception as error:  # noqa: BLE001 - retry any transport failure
                log(f"  failed: {error}")
                destination.unlink(missing_ok=True)
        else:
            raise SystemExit(
                f"Could not download {url} after {DOWNLOAD_ATTEMPTS} attempts. "
                "Check your connection and re-run."
            )


def read_source(name):
    """Yield `(source_label, email_text)` for one corpus, skipping empty rows."""
    path = SOURCES_DIR / f"{name}.csv"
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            subject = (row.get("subject") or "").strip()
            body = (row.get("body") or "").strip()
            email_text = f"{subject}\n\n{body}".strip()
            if email_text:
                yield row.get("label"), email_text


def build_mixed_sample():
    """The original mixed benchmark: every corpus, every corpus's own label."""
    rows = []
    for source in SOURCES:
        for label, email_text in read_source(source):
            if label not in ("0", "1"):
                continue
            rows.append({
                "label": "phishing" if label == "1" else "legitimate",
                "email_text": email_text,
            })

    random.seed(MIXED_SEED)
    random.shuffle(rows)
    return rows[:MIXED_SAMPLE_SIZE]


def build_focused_splits():
    """`{"tuning": rows, "holdout": rows}` for the phishing-focused benchmark."""
    phishing, legitimate = [], []
    for source in PHISHING_SOURCES:
        phishing.extend(text for _, text in read_source(source))
    for source in LEGITIMATE_SOURCES:
        legitimate.extend(text for label, text in read_source(source) if label == "0")

    random.seed(FOCUSED_SEED)
    random.shuffle(phishing)
    random.shuffle(legitimate)

    n = FOCUSED_PER_CLASS_PER_SPLIT
    slices = {"tuning": slice(0, n), "holdout": slice(n, 2 * n)}
    splits = {}
    for name, window in slices.items():
        rows = [{"label": "phishing", "email_text": t} for t in phishing[window]]
        rows += [{"label": "legitimate", "email_text": t} for t in legitimate[window]]
        random.shuffle(rows)
        splits[name] = rows
    return splits


def write_dataset(path, rows, log=print):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["label", "email_text"])
        writer.writeheader()
        writer.writerows(rows)

    counts = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    log(f"Wrote {path} ({len(rows)} rows, {counts})")


def read_dataset(path):
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))
