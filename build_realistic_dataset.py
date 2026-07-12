"""
Builds data/realistic_phishing/realistic_emails.csv: a balanced sample of
real, unstructured phishing/spam and legitimate emails, used alongside the
templated Kaggle set as a second, harder evaluation benchmark (see README).

Sources (all public, downloaded fresh - nothing is committed to git since
data/ is gitignored):
  - CEAS_08   - CEAS 2008 Spam Challenge corpus
  - Enron     - Enron-Spam legitimate business email corpus
  - Nazario   - Jose Nazario's phishing corpus
  - Nigerian_Fraud - advance-fee ("419") scam corpus
  - SpamAssasin - Apache SpamAssassin public spam/ham corpus
  compiled by https://github.com/rokibulroni/Phishing-Email-Dataset

Usage: python build_realistic_dataset.py
"""
import csv
import random
import sys
from pathlib import Path
from urllib.request import urlretrieve

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

RAW_BASE_URL = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"
SOURCES = ["CEAS_08", "Enron", "Nazario", "Nigerian_Fraud", "SpamAssasin"]
SAMPLE_SIZE = 4000
RANDOM_SEED = 42

DATA_DIR = Path(__file__).parent / "data" / "realistic_phishing"
SOURCES_DIR = DATA_DIR / "_sources"
OUT_PATH = DATA_DIR / "realistic_emails.csv"


def download_sources():
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    for source in SOURCES:
        dest = SOURCES_DIR / f"{source}.csv"
        if dest.exists():
            print(f"Already downloaded: {dest}")
            continue
        url = f"{RAW_BASE_URL}/{source}.csv"
        print(f"Downloading {url} -> {dest}")
        urlretrieve(url, dest)


def load_rows():
    rows = []
    for source in SOURCES:
        path = SOURCES_DIR / f"{source}.csv"
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                label = row.get("label")
                if label not in ("0", "1"):
                    continue
                subject = (row.get("subject") or "").strip()
                body = (row.get("body") or "").strip()
                email_text = f"{subject}\n\n{body}".strip()
                if not email_text:
                    continue
                rows.append({
                    "label": "phishing" if label == "1" else "legitimate",
                    "email_text": email_text,
                })
    return rows


def main():
    download_sources()
    rows = load_rows()
    print(f"Total combined rows available: {len(rows)}")

    random.seed(RANDOM_SEED)
    random.shuffle(rows)
    sample = rows[:SAMPLE_SIZE]

    label_counts = {}
    for row in sample:
        label_counts[row["label"]] = label_counts.get(row["label"], 0) + 1
    print(f"Sample size: {len(sample)}, label counts: {label_counts}")

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["label", "email_text"])
        writer.writeheader()
        writer.writerows(sample)

    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
