# PhishGuard
Repository for the Project PhishGuard

## Project Description
Webpage to detect phishing emails and suspicious urls

## Setup

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

The app runs on http://127.0.0.1:5000 by default.

Set the `SECRET_KEY` environment variable to a stable random value in any
persistent deployment (it is used for CSRF protection). Set `FLASK_DEBUG=1`
to enable the Flask debugger during local development only — never in
production, since it allows arbitrary code execution.

Optionally set `SAFE_BROWSING_API_KEY` to a [Google Safe Browsing API](https://developers.google.com/safe-browsing)
key to check scanned URLs against Google's known-threat list. Without it,
that check is silently skipped — every other feature, including the WHOIS
domain-age check, works with no configuration.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Dataset Evaluation

PhishGuard includes a small evaluation runner that can be used with the
included sample data or with a larger Kaggle phishing email dataset exported to
CSV/XLSX.

Expected CSV columns:

- `label`: `phishing` or `legitimate`
- `email_text`: the full email text to analyze

Run the sample evaluation:

```bash
python evaluate_dataset.py sample_data/sample_emails.csv
```

Run the downloaded Kaggle evaluation:

```bash
python evaluate_dataset.py "data/kaggle_phishing_email/phishing_dataset (1).xlsx"
```

For a shorter output:

```bash
python evaluate_dataset.py "data/kaggle_phishing_email/phishing_dataset (1).xlsx" --quiet
```

The script reports total emails, correct predictions, accuracy, false positives,
and false negatives. These results can be added to the final README/report as
project evidence.

Kaggle dataset used locally:

- Title: Phishing Email Dataset
- Source: https://www.kaggle.com/datasets/tommyf1/phishing-email-dataset
- License: MIT

Current Kaggle evaluation result:

- Total emails: 800
- Correct predictions: 800
- Accuracy: 100.00%
- False positives: 0 (0.00%)
- False negatives: 0 (0.00%)

Interpretation: this Kaggle dataset is templated — all 800 rows are repeats
of only 8 unique sentences (4 phishing, 4 legitimate). The two phishing
templates PhishGuard originally missed ("your email password expires
today...", "you have won ¥500,000...") are now covered by the
credential-expiry and prize/lottery-scam keyword rules added to
`detector.py`. 100% accuracy reflects full rule coverage of this dataset's
specific phrasing, not a claim of perfect real-world detection — a phishing
email with none of these keywords or URL red flags will still be missed.
`evaluate_dataset.py` deliberately doesn't exercise the Google Safe
Browsing/WHOIS checks (see below), since those need live network access and
would make the evidence run slow and non-deterministic; it measures the
offline rule engine only.

## URL threat intelligence (live app only)

Beyond the offline rules, live scans in the web app also check each URL
against:

- **Google Safe Browsing** — flags URLs on Google's known malware/phishing
  list. Requires `SAFE_BROWSING_API_KEY`; skipped without one.
- **WHOIS domain age** — flags domains registered in the last 30 days, a
  common phishing indicator. No API key needed. Bounded to a 5-second
  timeout per domain (checks at most 3 unique domains per email) so a slow
  or unreachable WHOIS server can't hang the request.

Both checks are best-effort: any failure (missing key, network error, WHOIS
lookup failure) is swallowed and simply adds no flag, rather than breaking
the scan.
