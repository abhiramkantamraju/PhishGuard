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

## Second benchmark: realistic, unstructured email data

Because the Kaggle set above is small and templated, `build_realistic_dataset.py`
builds a second, harder benchmark from real (not synthetic) public email
corpora — Enron business email (legitimate), the CEAS 2008 Spam Challenge and
Apache SpamAssassin corpora (mixed spam/legitimate), and the Nazario and
Nigerian-fraud phishing corpora — compiled by
[rokibulroni/Phishing-Email-Dataset](https://github.com/rokibulroni/Phishing-Email-Dataset).
Run `python build_realistic_dataset.py` to download the sources and produce
a 4,000-email balanced sample at `data/realistic_phishing/realistic_emails.csv`
(seeded, so the sample is reproducible), then evaluate it the same way:

```bash
python evaluate_dataset.py "data/realistic_phishing/realistic_emails.csv" --quiet
```

Current result:

- Total emails: 4,000
- Accuracy: 51.82%
- False positives: 52 (1.30%)
- False negatives: 1,875 (46.88%)
- Precision: 82.37%
- Recall: 11.47%
- F1 score: 20.14%

Interpretation: this is a much harder, more honest test than the Kaggle set,
and the numbers are meaningfully worse — which is expected and worth stating
plainly rather than hiding. Two things came out of building it:

1. **A real bug it caught**: the two weakest signals in `detector.py`
   ("contains a link" and "contains an insecure HTTP link") were originally
   scored, and since almost every real email — mailing-list digests, tech
   newsletters, forum threads — contains a link, this alone was enough to
   push ordinary legitimate email over the "Suspicious" threshold. Before the
   fix, false positives were 20.30%; after removing the score contribution
   from those two flags (kept as informational-only messages), false
   positives dropped to 2.50%, at the cost of recall (which had partly been
   inflated by the same blunt "has a link" trigger rather than genuine
   detection).
2. **Real, low-risk recall gains**: an advance-fee ("419" scam) keyword
   category and several account-validation phrases were added, each checked
   against the real Enron legitimate corpus first to confirm near-zero false
   positive rate before inclusion (see git history / `detector.py` comments
   for the specific phrases and their measured false-positive rates).

A third check, `sample_data/legitimate_marketing_emails.csv` (ten synthetic
but realistic promotional emails — flash sales, trial-expiry reminders,
policy notices), specifically targeted the concern that legitimate marketing
copy reuses the same urgency language as phishing ("act now", "limited time
offer", "expires today"). Initial result: 60% false positive rate, entirely
from the generic `URGENT_KEYWORDS` category — including a literal bug where
"no action required" matched the "action required" keyword because the
substring-matching approach has no negation handling. Removing three
bare/generic phrases ("immediately", "important notice", "action required")
that had no measurable effect on the Kaggle or realistic-set true positives
brought this down to 40%. The residual false positives ("act now" and
"expires soon" still firing on real sales copy) are left as-is and
documented rather than removed, since those exact phrases are also
genuinely common phishing CTAs — this is an inherent precision/recall
tradeoff for keyword-based urgency detection, not a bug to chase to zero.

Recall (11.47%) is still low against the realistic dataset. A meaningful
chunk of its
"phishing" label is generic commercial spam (pharmaceutical ads, replica
watches, etc.) rather than credential-theft/financial-scam phishing, which is
this project's actual scope per the user-stories backlog — so some of that
gap reflects a scope difference (spam filtering vs. phishing detection), not
purely a detector weakness. The honest takeaway: PhishGuard's rule-based
approach is conservative and precision-oriented (rarely cries wolf on real
legitimate mail) but has real recall limits against varied, real-world
phishing it wasn't specifically tuned for — a fundamental limitation of
fixed keyword rules versus a learned model, and explicitly out of scope for
this project (see "Explicitly out of scope" in `CLAUDE.md`).

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

These checks can take a few seconds (WHOIS lookups especially), so they
don't run inline with the scan request. The result page loads immediately
with the offline analysis, then fetches `/history/<id>/network-check` in the
background via JavaScript and updates the risk score/flags in place once it
resolves — the request is only made if the email contained a URL at all.
That endpoint (and the scan form itself) is rate-limited to 20 requests per
minute per IP (`Flask-Limiter`) to protect the Safe Browsing quota and avoid
hammering WHOIS servers.

## Deployment (Render)

`render.yaml` deploys the app to [Render](https://render.com)'s free tier:

1. Push this repo to GitHub (already done if you're reading this from there).
2. In the Render dashboard: **New > Blueprint**, connect the repo. Render
   reads `render.yaml` and pre-fills the service (build command, start
   command, Python version).
3. `SECRET_KEY` is auto-generated by Render. `SAFE_BROWSING_API_KEY` is
   listed as a required secret but left blank (`sync: false`) — set it in
   the dashboard if you have one, or leave it empty to skip that check.
4. Deploy. Every subsequent push to the connected branch auto-deploys.

Two things specific to the free tier worth knowing:

- **The dev server (`python app.py`) is never used in production.** Render
  runs `gunicorn app:app` instead (see `requirements-render.txt` — gunicorn
  is Unix-only and deliberately kept out of `requirements.txt` since it
  can't install on Windows, which is what local development happens on here).
- **Scan history won't persist reliably.** Render's free web services use an
  ephemeral filesystem — SQLite data can be lost on redeploys or when the
  service spins down from inactivity. The live demo is fine for showing the
  analysis feature working end-to-end; don't rely on `/history` retaining
  data long-term without upgrading to a paid plan with a persistent disk (or
  swapping SQLite for a hosted database).
