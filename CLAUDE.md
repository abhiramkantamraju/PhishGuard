# PhishGuard

## End goal

A Flask web app that helps a user paste an email and immediately learn whether
it's a phishing attempt: it analyzes the text and any embedded URLs, returns a
Safe / Suspicious / Dangerous score with a plain-English list of every red
flag detected, and saves each scan to SQLite so results can be reviewed later.

This is a solo university project (course: **IT Project IV**, instructor Dr.
Denilton Luiz Darold; student: Abhiram). The evaluator's acceptance bar is: a
working prototype, a public GitHub repo, and documented accuracy results
against a real phishing dataset. Source of truth for scope: `PhishGuard_User_Stories_.docx`
one level up, in the parent `PhishGuard` folder (not this repo).

## Architecture

- `app.py` — Flask routes: `/` (paste + analyze), `/history` (list past
  scans), `/history/<id>/edit` (add a note), `/history/<id>/delete`. SQLite
  db is `phishguard.db` (gitignored, recreated by `init_db()` on first run).
- `detector.py` — the actual detection engine:
  - `analyze_text()` is pure (no I/O), used by the live app, the test suite,
    and `evaluate_dataset.py`. Keyword rules for urgency / credential
    requests / threats / prize-lottery scams. URL extraction + checks:
    IP-address URLs, link shorteners, insecure `http://`, domain spoofing
    (brand name embedded in an unrelated domain), typo-squatting
    (Levenshtein distance 1, and leetspeak-style lookalike normalization
    e.g. `0`→`o`). Returns `(flags, score)`; `get_risk_level()` buckets the
    score into Safe / Suspicious / Dangerous.
  - `analyze_urls_network()` is the network-based counterpart — Google Safe
    Browsing + WHOIS domain-age checks. Deliberately kept separate from
    `analyze_text()` so the pure path stays fast/offline/deterministic for
    tests and dataset evaluation; only `app.py` calls it, per live scan.
    Every failure mode (no API key, network error, WHOIS timeout) degrades
    to "no flag" rather than raising. WHOIS lookups run on a worker thread
    with a hard timeout (`check_domain_age`) since `python-whois` doesn't
    reliably honor socket-level timeouts itself.
- `evaluate_dataset.py` — CLI script that runs `analyze_text` over a labeled
  CSV/XLSX (`label`, `email_text` columns) and reports accuracy / false
  positive / false negative rates. This is the evidence artifact for the
  course evaluator.
- `templates/` — Jinja templates for the four routes above. `static/` exists
  but is currently empty (no custom CSS/JS yet).
- `test_detector.py` — pytest unit tests for `detector.py`.

## Setup / run / test

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py               # http://127.0.0.1:5000
```

```bash
pip install -r requirements-dev.txt
pytest
python evaluate_dataset.py sample_data/sample_emails.csv
```

`SECRET_KEY` should be set in any persistent deployment (CSRF). `FLASK_DEBUG=1`
is dev-only — never in production (enables arbitrary code execution via the
debugger). `SAFE_BROWSING_API_KEY` is optional — without it the Safe
Browsing check is silently skipped (WHOIS domain-age still runs).

## Feature status vs. the user-stories backlog

| Feature | Status |
|---|---|
| F1 Email text analysis (US1, US2) | Done — keyword rules in `detector.py`, including credential-expiry and prize/lottery-scam categories added to close a recall gap found via dataset analysis |
| F2 URL threat analysis (US3) | Done — shortener/IP/spoofing/typo-squat checks (offline, in `analyze_text()`) plus Google Safe Browsing (K4) and WHOIS domain-age (K5) checks (network, in `analyze_urls_network()`, live app only) |
| F3 Scan history CRUD (US4/5/6) | Done — save, list, edit note, delete all exist in `app.py` |
| F4 Evidence package (US7) | Done — `evaluate_dataset.py` + results committed to README (100% accuracy on the 800-row Kaggle set, 0 false positives, 0 false negatives — see README for the important caveat that this dataset is only 8 unique templated sentences) |

Explicitly out of scope per the backlog: ML/AI classification, live email
scanning, browser extension, mobile app, user accounts.

## Structural notes / recommendations

- **Nested folder confusion**: the workspace root (`D:\Masters Berlin\PhishGuard`)
  contains this git repo in a subfolder also named `PhishGuard`, plus loose
  files that aren't part of the repo: an empty `GEMINI.md`, a 12-byte
  `PhishGuard.txt`, and `PhishGuard_User_Stories_.docx`. Worth either moving
  the docx into a `docs/` folder inside the repo (so it's versioned with the
  code it describes) or deleting the stray `.txt`/empty `.md` if they're not
  needed.
- **Dataset filename**: `data/kaggle_phishing_email/phishing_dataset (1).xlsx`
  has a "(1)" suggesting a duplicate browser download. `data/` is gitignored
  (correct, it's a large third-party dataset) — the Kaggle link to
  re-download it is already in the README.
- **Flat structure is fine for now.** At ~5 Python files this doesn't need an
  `app/` package or blueprints. Revisit only if routes/detector logic grow
  significantly past current scope.
- **Run `git status` before relying on any of the above.** This file is
  hand-maintained alongside the code, not regenerated automatically, so it
  can drift — check current repo state rather than trusting this file blindly
  for anything time-sensitive (uncommitted changes, CI status, etc).
