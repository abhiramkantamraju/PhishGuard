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
- `detector.py` — the actual detection engine, pure functions, no Flask
  dependency:
  - keyword rules for urgency / credential requests / threats
  - URL extraction + checks: IP-address URLs, link shorteners, insecure
    `http://`, domain spoofing (brand name embedded in an unrelated domain),
    typo-squatting (Levenshtein distance 1, and leetspeak-style lookalike
    normalization e.g. `0`→`o`)
  - `analyze_text()` returns `(flags, score)`; `get_risk_level()` buckets the
    score into Safe / Suspicious / Dangerous
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
debugger).

## Feature status vs. the user-stories backlog

| Feature | Status |
|---|---|
| F1 Email text analysis (US1, US2) | Done — keyword rules in `detector.py` |
| F2 URL threat analysis (US3) | Partially done — shortener/IP/spoofing/typo-squat checks exist. **Not implemented**: Google Safe Browsing API blacklist check (K4) and WHOIS domain-age lookup (K5), both listed in the backlog as planned sub-tasks |
| F3 Scan history CRUD (US4/5/6) | Done — save, list, edit note, delete all exist in `app.py` |
| F4 Evidence package (US7) | Done — `evaluate_dataset.py` + results committed to README (76.75% accuracy on 800-email Kaggle set, 0 false positives, 23.25% false negatives) |

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
- **`venv/` isn't in `.gitignore`**. It isn't currently tracked, but nothing
  stops someone from `git add -A`-ing it in by accident. Add `venv/` and
  `*.pyc` explicitly.
- **Dataset filename**: `data/kaggle_phishing_email/phishing_dataset (1).xlsx`
  has a "(1)" suggesting a duplicate browser download. `data/` is gitignored
  (correct, it's a large third-party dataset) — but since it's not versioned,
  worth a one-line note in the README on exactly where to re-download it from
  if the folder is ever wiped (the Kaggle link is already in the README).
- **No CI**. Since the evaluator explicitly checks for test results, a small
  GitHub Actions workflow that runs `pytest` on every push would strengthen
  the evidence package (F4) with minimal effort.
- **Uncommitted work**: at last check, `.gitignore`, `README.md`,
  `detector.py`, `requirements-dev.txt`, and `templates/result.html` had
  local modifications, and `evaluate_dataset.py` + `sample_data/` were
  untracked entirely. Since the dataset evaluation script is the required
  evidence artifact (US7/F4), it should be committed and pushed, not left
  local-only. Run `git status` to check current state — this changes often.
- **Flat structure is fine for now.** At ~5 Python files this doesn't need an
  `app/` package or blueprints. Revisit only if routes/detector logic grow
  significantly past current scope.
