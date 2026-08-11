# Architecture

## Layout

```
app.py                     Flask routes, SQLite persistence, presentation
phishguard/                the detection engine — no Flask, no I/O except network.py
  __init__.py              public API; import from here, not the submodules
  rules.py                 the rule registry: what to look for, what it's worth
  urls.py                  URL/domain inspection (offline)
  headers.py               sender-header consistency (offline)
  scoring.py               matches -> findings -> score -> risk level
  network.py               Safe Browsing + WHOIS (the only outbound calls)
  validation.py            input validation
templates/                 Jinja templates, all extending base.html
static/                    style.css, app.js, favicon.svg — no build step, no CDN
tests/                     pytest suite, 198 tests, no network access
scripts/
  corpora.py               download and split the evaluation corpora
  calibrate.py             threshold sweep and per-rule measurement
  breakdown.py             recall per source corpus
evaluate_dataset.py        CLI: measure against a labelled dataset
build_realistic_dataset.py CLI: build the benchmark CSVs
```

The dependency direction is one-way: `app.py` imports `phishguard`, never the
reverse. Nothing in `phishguard/` knows a web request exists, which is why the whole
detector can be tested and benchmarked without a test client or a running server.

## The path a scan takes

```
POST /
  │
  ├─ validate_email_input()          reject empty / whitespace / oversized input
  │                                  → 400 and re-render, nothing analysed or saved
  │
  ├─ analyze(email_text)             pure, offline, deterministic
  │    ├─ TEXT_RULES                 30 regex rules, each tagged with a category
  │    ├─ ATTACHMENT_MENTION_PATTERN risky attachment filenames
  │    ├─ check_sender_headers()     From vs Reply-To vs display name
  │    ├─ _url_findings()            IP hosts, shorteners, '@' tricks, TLDs, spoofing
  │    ├─ _dedupe()                  one report per phrase per category
  │    └─ score = Σ weight of each *distinct* category that fired
  │
  ├─ INSERT INTO scans               email, flat flags, structured findings (JSON),
  │                                  score, risk level, timestamp
  │
  └─ 302 → /history/<id>?new=1       post-redirect-get: permalink, refresh-safe

GET /history/<id>
  │
  ├─ render the verdict + findings grouped by category
  │
  └─ if the email had links and they haven't been checked yet:
       fetch POST /history/<id>/network-check   (in the background, from JS)
          ├─ Safe Browsing (5s timeout, skipped without an API key)
          ├─ WHOIS domain age (5s timeout, max 3 domains, worker thread)
          ├─ merge into the stored findings, set network_checked = 1
          └─ JSON back; the page updates the score and risk badge in place
```

## Design decisions worth knowing

**Categories carry the score, not rules.** Each category contributes its weight at
most once per email, so an email that trips four phrasings of "verify your account"
scores the same as one that trips a single phrasing. Without this, a verbose sender
inflates the score and the thresholds stop meaning anything. See `scoring.py`.

**Network checks are separate from `analyze()`.** `analyze()` must stay fast, offline
and deterministic — it runs 3,000 times in a benchmark and inside every test.
`network.py` is the only module that makes outbound calls, and every failure mode
there (no key, connection error, WHOIS timeout, malformed JSON) degrades to "no
finding" rather than raising. A scan must succeed with the internet unplugged.

**Link checks run after the response, not during it.** WHOIS can take seconds. The
scan page renders immediately with the offline analysis, then fetches
`/history/<id>/network-check`. That endpoint is idempotent — the `network_checked`
column stops a refresh or a second tab from double-counting the same flags.

**One database connection per request.** Held on Flask's `g`, closed in
`teardown_appcontext`. The previous version opened and closed a connection per query
by hand, which leaked one whenever a route raised between open and close.

**Findings are stored structured *and* flat.** The `findings` column holds JSON
(rule, category, message, matched text) so the history page can render the same
grouped layout as a fresh scan; `flags` keeps the newline-joined messages for
backwards compatibility with rows written by earlier versions. `analysis_from_row()`
falls back to `flags` when `findings` is empty, and silently drops findings whose
category no longer exists — so deleting a rule can't break the history page.

**Schema migrations are explicit.** `MIGRATIONS` in `app.py` maps a column name to
the `ALTER TABLE` that adds it; `init_db()` compares against `PRAGMA table_info` and
applies what's missing. SQLite has no `ADD COLUMN IF NOT EXISTS`.

**`init_db()` runs at import time**, not under `if __name__ == "__main__"`. Gunicorn
imports the module and calls the `app` object directly, so it never executes the
`__main__` block.

**The UI has no build step and no external requests.** System font stack, one CSS
file driven by custom properties, one small JS file. Everything degrades without
JavaScript except the background link check: the form submits, the history table
renders, deletes work.

## Test layout

| File | Covers |
|---|---|
| `tests/test_urls.py` | URL extraction, hostname parsing, spoofing, homographs, malformed-URL regression |
| `tests/test_rules.py` | Registry integrity: unique keys, real categories, message templates, a canary that no rule fires on ordinary correspondence |
| `tests/test_scoring.py` | The scoring model: category-once weighting, dedupe, thresholds, informational findings |
| `tests/test_headers.py` | Sender-header parsing and every mismatch rule, plus the ordinary cases that must not fire |
| `tests/test_network.py` | Safe Browsing and WHOIS with injected fakes; every failure mode |
| `tests/test_app.py` | Routes, CRUD, search/filter, export, health, error pages, CSRF, rate limiting, XSS escaping, schema migration |
| `tests/test_scan_workflow.py` | The must-have workflow end to end (US1) — the course's automated-testing evidence |
| `tests/test_evaluate_dataset.py` | The metric arithmetic itself |

No test touches the network or the real `phishguard.db`.
