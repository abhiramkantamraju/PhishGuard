# Course deliverables — IT Project IV

Status of each thing the evaluator asked for.

## Acceptance criteria

| Requirement | Status | Where |
|---|---|---|
| Working prototype | ✅ | `python app.py` — no API keys, no network, no database server needed |
| Public GitHub repository | ✅ | https://github.com/abhiramkantamraju/PhishGuard |
| Documented accuracy results against a real phishing dataset | ✅ | [`evaluation.md`](evaluation.md); reproduce with `python build_realistic_dataset.py && python evaluate_dataset.py …` |
| Live deployed demo | ✅ | https://phishguard-qbkm.onrender.com — Render free tier. Spins down after 15 minutes idle, and scan history does not survive a spin-down or redeploy (see README → Deployment) |

## Feature backlog

Scope source of truth: `PhishGuard_User_Stories_.docx` (kept with the submission
documents at the workspace root, outside the repo).

| Feature | User stories | Status |
|---|---|---|
| F1 Email text analysis | US1, US2 | ✅ 30 rules across 12 weighted categories, each measured against real corpora before inclusion |
| F2 URL threat analysis | US3, K4, K5 | ✅ Offline: IP hosts, shorteners, `@` tricks, abusive TLDs, brand impersonation, typo-squats, homographs, punycode. Network: Google Safe Browsing + WHOIS domain age |
| F3 Scan history CRUD | US4, US5, US6 | ✅ Create (scan), Read (list, search, filter, permalink detail), Update (note), Delete — plus CSV/JSON export |
| F4 Evidence package | US7 | ✅ Four benchmarks with methodology, a held-out split, per-rule measurement and per-corpus breakdown |

Explicitly out of scope per the backlog: ML/AI classification, live mailbox scanning,
browser extension, mobile app, user accounts.

## Beyond the backlog

Added because they materially improve the prototype, not because a story asked:

- Sender-header analysis (From vs Reply-To vs display name) — the strongest offline
  signal available when someone pastes a whole email.
- A "How it works" page generated from the same category registry the detector scores
  against, so the explanation cannot drift from the code.
- Four one-click sample emails, so the app can be demonstrated without hunting for
  real phishing.
- `/healthz`, friendly 404/429/500 pages, automatic schema migration, dark mode,
  and a responsive layout that works on a phone.

## Evidence artifacts

| Artifact | Location |
|---|---|
| Automated tests | `pytest` — 198 tests, ~1s, no network access. CI runs them on Python 3.11 and 3.12 |
| Accuracy evidence | `evaluate_dataset.py` + [`evaluation.md`](evaluation.md) |
| Threshold calibration | `python scripts/calibrate.py` |
| Per-rule measurement | `python scripts/calibrate.py --rules` |
| Per-corpus recall breakdown | `python scripts/breakdown.py` |
| CRUD workflow evidence | `PhishGuard_CRUD_Submission.pdf` (submission documents, outside the repo) |
| Automated-testing submission note | `PhishGuard_Automated_Tests_Submission.pdf` (ditto) |
| Demo video | `02_Demo.mp4`, in `BIT6_4_Practical_Project_Kamtamraju.zip` (ditto) — one continuous run covering the scan flow, persistence across a server restart, a rejected invalid submission, all four CRUD operations and `198 passed` |
| Final report | `BIT6_4_Final_Project_Report_Kamtamraju.pdf` (ditto) |

## Optional extras

1. **Set `SAFE_BROWSING_API_KEY`** to enable the Google Safe Browsing link check.
   Without it that one check is skipped silently; everything else, including the WHOIS
   domain-age check, works.
2. **Move to a paid instance with a persistent disk** and point `PHISHGUARD_DB` at it,
   if hosted scan history needs to survive a spin-down or redeploy.
