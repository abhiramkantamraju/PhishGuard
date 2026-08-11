# PhishGuard documentation

| Document | What's in it |
|---|---|
| [`architecture.md`](architecture.md) | Module map, the path a scan takes, and the design decisions behind it |
| [`evaluation.md`](evaluation.md) | Benchmark methodology, corpora, threshold calibration, results and known limitations |
| [`submission-checklist.md`](submission-checklist.md) | Course deliverables and what still needs a manual step |

The project [`README.md`](../README.md) is the starting point: results, setup and a
summary of how the detection works.

## Where the course submission documents live

The Word and PDF submission artifacts (`PhishGuard_Final_Report`,
`PhishGuard_CRUD_Submission`, `PhishGuard_Automated_Tests_Submission`,
`PhishGuard_User_Stories_`, the risk register and the AI-use declaration) sit in the
workspace folder **above** this repository rather than inside it. They are Word and
PDF binaries that are edited outside git and regenerated for each submission, so
versioning them alongside the code would add megabytes of unreadable diffs without
making either easier to review.

`submission-checklist.md` records which artifact covers which requirement, so the
mapping is in the repository even when the binaries aren't.
