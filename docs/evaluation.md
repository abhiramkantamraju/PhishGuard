# Evaluation methodology and results

Everything here is reproducible from a clean checkout:

```bash
python build_realistic_dataset.py
python evaluate_dataset.py data/realistic_phishing/phishing_focused_holdout.csv --quiet
python scripts/calibrate.py
python scripts/breakdown.py
```

The sampling is seeded, so the generated CSVs are byte-identical on every machine.

---

## 1. Why there are several benchmarks

The project's original evidence was a Kaggle set on which PhishGuard scored 100%.
That number was not worth much: all 800 rows are repeats of 8 unique sentences, so
100% meant "the rules cover 8 sentences". Building a harder benchmark from real
corpora then produced the opposite problem — an aggregate accuracy of 51.8% that
made the detector look far worse than it is, because most of that benchmark's
"phishing" class is not phishing.

So there are four, each answering a different question.

| Benchmark | Question it answers |
|---|---|
| **Phishing-focused, holdout split** | How well does this detect the thing it is built to detect, on data it was not tuned on? |
| Phishing-focused, tuning split | Same, on the data the rules *were* developed against — the gap between the two shows whether anything was over-fitted. |
| Mixed-source | What happens when the target is widened to all unwanted mail, including spam? |
| Legitimate-marketing stress test | Does it cry wolf on real promotional email, which reuses phishing's urgency language? |

## 2. The corpora

All public, downloaded on demand by `build_realistic_dataset.py`, compiled by
[rokibulroni/Phishing-Email-Dataset](https://github.com/rokibulroni/Phishing-Email-Dataset).
Nothing is committed to git — `data/` is gitignored.

| Corpus | Rows | Contents |
|---|---|---|
| Enron | 29,767 | Enron-Spam: real business email plus spam |
| CEAS_08 | 39,154 | CEAS 2008 Spam Challenge, mixed |
| SpamAssasin | 5,809 | Apache SpamAssassin public corpus, mixed |
| Nazario | 1,565 | Jose Nazario's phishing corpus — all phishing |
| Nigerian_Fraud | 3,332 | Advance-fee ("419") fraud — all phishing |

Each row is reduced to `subject + "\n\n" + body`. Sender headers are **not**
included, deliberately: only two of the five corpora have a sender column, and both
are phishing corpora. Including them would let the detector's header rules key on a
field that exists only for the positive class — leakage that would inflate every
number here.

## 3. The phishing-focused benchmark

- **Positive class:** every row of Nazario and Nigerian_Fraud (4,897 credential-theft
  and advance-fee phishing emails).
- **Negative class:** the rows Enron, SpamAssassin and CEAS label legitimate
  (37,194 real business and personal emails).
- Both shuffled with seed 11, then split into two disjoint 1,500-per-class blocks:
  **tuning** (3,000 emails) and **holdout** (3,000 emails).

Rules and thresholds were developed against the tuning split only. The README quotes
the holdout numbers.

### Results

| Split | Accuracy | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|---|
| Holdout | 89.53% | 97.06% | 81.53% | 88.62% | 2.47% |
| Tuning | 88.90% | 96.57% | 80.67% | 87.90% | 2.87% |

The holdout split scores marginally *higher* than the split the rules were tuned on,
which is the result you want to see: it indicates the rules capture general phishing
behaviour rather than memorising the tuning data.

Holdout confusion matrix:

```
  True positives  (phishing caught):     1223
  False negatives (phishing missed):      277  (18.47% of phishing)
  True negatives  (legitimate cleared):  1463
  False positives (legitimate flagged):    37  ( 2.47% of legitimate)
```

## 4. Threshold calibration

`scripts/calibrate.py` sweeps every possible score cut-off. Holdout split:

| Threshold | Precision | Recall | F1 | Accuracy | FP rate | |
|---|---|---|---|---|---|---|
| 1 | 95.28% | 87.47% | 91.21% | 91.57% | 4.33% | |
| 2 | 95.28% | 87.47% | 91.21% | 91.57% | 4.33% | |
| **3** | **97.06%** | **81.53%** | **88.62%** | **89.53%** | **2.47%** | ← Suspicious (in use) |
| 4 | 99.78% | 59.27% | 74.36% | 79.57% | 0.13% | |
| 5 | 99.77% | 57.53% | 72.98% | 78.70% | 0.13% | |
| **6** | 99.73% | 24.40% | 39.21% | 62.17% | 0.07% | ← Dangerous |
| 7 | 100.00% | 20.13% | 33.52% | 60.07% | 0.00% | |

**Threshold 2 maximises F1 (91.21%), and threshold 3 was chosen anyway.** The reason
is the fourth benchmark. At threshold 2, a single weight-2 category is enough to call
an email phishing — one urgent phrase, or one impersonal greeting. Run that against
the legitimate-marketing set and **5 of 10** genuine promotional emails are flagged.
At threshold 3 it is **0 of 10**, because an email now needs either one strong signal
(a credential request, an account threat, a deceptive link) or two independent weaker
ones.

The trade is explicit: **−2.6 points of F1 in exchange for cutting the false-positive
rate on legitimate mail by 43%**, and eliminating it entirely on real marketing copy.
For a tool a person consults about their own inbox, a false alarm costs more than a
miss — a miss leaves them where they started, a false alarm teaches them to ignore
the tool.

The Dangerous threshold of 6 means "two independent strong categories". It is a
presentation boundary, not a classification one: anything from 3 up is reported as
phishing.

## 5. The mixed-source benchmark, and why its number is misleading

4,000 emails sampled (seed 42) across all five corpora, each row keeping its source
corpus's own label. Result:

| Accuracy | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|
| 52.55% | 82.74% | 13.13% | 22.66% | 3.08% |

13% recall looks damning. `scripts/breakdown.py` shows where it comes from:

```
corpus               rows   share  caught   recall
CEAS_08              1125  53.1%       6    0.5%   (spam)
Enron                 669  31.6%      56    8.4%   (spam)
Nigerian_Fraud        166   7.8%     157   94.6%   (phishing)
SpamAssasin            81   3.8%      22   27.2%   (spam)
Nazario                77   3.6%      37   48.1%   (phishing)

  credential-theft / advance-fee phishing:  243 rows (11.5%), recall 79.84%
  generic commercial spam:                 1875 rows (88.5%), recall  4.48%
```

**88.5% of the positive class is generic commercial spam** — pharmacy ads, stock
pump-and-dumps, replica watches, dating spam. PhishGuard catches 79.84% of the actual
phishing in this same benchmark and 4.48% of the spam, and the aggregate is dominated
by the latter.

That is a scope difference, not a hidden defect: the user-story backlog scopes this
project to phishing (credential theft and financial fraud), and spam filtering is a
different problem with different signals. The benchmark is kept, and its bad number
published, because dropping a benchmark once it stops flattering you is how projects
end up reporting only convenient results. What would be wrong is presenting 52.55% as
"PhishGuard's accuracy" without the breakdown above.

## 6. The legitimate-marketing stress test

Ten synthetic-but-realistic promotional emails (`sample_data/legitimate_marketing_emails.csv`):
flash sales, trial-expiry reminders, policy updates, renewal notices. They exist
because legitimate marketing copy uses exactly the same urgency vocabulary as
phishing — "act now", "limited time", "expires today".

| Version | False positives |
|---|---|
| Original detector | 4 of 10 (40%) |
| After removing three over-broad urgency phrases | 4 of 10 (40%) |
| Current (weighted categories, threshold 3) | **0 of 10** |

The last remaining false positive was a renewal notice saying "update payment details
anytime from your account settings", matched by the `verify_records` rule. Making the
possessive mandatory ("update **your** payment details") removed it and cost 0.3
points of recall on the phishing corpora — a good trade, and the kind of decision the
per-rule measurement in `scripts/calibrate.py --rules` exists to support.

## 7. The Kaggle set

800 rows, 8 unique sentences, 100% accuracy. Kept because it was the project's
original evidence artifact and the result should not silently disappear, but it
measures rule coverage of 8 sentences and nothing more. One of its phishing templates
("Urgent: Update your BVN immediately to avoid restriction") was briefly missed after
the scoring rework, which is what prompted two genuinely useful new rules:
`identity_number_request` (BVN / Aadhaar / SSN / OTP / CVV) and `avoid_consequence`
("to avoid suspension"). Both produced zero false positives across 3,000 legitimate
emails.

## 8. Known limitations

1. **Fixed rules cannot generalise to unseen phrasing.** A phishing email that avoids
   every phrase in the rule set scores Safe. This is the fundamental cost of a
   rule-based approach, accepted in exchange for being fully inspectable and
   self-explaining. ML classification is explicitly out of scope for the project.
2. **The rules were developed against 2000s-era corpora.** Modern phishing leans on
   channels these corpora barely contain — QR codes, OAuth consent phishing, SMS
   handoff. A few rules (`identity_number_request`) were added on precision grounds
   to cover current patterns, but the corpora cannot validate them.
3. **The negative class is mostly corporate email.** Enron and CEAS ham skew towards
   business correspondence. False positives on other kinds of legitimate mail
   (transactional receipts, mailing lists in other languages) are less well measured;
   the marketing stress test is a partial answer, and it is only ten emails.
4. **Header rules are unmeasured by these benchmarks** because the corpora are
   subject+body only. They are covered by unit tests in `tests/test_headers.py`
   instead, which verifies behaviour but not real-world hit rate.
5. **English only.** Every pattern is English; a non-English phishing email will
   score close to zero.
