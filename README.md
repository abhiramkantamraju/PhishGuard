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
- Correct predictions: 614
- Accuracy: 76.75%
- False positives: 0 (0.00%)
- False negatives: 186 (23.25%)

Interpretation: PhishGuard is conservative in its current rule-based form. It
does not wrongly flag legitimate emails in this dataset, but it misses some
phishing emails that do not contain the current keywords or URL warning signs.
