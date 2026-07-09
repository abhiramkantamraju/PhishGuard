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
