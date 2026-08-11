"""
PhishGuard web app.

Routes, persistence and presentation only — every judgement about whether an
email is phishing lives in the `phishguard` package, so this module stays a thin
shell around it and the detection logic stays testable without a request
context.
"""

import csv
import io
import json
import os
import secrets
import sqlite3
from datetime import datetime

from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

from phishguard import (
    CATEGORIES,
    DANGEROUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    Analysis,
    Finding,
    analyze,
    extract_urls,
    get_risk_level,
    network_findings,
)
from phishguard.validation import MAX_EMAIL_LENGTH, validate_email_input

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# Path is configurable so a deployment can point it at a mounted disk instead of
# the ephemeral working directory (see README → Deployment).
app.config["DATABASE"] = os.environ.get("PHISHGUARD_DB", "phishguard.db")
csrf = CSRFProtect(app)

# In-memory rate-limit storage is fine for this single-process demo app; a
# multi-worker deployment would need a shared backend (Redis, Memcached).
limiter = Limiter(get_remote_address, app=app, default_limits=[])

SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")
SCAN_RATE_LIMIT = "20 per minute"
HISTORY_PAGE_SIZE = 50

RISK_LEVELS = ("Safe", "Suspicious", "Dangerous")

# Ready-made examples so the app can be demonstrated without hunting for a real
# phishing email. Rendered as one-click buttons on the scan form.
SAMPLE_EMAILS = [
    {
        "key": "credential",
        "label": "Credential phishing",
        "description": "Impersonates a provider and pushes you at a lookalike login page.",
        "text": (
            "From: PayPal Service <service@paypal-secure-billing.tk>\n"
            "Reply-To: recovery.desk@mail.ru\n"
            "Subject: Your account has been limited\n\n"
            "Dear Customer,\n\n"
            "We detected unusual sign-in activity on your account, and your account "
            "has been limited as a precaution. You must verify your account within 24 "
            "hours to avoid permanent suspension.\n\n"
            "Click the link below to confirm your details:\n"
            "http://paypal-secure-billing.tk/login/verify?id=8812\n\n"
            "Failure to do so will result in closure of your account.\n\n"
            "PayPal Security Team"
        ),
    },
    {
        "key": "advance_fee",
        "label": "Advance-fee scam",
        "description": "The classic inheritance letter: a large sum, a stranger, a share for you.",
        "text": (
            "Subject: STRICTLY CONFIDENTIAL BUSINESS PROPOSAL\n\n"
            "Dear Friend,\n\n"
            "I am Barrister Michael Okoro, a solicitor at law. I write concerning my late "
            "client who died in a motor accident leaving the sum of USD 12,500,000.00 in a "
            "dormant account with a security company here.\n\n"
            "I am contacting you as the next of kin to this fund. 30% of the total sum will "
            "be for you for your assistance. This transaction must be treated as strictly "
            "confidential.\n\n"
            "Please reply to me at barr.okoro.chambers@yahoo.com with your full details for "
            "the transfer of the funds.\n\n"
            "God bless you.\n"
            "Barrister Michael Okoro"
        ),
    },
    {
        "key": "it_helpdesk",
        "label": "Mailbox quota phishing",
        "description": "Pretends to be your own IT department; the giveaway is in the link.",
        "text": (
            "Subject: [IMPORTANT] Mailbox storage limit exceeded\n\n"
            "Dear Email User,\n\n"
            "Your mailbox is almost full and you have exceeded your storage quota. Your "
            "email will be closed if you do not update your account information today.\n\n"
            "Please enter your username and password on our webmail upgrade page to "
            "re-validate your mailbox: http://webmail-upgrade.example-support.xyz/owa\n\n"
            "Regards,\n"
            "IT Help Desk / System Administrator"
        ),
    },
    {
        "key": "legitimate",
        "label": "Legitimate email",
        "description": "A real service notice — urgent-sounding, but nothing actually wrong.",
        "text": (
            "From: Notifications <no-reply@github.com>\n"
            "Subject: Your monthly usage summary\n\n"
            "Hi Abhiram,\n\n"
            "Here is your usage summary for last month. Your plan renews on the 1st, and "
            "you can manage your plan or update payment details anytime from your account "
            "settings at https://github.com/settings/billing.\n\n"
            "No action is required if everything looks correct.\n\n"
            "The GitHub Team"
        ),
    },
]


# --- Persistence ------------------------------------------------------------

def get_db_connection():
    """
    The request-scoped SQLite connection, opened on first use.

    Stored on `g` and closed in `teardown_appcontext` so a single request never
    opens several connections, and so a route that raises can't leak one — the
    previous version opened and closed a connection per query by hand.
    """
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db_connection(exception=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_text TEXT NOT NULL,
    flags TEXT NOT NULL,
    findings TEXT NOT NULL DEFAULT '[]',
    score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    network_checked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS scans_risk_level ON scans (risk_level);
"""

# Columns added after the first release, with the SQL to add them. SQLite can't
# add a column conditionally, so existing local databases are migrated by
# comparing against PRAGMA table_info.
MIGRATIONS = {
    "network_checked": "ALTER TABLE scans ADD COLUMN network_checked INTEGER NOT NULL DEFAULT 0",
    "findings": "ALTER TABLE scans ADD COLUMN findings TEXT NOT NULL DEFAULT '[]'",
}


def init_db():
    """Create the schema if needed and bring an older database up to date."""
    with app.app_context():
        connection = get_db_connection()
        connection.executescript(SCHEMA)
        existing = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        for column, statement in MIGRATIONS.items():
            if column not in existing:
                connection.execute(statement)
        connection.commit()


# Run at import time, not only under `__main__`: a production WSGI server
# (gunicorn) imports this module and calls the `app` object directly, so it
# never executes the `__main__` block at the bottom.
init_db()


def serialize_findings(findings):
    return json.dumps([
        {"rule": f.rule, "category": f.category, "message": f.message, "match": f.match}
        for f in findings
    ])


def deserialize_findings(raw):
    """
    Rebuild `Finding` objects from a stored row.

    Falls back to the newline-joined `flags` column for scans saved before
    structured findings existed, and skips any category that no longer exists so
    that removing a rule can't break the history page.
    """
    try:
        records = json.loads(raw or "[]")
    except (TypeError, ValueError):
        records = []
    return [
        Finding(r.get("rule", ""), r["category"], r["message"], r.get("match", ""))
        for r in records
        if r.get("category") in CATEGORIES
    ]


def analysis_from_row(row):
    """An `Analysis`-shaped view of a stored scan, for the shared template."""
    # `.keys()` is required: sqlite3.Row's `in` operator searches values, not
    # column names, so `"findings" in row` would silently do the wrong thing.
    columns = row.keys()  # noqa: SIM118
    findings = deserialize_findings(row["findings"] if "findings" in columns else "[]")
    if not findings and row["flags"]:
        findings = [
            Finding("legacy", "informational", message)
            for message in row["flags"].split("\n") if message
        ]
    return Analysis(findings=findings, score=row["score"])


# --- Routes -----------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@limiter.limit(SCAN_RATE_LIMIT, methods=["POST"])
def index():
    if request.method == "POST":
        # Validation lives in phishguard.validation so it can be unit tested
        # without a request context; this route only decides how to present the
        # error it returns.
        email_text, error = validate_email_input(request.form.get("email_text"))
        if error:
            return render_template(
                "index.html", error=error, email_text=email_text,
                samples=SAMPLE_EMAILS, max_length=MAX_EMAIL_LENGTH,
            ), 400

        # Only the offline checks run here so the page responds immediately.
        # Safe Browsing and WHOIS are network calls that can take seconds; the
        # scan page fetches those afterwards via /history/<id>/network-check.
        analysis = analyze(email_text)
        connection = get_db_connection()
        cursor = connection.execute(
            """
            INSERT INTO scans (email_text, flags, findings, score, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email_text,
                "\n".join(analysis.flags),
                serialize_findings(analysis.findings),
                analysis.score,
                analysis.risk_level,
                datetime.now().strftime("%Y-%m-%d %H:%M"),
            ),
        )
        connection.commit()

        # Redirect after POST: the result gets a shareable permalink, and a
        # browser refresh re-reads the scan instead of re-submitting the form.
        return redirect(url_for("scan_detail", scan_id=cursor.lastrowid, new=1))

    return render_template(
        "index.html", samples=SAMPLE_EMAILS, max_length=MAX_EMAIL_LENGTH,
    )


@app.route("/history/<int:scan_id>")
def scan_detail(scan_id):
    connection = get_db_connection()
    scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        return render_template("not_found.html", scan_id=scan_id), 404

    return render_template(
        "result.html",
        scan=scan,
        analysis=analysis_from_row(scan),
        is_new=request.args.get("new") == "1",
        check_links=bool(extract_urls(scan["email_text"])) and not scan["network_checked"],
    )


@app.route("/history/<int:scan_id>/network-check", methods=["POST"])
@limiter.limit(SCAN_RATE_LIMIT)
def network_check(scan_id):
    connection = get_db_connection()
    scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    # Idempotent: the `network_checked` guard stops a repeat call (a refresh, a
    # second tab) from adding the same flags and score twice.
    if scan["network_checked"]:
        return jsonify({
            "flags": [], "findings": [],
            "score": scan["score"], "risk_level": scan["risk_level"],
        })

    urls = extract_urls(scan["email_text"])
    new_findings, network_score = network_findings(urls, api_key=SAFE_BROWSING_API_KEY)

    existing = analysis_from_row(scan)
    combined = existing.findings + new_findings
    combined_score = scan["score"] + network_score
    combined_risk_level = get_risk_level(combined_score)

    connection.execute(
        """
        UPDATE scans
           SET flags = ?, findings = ?, score = ?, risk_level = ?, network_checked = 1
         WHERE id = ?
        """,
        (
            "\n".join(f.message for f in combined),
            serialize_findings(combined),
            combined_score,
            combined_risk_level,
            scan_id,
        ),
    )
    connection.commit()

    return jsonify({
        "flags": [f.message for f in new_findings],
        "findings": [
            {
                "message": f.message,
                "category": f.category,
                "category_label": f.category_label,
                "advice": f.advice,
            }
            for f in new_findings
        ],
        "score": combined_score,
        "risk_level": combined_risk_level,
    })


def query_history(search="", risk=""):
    """Rows for the history page, filtered by free-text search and risk level."""
    sql = "SELECT * FROM scans"
    conditions, parameters = [], []

    if search:
        conditions.append("(email_text LIKE ? OR note LIKE ? OR flags LIKE ?)")
        parameters.extend([f"%{search}%"] * 3)
    if risk in RISK_LEVELS:
        conditions.append("risk_level = ?")
        parameters.append(risk)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY id DESC LIMIT ?"
    parameters.append(HISTORY_PAGE_SIZE)

    return get_db_connection().execute(sql, parameters).fetchall()


@app.route("/history")
def history():
    search = (request.args.get("q") or "").strip()
    risk = request.args.get("risk") or ""
    scans = query_history(search, risk)

    totals = {
        row["risk_level"]: row["count"]
        for row in get_db_connection().execute(
            "SELECT risk_level, COUNT(*) AS count FROM scans GROUP BY risk_level"
        )
    }

    return render_template(
        "history.html",
        scans=scans,
        search=search,
        risk=risk,
        risk_levels=RISK_LEVELS,
        totals=totals,
        total_count=sum(totals.values()),
        page_size=HISTORY_PAGE_SIZE,
    )


@app.route("/history/<int:scan_id>/edit", methods=["GET", "POST"])
def edit_scan(scan_id):
    connection = get_db_connection()
    scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        return render_template("not_found.html", scan_id=scan_id), 404

    if request.method == "POST":
        note = (request.form.get("note") or "").strip()
        if len(note) > 2000:
            return render_template(
                "edit_scan.html", scan=scan, note=note,
                error="Note is too long (max 2000 characters).",
            ), 400
        connection.execute("UPDATE scans SET note = ? WHERE id = ?", (note, scan_id))
        connection.commit()
        flash("Note saved." if note else "Note cleared.", "success")
        return redirect(url_for("scan_detail", scan_id=scan_id))

    return render_template("edit_scan.html", scan=scan, note=scan["note"] or "")


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    connection = get_db_connection()
    cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    connection.commit()
    flash(
        f"Scan #{scan_id} deleted." if cursor.rowcount else f"Scan #{scan_id} no longer exists.",
        "success" if cursor.rowcount else "error",
    )
    return redirect(url_for("history"))


@app.route("/history/export.<string:file_format>")
def export_history(file_format):
    """Download the whole scan history as CSV or JSON."""
    if file_format not in {"csv", "json"}:
        return render_template("not_found.html", scan_id=None), 404

    rows = get_db_connection().execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    stamp = datetime.now().strftime("%Y%m%d-%H%M")

    if file_format == "json":
        payload = [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "risk_level": row["risk_level"],
                "score": row["score"],
                "note": row["note"] or "",
                "email_text": row["email_text"],
                "findings": [
                    {"category": f.category, "category_label": f.category_label,
                     "message": f.message}
                    for f in analysis_from_row(row).findings
                ],
            }
            for row in rows
        ]
        return Response(
            json.dumps(payload, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="phishguard-history-{stamp}.json"',
            },
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "created_at", "risk_level", "score", "note", "flags", "email_text"])
    for row in rows:
        writer.writerow([
            row["id"], row["created_at"], row["risk_level"], row["score"],
            row["note"] or "", " | ".join(row["flags"].split("\n")), row["email_text"],
        ])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phishguard-history-{stamp}.csv"'},
    )


@app.route("/how-it-works")
def how_it_works():
    """
    What each category means and how the score adds up.

    Built from the same `CATEGORIES` registry the detector scores against, so
    the explanation can't drift out of step with the rules.
    """
    categories = sorted(
        (c for c in CATEGORIES.values() if c.weight > 0),
        key=lambda c: (-c.weight, c.label),
    )
    return render_template(
        "how_it_works.html",
        categories=categories,
        suspicious_threshold=SUSPICIOUS_THRESHOLD,
        dangerous_threshold=DANGEROUS_THRESHOLD,
    )


@app.route("/healthz")
def healthz():
    """Liveness probe: confirms the process is up and the database is readable."""
    try:
        get_db_connection().execute("SELECT 1").fetchone()
    except sqlite3.Error as error:
        return jsonify({"status": "error", "detail": str(error)}), 503
    return jsonify({"status": "ok"})


# --- Error handling ---------------------------------------------------------

@app.errorhandler(404)
def handle_not_found(error):
    return render_template("not_found.html", scan_id=None), 404


@app.errorhandler(429)
def handle_rate_limited(error):
    return render_template(
        "error.html",
        title="Too many scans",
        message="You've hit the rate limit of 20 scans per minute. Wait a moment and try again.",
    ), 429


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """
    A stale form (left open long enough for the session to roll over) posts an
    invalid CSRF token. The default response is a bare 400 page; this explains
    what to do about it.
    """
    return render_template(
        "error.html",
        title="This form expired",
        message="Your session changed while the page was open, so the submission was "
                "rejected for safety. Go back to the scan form and paste the email again.",
    ), 400


@app.errorhandler(500)
def handle_server_error(error):
    return render_template(
        "error.html",
        title="Something went wrong",
        message="PhishGuard hit an unexpected error. Nothing was saved for that scan.",
    ), 500


@app.context_processor
def template_globals():
    return {"current_year": datetime.now().year}


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, port=int(os.environ.get("PORT", 5000)))
