import os
import secrets
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

from detector import analyze_text, analyze_urls_network, extract_urls, get_risk_level


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
csrf = CSRFProtect(app)
# In-memory storage is fine for this single-process dev/demo app; a real
# deployment with multiple workers would need a shared backend (Redis, etc).
limiter = Limiter(get_remote_address, app=app, default_limits=[])

DATABASE = "phishguard.db"
MAX_EMAIL_LENGTH = 20000
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_text TEXT NOT NULL,
            flags TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            network_checked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # Migrate existing local databases created before network_checked existed.
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    if "network_checked" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN network_checked INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    conn.close()


# Called at import time, not just under `if __name__ == "__main__"`: a
# production WSGI server (gunicorn) imports this module and calls the `app`
# object directly, so it never runs the __main__ block below.
init_db()


@app.route("/", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def index():
    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()

        if not email_text:
            return render_template(
                "index.html",
                error="Please paste an email message before checking it.",
                email_text=email_text,
            )

        if len(email_text) > MAX_EMAIL_LENGTH:
            return render_template(
                "index.html",
                error=f"Email text is too long (max {MAX_EMAIL_LENGTH} characters).",
                email_text=email_text,
            )

        # Only the offline, in-process checks run here so the page responds
        # immediately. Google Safe Browsing/WHOIS are network calls that can
        # take several seconds; the result page fetches those afterward via
        # /history/<id>/network-check so they don't block this response.
        flags, score = analyze_text(email_text)
        risk_level = get_risk_level(score)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

        conn = get_db_connection()
        cursor = conn.execute(
            """
            INSERT INTO scans (email_text, flags, score, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email_text, "\n".join(flags), score, risk_level, created_at),
        )
        conn.commit()
        scan_id = cursor.lastrowid
        conn.close()

        return render_template(
            "result.html",
            scan_id=scan_id,
            email_text=email_text,
            flags=flags,
            score=score,
            risk_level=risk_level,
            check_links=bool(extract_urls(email_text)),
        )

    return render_template("index.html")


@app.route("/history/<int:scan_id>/network-check", methods=["POST"])
@limiter.limit("20 per minute")
def network_check(scan_id):
    conn = get_db_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if scan is None:
        conn.close()
        return jsonify({"error": "Scan not found"}), 404

    if scan["network_checked"]:
        conn.close()
        return jsonify({
            "flags": [],
            "score": scan["score"],
            "risk_level": scan["risk_level"],
        })

    urls = extract_urls(scan["email_text"])
    network_flags, network_score = analyze_urls_network(urls, api_key=SAFE_BROWSING_API_KEY)

    existing_flags = [flag for flag in scan["flags"].split("\n") if flag]
    combined_score = scan["score"] + network_score
    combined_risk_level = get_risk_level(combined_score)

    conn.execute(
        """
        UPDATE scans SET flags = ?, score = ?, risk_level = ?, network_checked = 1
        WHERE id = ?
        """,
        ("\n".join(existing_flags + network_flags), combined_score, combined_risk_level, scan_id),
    )
    conn.commit()
    conn.close()

    return jsonify({
        "flags": network_flags,
        "score": combined_score,
        "risk_level": combined_risk_level,
    })


@app.route("/history")
def history():
    conn = get_db_connection()
    scans = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    conn.close()

    return render_template("history.html", scans=scans)


@app.route("/history/<int:scan_id>/edit", methods=["GET", "POST"])
def edit_scan(scan_id):
    conn = get_db_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if scan is None:
        conn.close()
        return redirect(url_for("history"))

    if request.method == "POST":
        note = request.form.get("note", "").strip()
        conn.execute("UPDATE scans SET note = ? WHERE id = ?", (note, scan_id))
        conn.commit()
        conn.close()
        return redirect(url_for("history"))

    conn.close()
    return render_template("edit_scan.html", scan=scan)


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("history"))


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)