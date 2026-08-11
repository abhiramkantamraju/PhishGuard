"""
Route-level tests: the scan form, the history CRUD operations, export, health
and the error pages.
"""

import json
import sqlite3

import app as app_module

from conftest import create_scan, csrf_token, post_scan

PHISHING_EMAIL = (
    "Dear Customer, your account has been suspended. Verify your account at "
    "http://paypa1.com/login within 24 hours."
)
BENIGN_EMAIL = "Hi, just checking in about lunch tomorrow."


class TestIndexRoute:
    def test_get_returns_the_form(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "email_text" in response.text

    def test_get_offers_sample_emails(self, client):
        response = client.get("/")
        for sample in app_module.SAMPLE_EMAILS:
            assert sample["label"] in response.text

    def test_empty_email_shows_error_and_does_not_redirect(self, client):
        response = client.post("/", data={"email_text": ""})
        assert response.status_code == 400
        assert "Please paste an email message" in response.text

    def test_oversized_email_shows_the_limit(self, client):
        response = client.post("/", data={"email_text": "a" * 20_001})
        assert response.status_code == 400
        assert "too long" in response.text

    def test_valid_scan_redirects_to_its_permalink(self, client):
        """
        Post-redirect-get: the scan gets a shareable URL and a browser refresh
        re-reads it instead of submitting the form a second time.
        """
        response = post_scan(client, BENIGN_EMAIL)
        assert response.status_code == 302
        assert response.headers["Location"].startswith("/history/")
        assert "new=1" in response.headers["Location"]


class TestScanDetail:
    def test_shows_the_verdict_and_the_email(self, client):
        scan_id = create_scan(client, PHISHING_EMAIL)
        response = client.get(f"/history/{scan_id}")
        assert response.status_code == 200
        assert "Dangerous" in response.text
        assert "paypa1.com" in response.text

    def test_groups_findings_by_category(self, client):
        scan_id = create_scan(client, PHISHING_EMAIL)
        response = client.get(f"/history/{scan_id}")
        assert "Requests credentials or personal data" in response.text
        assert "Impersonal or generic greeting" in response.text

    def test_scan_without_urls_has_no_background_link_check(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        response = client.get(f"/history/{scan_id}")
        assert "network-check-status" not in response.text

    def test_scan_with_a_url_schedules_the_link_check(self, client):
        scan_id = create_scan(client, "Verify your account at http://example.com/login")
        response = client.get(f"/history/{scan_id}")
        assert "network-check-status" in response.text

    def test_unknown_scan_returns_404_page(self, client):
        response = client.get("/history/9999")
        assert response.status_code == 404
        assert "doesn't exist" in response.text


class TestNetworkCheckRoute:
    def test_unknown_scan_id_returns_404_json(self, client):
        response = client.post("/history/999/network-check")
        assert response.status_code == 404
        assert response.get_json()["error"]

    def test_merges_findings_and_score(self, client, monkeypatch):
        scan_id = create_scan(client, "Verify your account at http://example.com/login")

        def fake_network_findings(urls, api_key=None):
            finding = app_module.Finding(
                "safe_browsing", "link_manipulation", "flagged as malware"
            )
            return ([finding], 5)

        monkeypatch.setattr(app_module, "network_findings", fake_network_findings)

        data = client.post(f"/history/{scan_id}/network-check").get_json()
        assert data["flags"] == ["flagged as malware"]
        assert data["findings"][0]["category_label"]
        assert data["score"] >= 5

    def test_is_idempotent(self, client, monkeypatch):
        scan_id = create_scan(client, "Verify your account at http://example.com/login")
        calls = {"count": 0}

        def fake_network_findings(urls, api_key=None):
            calls["count"] += 1
            return ([app_module.Finding("safe_browsing", "link_manipulation", "some flag")], 5)  # noqa: E501

        monkeypatch.setattr(app_module, "network_findings", fake_network_findings)

        first = client.post(f"/history/{scan_id}/network-check").get_json()
        second = client.post(f"/history/{scan_id}/network-check").get_json()

        assert calls["count"] == 1
        assert second["flags"] == []
        assert second["score"] == first["score"]

    def test_already_checked_scan_does_not_offer_to_check_again(self, client, monkeypatch):
        scan_id = create_scan(client, "Verify your account at http://example.com/login")
        monkeypatch.setattr(app_module, "network_findings", lambda urls, api_key=None: ([], 0))
        client.post(f"/history/{scan_id}/network-check")

        response = client.get(f"/history/{scan_id}")
        assert "network-check-status" not in response.text


class TestHistory:
    def test_empty_history_shows_an_empty_state(self, client):
        response = client.get("/history")
        assert "No scans saved yet" in response.text

    def test_lists_scans_newest_first(self, client):
        first = create_scan(client, "Hi, first email about lunch.")
        second = create_scan(client, "Hi, second email about dinner.")
        response = client.get("/history")
        assert response.text.index(f"/history/{second}") < response.text.index(f"/history/{first}")

    def test_shows_risk_totals(self, client):
        create_scan(client, BENIGN_EMAIL)
        create_scan(client, PHISHING_EMAIL)
        response = client.get("/history")
        assert "Total scans" in response.text

    def test_search_filters_by_email_text(self, client):
        create_scan(client, "Hi, lunch on Tuesday about the quarterly report?")
        create_scan(client, "Hi, dinner on Friday with the neighbours?")
        response = client.get("/history?q=quarterly")
        assert "quarterly" in response.text
        assert "neighbours" not in response.text

    def test_search_with_no_match_shows_a_filtered_empty_state(self, client):
        create_scan(client, BENIGN_EMAIL)
        response = client.get("/history?q=zzzznotpresent")
        assert "No scans match that filter" in response.text

    def test_risk_filter_narrows_the_list(self, client):
        create_scan(client, BENIGN_EMAIL)
        dangerous_id = create_scan(client, PHISHING_EMAIL)
        response = client.get("/history?risk=Dangerous")
        assert f"/history/{dangerous_id}" in response.text
        assert "lunch tomorrow" not in response.text

    def test_unknown_risk_filter_is_ignored_rather_than_erroring(self, client):
        create_scan(client, BENIGN_EMAIL)
        response = client.get("/history?risk=Bogus")
        assert response.status_code == 200


class TestEditNote:
    def test_get_shows_the_form(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        response = client.get(f"/history/{scan_id}/edit")
        assert response.status_code == 200
        assert "Your note" in response.text

    def test_saving_a_note_persists_and_redirects(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        response = client.post(f"/history/{scan_id}/edit", data={"note": "Reported to IT"})
        assert response.status_code == 302

        detail = client.get(f"/history/{scan_id}")
        assert "Reported to IT" in detail.text

    def test_clearing_a_note_is_allowed(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        client.post(f"/history/{scan_id}/edit", data={"note": "temporary"})
        client.post(f"/history/{scan_id}/edit", data={"note": ""})
        response = client.get("/history")
        assert "No note" in response.text

    def test_overlong_note_is_rejected(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        response = client.post(f"/history/{scan_id}/edit", data={"note": "x" * 2001})
        assert response.status_code == 400
        assert "too long" in response.text

    def test_editing_a_missing_scan_returns_404(self, client):
        assert client.get("/history/4242/edit").status_code == 404


class TestDelete:
    def test_deleting_removes_the_scan(self, client):
        scan_id = create_scan(client, BENIGN_EMAIL)
        response = client.post(f"/history/{scan_id}/delete")
        assert response.status_code == 302
        assert client.get(f"/history/{scan_id}").status_code == 404

    def test_deleting_a_missing_scan_reports_it_without_erroring(self, client):
        response = client.post("/history/4242/delete", follow_redirects=True)
        assert response.status_code == 200
        assert "no longer exists" in response.text


class TestExport:
    def test_csv_export_has_a_header_row_and_the_scan(self, client):
        create_scan(client, PHISHING_EMAIL)
        response = client.get("/history/export.csv")
        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert "attachment" in response.headers["Content-Disposition"]
        assert response.text.splitlines()[0].startswith("id,created_at,risk_level")
        assert "paypa1.com" in response.text

    def test_json_export_is_valid_json_with_findings(self, client):
        create_scan(client, PHISHING_EMAIL)
        response = client.get("/history/export.json")
        assert response.status_code == 200
        payload = json.loads(response.text)
        assert payload[0]["risk_level"] == "Dangerous"
        assert payload[0]["findings"]
        assert payload[0]["findings"][0]["category_label"]

    def test_unknown_format_is_404(self, client):
        assert client.get("/history/export.xml").status_code == 404


class TestStaticPages:
    def test_how_it_works_lists_the_categories(self, client):
        response = client.get("/how-it-works")
        assert response.status_code == 200
        assert "Requests credentials or personal data" in response.text
        assert str(app_module.SUSPICIOUS_THRESHOLD) in response.text

    def test_healthz_reports_ok(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.get_json() == {"status": "ok"}

    def test_healthz_reports_failure_when_the_database_is_unusable(self, client, monkeypatch):
        def broken_connection():
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(app_module, "get_db_connection", broken_connection)
        # The handler catches sqlite3.Error; anything else would be a 500.
        response = client.get("/healthz")
        assert response.status_code == 503

    def test_unknown_url_renders_the_404_page(self, client):
        response = client.get("/no-such-page")
        assert response.status_code == 404
        assert "Page not found" in response.text


class TestSecurity:
    def test_csrf_token_is_required_when_enabled(self, configured_app):
        configured_app.config["WTF_CSRF_ENABLED"] = True
        configured_app.config["RATELIMIT_ENABLED"] = False
        try:
            with configured_app.test_client() as client:
                response = client.post("/", data={"email_text": BENIGN_EMAIL})
                assert response.status_code == 400
                assert "expired" in response.text
        finally:
            configured_app.config["WTF_CSRF_ENABLED"] = False

    def test_valid_csrf_token_is_accepted(self, configured_app):
        configured_app.config["WTF_CSRF_ENABLED"] = True
        configured_app.config["RATELIMIT_ENABLED"] = False
        try:
            with configured_app.test_client() as client:
                token = csrf_token(client.get("/").text)
                response = client.post("/", data={"email_text": BENIGN_EMAIL, "csrf_token": token})
                assert response.status_code == 302
        finally:
            configured_app.config["WTF_CSRF_ENABLED"] = False

    def test_email_text_is_escaped_not_rendered(self, client):
        """
        Stored email bodies are attacker-controlled text. Jinja autoescaping must
        keep a <script> tag in a scanned email from executing on the result page.
        """
        scan_id = create_scan(
            client, "Hello <script>alert('xss')</script> please verify your account"
        )
        response = client.get(f"/history/{scan_id}")
        assert "<script>alert" not in response.text
        assert "&lt;script&gt;" in response.text

    def test_excessive_scans_are_rate_limited(self, configured_app):
        with configured_app.test_client() as client:
            statuses = [post_scan(client, BENIGN_EMAIL).status_code for _ in range(21)]
        assert 429 in statuses

    def test_rate_limited_response_is_a_friendly_page(self, configured_app):
        with configured_app.test_client() as client:
            for _ in range(21):
                response = post_scan(client, BENIGN_EMAIL)
            assert response.status_code == 429
            assert "Too many scans" in response.text


class TestPersistence:
    def test_findings_are_stored_structured_and_survive_a_reload(self, client, db_path):
        scan_id = create_scan(client, PHISHING_EMAIL)

        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        finally:
            connection.close()

        stored = json.loads(row["findings"])
        assert {"rule", "category", "message", "match"} <= set(stored[0])
        assert row["flags"].split("\n") == [item["message"] for item in stored]

    def test_a_scan_saved_before_structured_findings_still_renders(self, client, db_path):
        """
        Backwards compatibility: rows written by the previous version have only
        the newline-joined `flags` column. The detail page must fall back to it
        rather than showing an empty result.
        """
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "INSERT INTO scans (email_text, flags, findings, score, risk_level, created_at)"
                " VALUES (?, ?, '[]', ?, ?, ?)",
                (
                    "Old scan text", "Urgent language detected: 'act now'",
                    2, "Suspicious", "2026-01-01 10:00",
                ),
            )
            connection.commit()
            scan_id = connection.execute("SELECT MAX(id) AS id FROM scans").fetchone()[0]
        finally:
            connection.close()

        response = client.get(f"/history/{scan_id}")
        assert response.status_code == 200
        assert "Urgent language detected" in response.text

    def test_findings_referencing_a_removed_category_are_skipped(self, client, db_path):
        """
        Removing a rule (and its category) must not break the history page for
        scans that were saved while it existed.
        """
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "INSERT INTO scans (email_text, flags, findings, score, risk_level, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "Old scan text", "gone",
                    json.dumps([
                        {"rule": "gone", "category": "no_such_category", "message": "gone"}
                    ]),
                    2, "Suspicious", "2026-01-01 10:00",
                ),
            )
            connection.commit()
            scan_id = connection.execute("SELECT MAX(id) AS id FROM scans").fetchone()[0]
        finally:
            connection.close()

        assert client.get(f"/history/{scan_id}").status_code == 200


class TestMigration:
    def test_init_db_adds_missing_columns_to_an_older_database(self, tmp_path):
        """
        The pre-release schema had neither `findings` nor `network_checked`.
        Opening such a database must migrate it in place, not fail or wipe it.
        """
        old_db = tmp_path / "old.db"
        connection = sqlite3.connect(old_db)
        try:
            connection.execute(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_text TEXT NOT NULL,
                    flags TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    note TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO scans (email_text, flags, score, risk_level, created_at)"
                " VALUES ('old', 'flag', 2, 'Suspicious', '2026-01-01 10:00')"
            )
            connection.commit()
        finally:
            connection.close()

        app_module.app.config["DATABASE"] = str(old_db)
        app_module.init_db()

        connection = sqlite3.connect(old_db)
        try:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
            surviving = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finally:
            connection.close()

        assert {"findings", "network_checked"} <= columns
        assert surviving == 1
