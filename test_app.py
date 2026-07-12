import re

import pytest

import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DATABASE", str(tmp_path / "test_phishguard.db"))
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.app.config["RATELIMIT_ENABLED"] = False
    with app_module.app.test_client() as test_client:
        yield test_client


def get_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1)


def post_scan(client, email_text):
    get_response = client.get("/")
    token = get_csrf_token(get_response.text)
    return client.post("/", data={"email_text": email_text, "csrf_token": token})


class TestIndexRoute:
    def test_get_index_returns_form(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "email_text" in response.text

    def test_empty_email_shows_error(self, client):
        get_response = client.get("/")
        token = get_csrf_token(get_response.text)
        response = client.post("/", data={"email_text": "", "csrf_token": token})
        assert response.status_code == 200
        assert "Please paste an email message" in response.text

    def test_scan_without_urls_has_no_network_check_script(self, client):
        response = post_scan(client, "Hi, just checking in about lunch tomorrow.")
        assert response.status_code == 200
        assert "network-check" not in response.text

    def test_scan_with_url_includes_network_check_script(self, client):
        response = post_scan(client, "Verify your account at http://example.com/login")
        assert response.status_code == 200
        assert "network-check-status" in response.text


class TestRateLimiting:
    def test_excessive_scans_are_rate_limited(self, tmp_path, monkeypatch):
        monkeypatch.setattr(app_module, "DATABASE", str(tmp_path / "test_phishguard.db"))
        app_module.init_db()
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        app_module.limiter.reset()

        with app_module.app.test_client() as client:
            responses = [
                post_scan(client, "Hi, just checking in.").status_code
                for _ in range(21)
            ]

        assert 429 in responses
        app_module.limiter.reset()


class TestNetworkCheckRoute:
    def test_unknown_scan_id_returns_404(self, client):
        response = client.post("/history/999/network-check")
        assert response.status_code == 404

    def test_network_check_merges_flags_and_score(self, client, monkeypatch):
        scan_response = post_scan(client, "Verify your account at http://example.com/login")
        scan_id = re.search(r"/history/(\d+)/edit", scan_response.text).group(1)

        def fake_analyze_urls_network(urls, api_key=None):
            return (["Google Safe Browsing flagged 'http://example.com/login'"], 5)

        monkeypatch.setattr(app_module, "analyze_urls_network", fake_analyze_urls_network)

        response = client.post(f"/history/{scan_id}/network-check")
        data = response.get_json()

        assert response.status_code == 200
        assert data["flags"] == ["Google Safe Browsing flagged 'http://example.com/login'"]
        assert data["score"] >= 5

    def test_network_check_is_idempotent(self, client, monkeypatch):
        scan_response = post_scan(client, "Verify your account at http://example.com/login")
        scan_id = re.search(r"/history/(\d+)/edit", scan_response.text).group(1)

        call_count = {"count": 0}

        def fake_analyze_urls_network(urls, api_key=None):
            call_count["count"] += 1
            return (["some flag"], 5)

        monkeypatch.setattr(app_module, "analyze_urls_network", fake_analyze_urls_network)

        first = client.post(f"/history/{scan_id}/network-check").get_json()
        second = client.post(f"/history/{scan_id}/network-check").get_json()

        assert call_count["count"] == 1
        assert second["flags"] == []
        assert second["score"] == first["score"]
