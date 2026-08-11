"""
Shared fixtures.

The `client` fixture is the important one: it points the app at a throwaway
database under pytest's `tmp_path`, so no test can read or write the real
`phishguard.db`, and it turns off CSRF and rate limiting because almost no test
is about either. The two tests that *are* about them opt back in explicitly.
"""

import re

import pytest

import app as app_module


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "test_phishguard.db"


@pytest.fixture
def configured_app(db_path):
    """The real app object, pointed at a temporary database."""
    app_module.app.config.update(
        DATABASE=str(db_path),
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=True,
    )
    app_module.init_db()
    app_module.limiter.reset()
    yield app_module.app
    app_module.limiter.reset()


@pytest.fixture
def client(configured_app):
    configured_app.config["RATELIMIT_ENABLED"] = False
    with configured_app.test_client() as test_client:
        yield test_client


def csrf_token(html):
    """The CSRF token from a rendered form, for the tests that keep CSRF on."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else ""


def post_scan(client, email_text):
    """Submit the scan form the way a browser does."""
    page = client.get("/")
    return client.post(
        "/",
        data={"email_text": email_text, "csrf_token": csrf_token(page.text)},
    )


def scan_id_from_redirect(response):
    """The new scan's id, taken from the POST-redirect-GET Location header."""
    return int(re.search(r"/history/(\d+)", response.headers["Location"]).group(1))


def create_scan(client, email_text):
    """Submit a scan and return its id."""
    return scan_id_from_redirect(post_scan(client, email_text))
