"""Dashboard and API request rate-limit tests."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

INPUT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "test_events"
)

TEST_EMAIL = "rate.analyst@example.com"
TEST_PASSWORD = (
    "Secure-Rate-Analyst-2026!"
)


def build_app(
    tmp_path,
    monkeypatch,
):
    """Create an app with small deterministic limits."""

    monkeypatch.setenv(
        "SOC_LOGIN_RATE_LIMIT",
        "2",
    )

    monkeypatch.setenv(
        "SOC_LOGIN_RATE_WINDOW_SECONDS",
        "60",
    )

    monkeypatch.setenv(
        "SOC_API_RATE_LIMIT",
        "2",
    )

    monkeypatch.setenv(
        "SOC_API_RATE_WINDOW_SECONDS",
        "60",
    )

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="rate-limit-api-key",
        session_secret=(
            "rate-limit-session-secret"
        ),
    )

    app.state.identity_store.create_account(
        email=TEST_EMAIL,
        display_name="Rate Analyst",
        password=TEST_PASSWORD,
        role="analyst",
    )

    @app.get("/rate-limit-test")
    def protected_test_route():
        return {"status": "ok"}

    return app


def extract_csrf(html: str) -> str:
    """Extract a CSRF token from HTML."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def submit_failed_login(
    client: TestClient,
):
    """Submit one incorrect login attempt."""

    page = client.get(
        "/dashboard/login"
    )

    assert page.status_code == 200

    return client.post(
        "/dashboard/login",
        data={
            "email": TEST_EMAIL,
            "password": (
                "Incorrect-Rate-Password-2026!"
            ),
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )


def test_login_post_is_rate_limited(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )

    client = TestClient(app)

    first = submit_failed_login(client)
    second = submit_failed_login(client)
    blocked = submit_failed_login(client)

    assert first.status_code == 401
    assert first.headers[
        "x-ratelimit-limit"
    ] == "2"
    assert first.headers[
        "x-ratelimit-remaining"
    ] == "1"

    assert second.status_code == 401
    assert second.headers[
        "x-ratelimit-remaining"
    ] == "0"

    assert blocked.status_code == 429

    assert int(
        blocked.headers["retry-after"]
    ) >= 1

    assert (
        "Too many login requests"
        in blocked.text
    )


def test_login_page_get_is_not_limited(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )

    client = TestClient(app)

    for _ in range(10):
        response = client.get(
            "/dashboard/login"
        )

        assert response.status_code == 200

    first_post = submit_failed_login(
        client
    )

    assert first_post.status_code == 401
    assert first_post.headers[
        "x-ratelimit-remaining"
    ] == "1"


def test_protected_api_is_rate_limited(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )

    client = TestClient(app)

    headers = {
        "X-SOC-API-Key": (
            "rate-limit-api-key"
        )
    }

    first = client.get(
        "/rate-limit-test",
        headers=headers,
    )

    second = client.get(
        "/rate-limit-test",
        headers=headers,
    )

    blocked = client.get(
        "/rate-limit-test",
        headers=headers,
    )

    assert first.status_code == 200
    assert first.headers[
        "x-ratelimit-limit"
    ] == "2"
    assert first.headers[
        "x-ratelimit-remaining"
    ] == "1"

    assert second.status_code == 200
    assert second.headers[
        "x-ratelimit-remaining"
    ] == "0"

    assert blocked.status_code == 429

    assert blocked.json()["detail"] == (
        "Too many API requests. "
        "Try again later."
    )

    assert int(
        blocked.headers["retry-after"]
    ) >= 1


def test_public_health_route_is_not_limited(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
    )

    client = TestClient(app)

    for _ in range(6):
        response = client.get("/health")

        assert response.status_code == 200

        assert (
            "x-ratelimit-limit"
            not in response.headers
        )
