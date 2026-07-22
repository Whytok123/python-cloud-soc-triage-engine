"""Trusted-proxy integration with request rate limits."""

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

TEST_EMAIL = "proxy.analyst@example.com"
TEST_PASSWORD = (
    "Secure-Proxy-Analyst-2026!"
)

API_KEY = "trusted-proxy-api-key"


def build_app(
    tmp_path,
    monkeypatch,
    *,
    trusted_proxy_cidrs: str | None,
):
    """Create an application with one-request limits."""

    monkeypatch.setenv(
        "SOC_API_RATE_LIMIT",
        "1",
    )

    monkeypatch.setenv(
        "SOC_API_RATE_WINDOW_SECONDS",
        "60",
    )

    monkeypatch.setenv(
        "SOC_LOGIN_RATE_LIMIT",
        "1",
    )

    monkeypatch.setenv(
        "SOC_LOGIN_RATE_WINDOW_SECONDS",
        "60",
    )

    if trusted_proxy_cidrs is None:
        monkeypatch.delenv(
            "SOC_TRUSTED_PROXY_CIDRS",
            raising=False,
        )
    else:
        monkeypatch.setenv(
            "SOC_TRUSTED_PROXY_CIDRS",
            trusted_proxy_cidrs,
        )

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=API_KEY,
        session_secret=(
            "trusted-proxy-session-secret"
        ),
    )

    app.state.identity_store.create_account(
        email=TEST_EMAIL,
        display_name="Proxy Analyst",
        password=TEST_PASSWORD,
        role="analyst",
    )

    @app.get("/proxy-rate-test")
    def proxy_rate_test():
        return {"status": "ok"}

    return app


def api_headers(
    forwarded_for: str,
) -> dict[str, str]:
    """Create authenticated API headers."""

    return {
        "X-SOC-API-Key": API_KEY,
        "X-Forwarded-For": forwarded_for,
    }


def extract_csrf(html: str) -> str:
    """Extract a CSRF token from HTML."""

    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def failed_login(
    client: TestClient,
    *,
    forwarded_for: str,
):
    """Submit one failed login from a forwarded client."""

    page = client.get(
        "/dashboard/login"
    )

    assert page.status_code == 200

    return client.post(
        "/dashboard/login",
        headers={
            "X-Forwarded-For": forwarded_for,
        },
        data={
            "email": TEST_EMAIL,
            "password": (
                "Incorrect-Proxy-Password-2026!"
            ),
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )


def test_application_loads_trusted_proxy_cidrs(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        trusted_proxy_cidrs=(
            "10.0.0.0/8,192.168.0.0/16"
        ),
    )

    assert len(
        app.state.trusted_proxy_resolver
        .trusted_proxy_networks
    ) == 2


def test_untrusted_peer_cannot_rotate_forwarded_ip(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        trusted_proxy_cidrs=None,
    )

    client = TestClient(
        app,
        client=("10.0.0.10", 50000),
    )

    first = client.get(
        "/proxy-rate-test",
        headers=api_headers(
            "198.51.100.10"
        ),
    )

    blocked = client.get(
        "/proxy-rate-test",
        headers=api_headers(
            "198.51.100.11"
        ),
    )

    assert first.status_code == 200
    assert blocked.status_code == 429


def test_trusted_proxy_uses_forwarded_clients(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        trusted_proxy_cidrs="10.0.0.0/8",
    )

    client = TestClient(
        app,
        client=("10.0.0.10", 50000),
    )

    first_client = client.get(
        "/proxy-rate-test",
        headers=api_headers(
            "198.51.100.10"
        ),
    )

    second_client = client.get(
        "/proxy-rate-test",
        headers=api_headers(
            "198.51.100.11"
        ),
    )

    repeated_first_client = client.get(
        "/proxy-rate-test",
        headers=api_headers(
            "198.51.100.10"
        ),
    )

    assert first_client.status_code == 200
    assert second_client.status_code == 200
    assert (
        repeated_first_client.status_code
        == 429
    )


def test_login_limiter_uses_trusted_client_ip(
    tmp_path,
    monkeypatch,
):
    app = build_app(
        tmp_path,
        monkeypatch,
        trusted_proxy_cidrs="10.0.0.0/8",
    )

    client = TestClient(
        app,
        client=("10.0.0.10", 50000),
    )

    first_client = failed_login(
        client,
        forwarded_for="198.51.100.20",
    )

    second_client = failed_login(
        client,
        forwarded_for="198.51.100.21",
    )

    repeated_first_client = failed_login(
        client,
        forwarded_for="198.51.100.20",
    )

    assert first_client.status_code == 401
    assert second_client.status_code == 401

    assert (
        repeated_first_client.status_code
        == 429
    )
