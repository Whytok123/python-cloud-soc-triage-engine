"""Administrator account-unlock dashboard tests."""

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

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = (
    "Secure-Admin-Password-2026!"
)

TARGET_EMAIL = "locked@example.com"
TARGET_PASSWORD = (
    "Secure-Locked-Password-2026!"
)

REGULAR_EMAIL = "regular@example.com"
REGULAR_PASSWORD = (
    "Secure-Regular-Password-2026!"
)


def build_app(tmp_path):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="unlock-api-test-key",
        session_secret="unlock-session-secret",
    )

    app.state.identity_store.create_account(
        email=ADMIN_EMAIL,
        display_name="Admin User",
        password=ADMIN_PASSWORD,
        role="admin",
    )

    target = (
        app.state.identity_store.create_account(
            email=TARGET_EMAIL,
            display_name="Locked Analyst",
            password=TARGET_PASSWORD,
            role="analyst",
        )
    )

    app.state.identity_store.create_account(
        email=REGULAR_EMAIL,
        display_name="Regular Analyst",
        password=REGULAR_PASSWORD,
        role="analyst",
    )

    for _ in range(5):
        (
            app.state.login_security_store
            .record_failure(
                TARGET_EMAIL,
                identity_store=(
                    app.state.identity_store
                ),
            )
        )

    return app, target


def extract_csrf(html: str) -> str:
    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def login(
    client: TestClient,
    *,
    email: str,
    password: str,
) -> None:
    page = client.get(
        "/dashboard/login"
    )

    assert page.status_code == 200

    response = client.post(
        "/dashboard/login",
        data={
            "email": email,
            "password": password,
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303


def test_admin_page_displays_locked_account(
    tmp_path,
):
    app, _ = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    response = client.get(
        "/dashboard/admin/analysts"
    )

    assert response.status_code == 200
    assert TARGET_EMAIL in response.text
    assert "Locked" in response.text
    assert "Unlock account" in response.text


def test_admin_can_unlock_account(
    tmp_path,
):
    app, target = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    page = client.get(
        "/dashboard/admin/analysts"
    )

    response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/unlock"
        ),
        data={
            "csrf_token": extract_csrf(
                page.text
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    assert (
        app.state.login_security_store
        .get_state(TARGET_EMAIL)
        is None
    )

    events = (
        app.state.identity_store
        .list_audit_events(limit=30)
    )

    unlock_event = next(
        event
        for event in events
        if event.action
        == "account_unlocked"
    )

    assert unlock_event.actor_email == (
        ADMIN_EMAIL
    )

    fresh_client = TestClient(app)

    login(
        fresh_client,
        email=TARGET_EMAIL,
        password=TARGET_PASSWORD,
    )


def test_non_admin_cannot_unlock_account(
    tmp_path,
):
    app, target = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=REGULAR_EMAIL,
        password=REGULAR_PASSWORD,
    )

    dashboard = client.get("/dashboard")

    response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/unlock"
        ),
        data={
            "csrf_token": extract_csrf(
                dashboard.text
            ),
        },
    )

    assert response.status_code == 403

    assert (
        app.state.login_security_store
        .is_locked(TARGET_EMAIL)
    )
