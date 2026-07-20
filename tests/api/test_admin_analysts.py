"""Administrator analyst-management tests."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "test_events"
)

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Secure-Admin-Password-2026!"

ANALYST_EMAIL = "analyst@example.com"
ANALYST_PASSWORD = "Secure-Analyst-Password-2026!"


def build_app(tmp_path):
    """Create an isolated application for testing."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key="admin-api-test-key",
        session_secret="admin-session-test-secret",
    )

    app.state.identity_store.create_account(
        email=ADMIN_EMAIL,
        display_name="Admin User",
        password=ADMIN_PASSWORD,
        role="admin",
    )

    app.state.identity_store.create_account(
        email=ANALYST_EMAIL,
        display_name="Analyst User",
        password=ANALYST_PASSWORD,
        role="analyst",
    )

    return app


def extract_csrf(html: str) -> str:
    """Extract a CSRF token from rendered HTML."""

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
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
    """Sign in to the analyst dashboard."""

    login_page = client.get(
        "/dashboard/login"
    )

    assert login_page.status_code == 200

    csrf_token = extract_csrf(
        login_page.text
    )

    response = client.post(
        "/dashboard/login",
        data={
            "email": email,
            "password": password,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == (
        "/dashboard"
    )


def admin_csrf(
    client: TestClient,
) -> str:
    """Return a CSRF token from the admin page."""

    page = client.get(
        "/dashboard/admin/analysts"
    )

    assert page.status_code == 200

    return extract_csrf(page.text)


def test_non_admin_cannot_access_admin_page(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.get(
        "/dashboard/admin/analysts"
    )

    assert response.status_code == 403


def test_admin_can_view_accounts(
    tmp_path,
):
    app = build_app(tmp_path)
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
    assert ADMIN_EMAIL in response.text
    assert ANALYST_EMAIL in response.text
    assert (
        "Create analyst account"
        in response.text
    )


def test_admin_can_create_account(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    response = client.post(
        "/dashboard/admin/analysts/create",
        data={
            "csrf_token": admin_csrf(client),
            "email": "new@example.com",
            "display_name": "New Analyst",
            "role": "analyst",
            "password": (
                "Secure-New-Password-2026!"
            ),
            "password_confirmation": (
                "Secure-New-Password-2026!"
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    account = (
        app.state.identity_store
        .get_by_email("new@example.com")
    )

    assert account is not None
    assert account.role == "analyst"
    assert account.is_active is True


def test_admin_can_change_role(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    target = (
        app.state.identity_store
        .get_by_email(ANALYST_EMAIL)
    )

    assert target is not None

    response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/role"
        ),
        data={
            "csrf_token": admin_csrf(client),
            "role": "senior_analyst",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    updated = (
        app.state.identity_store
        .get_by_id(target.user_id)
    )

    assert updated is not None
    assert updated.role == (
        "senior_analyst"
    )


def test_admin_can_disable_and_reactivate_account(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    target = (
        app.state.identity_store
        .get_by_email(ANALYST_EMAIL)
    )

    assert target is not None

    disable_response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/active"
        ),
        data={
            "csrf_token": admin_csrf(client),
            "is_active": "false",
        },
        follow_redirects=False,
    )

    assert disable_response.status_code == 303

    disabled = (
        app.state.identity_store
        .get_by_id(target.user_id)
    )

    assert disabled is not None
    assert disabled.is_active is False

    reactivate_response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{target.user_id}/active"
        ),
        data={
            "csrf_token": admin_csrf(client),
            "is_active": "true",
        },
        follow_redirects=False,
    )

    assert reactivate_response.status_code == 303

    reactivated = (
        app.state.identity_store
        .get_by_id(target.user_id)
    )

    assert reactivated is not None
    assert reactivated.is_active is True


def test_admin_cannot_disable_own_account(
    tmp_path,
):
    app = build_app(tmp_path)
    client = TestClient(app)

    login(
        client,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
    )

    admin = (
        app.state.identity_store
        .get_by_email(ADMIN_EMAIL)
    )

    assert admin is not None

    response = client.post(
        (
            "/dashboard/admin/analysts/"
            f"{admin.user_id}/active"
        ),
        data={
            "csrf_token": admin_csrf(client),
            "is_active": "false",
        },
    )

    assert response.status_code == 403

    unchanged = (
        app.state.identity_store
        .get_by_id(admin.user_id)
    )

    assert unchanged is not None
    assert unchanged.is_active is True
