"""Dashboard role-based authorization tests."""

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

TEST_API_KEY = "rbac-machine-api-key"
TEST_SESSION_SECRET = (
    "rbac-dashboard-session-secret"
)

ANALYST_EMAIL = "analyst@example.com"
ANALYST_PASSWORD = (
    "Secure-Analyst-Password-2026!"
)

SENIOR_EMAIL = "senior@example.com"
SENIOR_PASSWORD = (
    "Secure-Senior-Password-2026!"
)


def build_app(tmp_path):
    """Create an isolated application with two users."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
        session_secret=TEST_SESSION_SECRET,
    )

    app.state.identity_store.create_account(
        email=ANALYST_EMAIL,
        display_name="Alice Analyst",
        password=ANALYST_PASSWORD,
        role="analyst",
    )

    app.state.identity_store.create_account(
        email=SENIOR_EMAIL,
        display_name="Sam Senior",
        password=SENIOR_PASSWORD,
        role="senior_analyst",
    )

    return app


def build_packet() -> dict:
    """Return a test SOC case packet."""

    return {
        "case_id": "case-rbac-test",
        "correlation_id": "corr-rbac-test",
        "title": "RBAC SSH investigation",
        "priority": "P1",
        "risk_score": 95,
        "risk_level": "critical",
        "event_ids": [
            "event-rbac-1",
            "event-rbac-2",
        ],
        "summary": (
            "Suspicious SSH authentication activity."
        ),
        "first_seen": (
            "2026-07-19T01:00:00+00:00"
        ),
        "last_seen": (
            "2026-07-19T01:10:00+00:00"
        ),
    }


def extract_csrf(html: str) -> str:
    """Extract the CSRF token from an HTML form."""

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
    """Authenticate a dashboard user."""

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


def case_csrf(
    client: TestClient,
) -> str:
    """Return a CSRF token from the case page."""

    response = client.get(
        "/dashboard/cases/case-rbac-test"
    )

    assert response.status_code == 200

    return extract_csrf(response.text)


def test_analyst_can_assign_case_to_self(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.post(
        "/dashboard/cases/"
        "case-rbac-test/update",
        data={
            "csrf_token": case_csrf(client),
            "case_status": "investigating",
            "assigned_to": ANALYST_EMAIL,
            "note": "Beginning SSH review.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    case = app.state.case_store.get_case(
        "case-rbac-test"
    )

    assert case is not None
    assert case.status == "investigating"
    assert case.assigned_to == ANALYST_EMAIL


def test_analyst_cannot_assign_another_user(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.post(
        "/dashboard/cases/"
        "case-rbac-test/update",
        data={
            "csrf_token": case_csrf(client),
            "case_status": "new",
            "assigned_to": SENIOR_EMAIL,
            "note": "",
        },
    )

    assert response.status_code == 403

    case = app.state.case_store.get_case(
        "case-rbac-test"
    )

    assert case is not None
    assert case.assigned_to is None


def test_analyst_cannot_resolve_case(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(
        client,
        email=ANALYST_EMAIL,
        password=ANALYST_PASSWORD,
    )

    response = client.post(
        "/dashboard/cases/"
        "case-rbac-test/update",
        data={
            "csrf_token": case_csrf(client),
            "case_status": "resolved",
            "assigned_to": "",
            "note": "",
        },
    )

    assert response.status_code == 403

    case = app.state.case_store.get_case(
        "case-rbac-test"
    )

    assert case is not None
    assert case.status == "new"


def test_senior_can_reassign_and_resolve(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(
        client,
        email=SENIOR_EMAIL,
        password=SENIOR_PASSWORD,
    )

    response = client.post(
        "/dashboard/cases/"
        "case-rbac-test/update",
        data={
            "csrf_token": case_csrf(client),
            "case_status": "resolved",
            "assigned_to": ANALYST_EMAIL,
            "note": "Investigation complete.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    case = app.state.case_store.get_case(
        "case-rbac-test"
    )

    assert case is not None
    assert case.status == "resolved"
    assert case.assigned_to == ANALYST_EMAIL

    audit_events = (
        app.state.case_store
        .get_audit_events(
            "case-rbac-test"
        )
    )

    assert audit_events[-1].actor == (
        SENIOR_EMAIL
    )
