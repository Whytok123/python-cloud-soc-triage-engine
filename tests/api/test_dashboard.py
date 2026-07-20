import re
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.dashboard import _format_timestamp


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

INPUT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "test_events"
)

TEST_API_KEY = "dashboard-test-api-key"
TEST_SESSION_SECRET = (
    "dashboard-test-session-secret"
)


def build_app(tmp_path):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
        session_secret=TEST_SESSION_SECRET,
    )

    app.state.identity_store.create_account(
        email="alice@example.com",
        display_name="Alice Analyst",
        password="Secure-Test-Password-2026!",
        role="analyst",
    )

    return app

def build_packet() -> dict:
    return {
        "case_id": "case-dashboard-test",
        "correlation_id": "corr-dashboard-test",
        "title": "Dashboard SSH case",
        "priority": "P1",
        "risk_score": 100,
        "risk_level": "critical",
        "event_ids": [
            "event-1",
            "event-2",
        ],
        "summary": "Suspicious SSH activity.",
        "first_seen": (
            "2026-07-19T01:00:00+00:00"
        ),
        "last_seen": (
            "2026-07-19T01:10:00+00:00"
        ),
    }


def extract_csrf(html: str) -> str:
    match = re.search(
        r'name="csrf_token"\s+'
        r'value="([^"]+)"',
        html,
    )

    assert match is not None

    return match.group(1)


def login(client: TestClient) -> str:
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
            "email": "alice@example.com",
            "password": (
                "Secure-Test-Password-2026!"
            ),
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == (
        "/dashboard"
    )

    dashboard = client.get(
        "/dashboard"
    )

    assert dashboard.status_code == 200

    return extract_csrf(
        dashboard.text
    )

def test_dashboard_requires_login(tmp_path):
    client = TestClient(
        build_app(tmp_path)
    )

    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == (
        "/dashboard/login"
    )


def test_dashboard_login_works(tmp_path):
    client = TestClient(
        build_app(tmp_path)
    )

    login(client)

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Security case queue" in response.text


def test_dashboard_case_update_is_persisted(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(client)

    detail = client.get(
        "/dashboard/cases/"
        "case-dashboard-test"
    )

    csrf_token = extract_csrf(
        detail.text
    )

    response = client.post(
        "/dashboard/cases/"
        "case-dashboard-test/update",
        data={
            "csrf_token": csrf_token,
            "case_status": "investigating",
            "assigned_to": (
                "alice@example.com"
            ),
            "note": (
                "Started SSH session review."
            ),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303

    case = app.state.case_store.get_case(
        "case-dashboard-test"
    )

    assert case is not None
    assert case.status == "investigating"
    assert case.assigned_to == (
        "alice@example.com"
    )

    audit_events = (
        app.state.case_store
        .get_audit_events(
            "case-dashboard-test"
        )
    )

    assert audit_events[-1].event_type == (
        "case_updated"
    )

    assert audit_events[-1].details[
        "note"
    ] == "Started SSH session review."


def test_invalid_csrf_is_rejected(
    tmp_path,
):
    app = build_app(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client = TestClient(app)

    login(client)

    response = client.post(
        "/dashboard/cases/"
        "case-dashboard-test/update",
        data={
            "csrf_token": "invalid-token",
            "case_status": "resolved",
            "assigned_to": "",
            "note": "",
        },
    )

    assert response.status_code == 403

    case = app.state.case_store.get_case(
        "case-dashboard-test"
    )

    assert case is not None
    assert case.status == "new"


def test_logout_requires_valid_csrf(
    tmp_path,
):
    client = TestClient(
        build_app(tmp_path)
    )

    login(client)

    response = client.post(
        "/dashboard/logout",
        data={
            "csrf_token": "invalid-token",
        },
    )

    assert response.status_code == 403

    dashboard = client.get("/dashboard")

    assert dashboard.status_code == 200


def test_timestamp_is_readable():
    result = _format_timestamp(
        "2026-07-19T01:33:49.586261+00:00"
    )

    assert result == (
        "Jul 19, 2026 01:33 AM UTC"
    )
