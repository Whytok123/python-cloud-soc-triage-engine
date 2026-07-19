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

TEST_API_KEY = (
    "test-only-soc-api-key-"
    "do-not-use-in-production"
)


def build_packet() -> dict:
    """Return a minimal valid persisted case packet."""

    return {
        "case_id": "case-api-test-001",
        "correlation_id": "corr-api-test-001",
        "title": "API test SSH case",
        "priority": "P1",
        "risk_score": 100,
        "risk_level": "critical",
        "event_ids": [
            "event-1",
            "event-2",
        ],
    }


def build_client(
    tmp_path,
) -> tuple[TestClient, object]:
    """Create an isolated API and case database."""

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
    )

    client = TestClient(app)

    client.headers.update(
        {
            "X-SOC-API-Key": TEST_API_KEY,
        }
    )

    return (
        client,
        app,
    )


def test_health_endpoint(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "ai-soc-copilot",
        "version": "2.0.0",
    }


def test_cases_are_empty_initially(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.get("/cases")

    assert response.status_code == 200
    assert response.json() == []


def test_case_can_be_listed_and_read(tmp_path):
    client, app = build_client(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    list_response = client.get("/cases")

    assert list_response.status_code == 200
    assert len(list_response.json()) == 1

    case_response = client.get(
        "/cases/case-api-test-001"
    )

    assert case_response.status_code == 200
    assert case_response.json()["case_id"] == (
        "case-api-test-001"
    )
    assert case_response.json()["status"] == "new"


def test_missing_case_returns_404(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.get(
        "/cases/missing-case"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Case not found: missing-case"
    )


def test_case_can_be_updated(tmp_path):
    client, app = build_client(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    response = client.patch(
        "/cases/case-api-test-001",
        json={
            "status": "investigating",
            "assigned_to": "alice@example.com",
            "note": "Reviewing the SSH evidence.",
            "actor": "alice@example.com",
        },
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "investigating"
    assert result["assigned_to"] == (
        "alice@example.com"
    )


def test_case_audit_history_is_returned(tmp_path):
    client, app = build_client(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    client.patch(
        "/cases/case-api-test-001",
        json={
            "status": "triage",
            "actor": "analyst@example.com",
        },
    )

    response = client.get(
        "/cases/case-api-test-001/audit"
    )

    assert response.status_code == 200

    event_types = [
        event["event_type"]
        for event in response.json()
    ]

    assert event_types == [
        "case_created",
        "case_updated",
    ]


def test_pipeline_endpoint_creates_case(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.post(
        "/pipelines/ssh",
        json={
            "snort_file": (
                "sample_snort_ssh_recon.json"
            ),
            "wazuh_file": (
                "sample_wazuh_ssh_compromise.json"
            ),
            "provider": "fallback",
            "actor": "api-test",
        },
    )

    assert response.status_code == 201

    result = response.json()

    assert result["snort_event_count"] == 1
    assert result["wazuh_event_count"] == 4
    assert result["total_event_count"] == 5
    assert result["finding_count"] == 1
    assert result["saved_case_count"] == 1
    assert len(result["case_ids"]) == 1

    cases_response = client.get("/cases")

    assert cases_response.status_code == 200
    assert len(cases_response.json()) == 1


def test_path_traversal_is_rejected(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.post(
        "/pipelines/ssh",
        json={
            "snort_file": "../secret.json",
            "wazuh_file": (
                "sample_wazuh_ssh_compromise.json"
            ),
            "provider": "fallback",
        },
    )

    assert response.status_code == 400
    assert "configured telemetry directory" in (
        response.json()["detail"]
    )


def test_non_json_input_is_rejected(tmp_path):
    client, _ = build_client(tmp_path)

    response = client.post(
        "/pipelines/ssh",
        json={
            "snort_file": "sample.txt",
            "wazuh_file": (
                "sample_wazuh_ssh_compromise.json"
            ),
            "provider": "fallback",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only JSON telemetry files are supported"
    )


def test_invalid_case_status_returns_422(tmp_path):
    client, app = build_client(tmp_path)

    app.state.case_store.save_packet(
        build_packet()
    )

    response = client.patch(
        "/cases/case-api-test-001",
        json={
            "status": "invalid-status",
        },
    )

    assert response.status_code == 422


def test_health_is_public_without_api_key(
    tmp_path,
):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
    )

    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_missing_api_key_is_rejected(
    tmp_path,
):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
    )

    client = TestClient(app)

    response = client.get("/cases")

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid or missing SOC API key"
    )


def test_invalid_api_key_is_rejected(
    tmp_path,
):
    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=TEST_API_KEY,
    )

    client = TestClient(app)

    response = client.get(
        "/cases",
        headers={
            "X-SOC-API-Key": "incorrect-key",
        },
    )

    assert response.status_code == 401
    assert response.headers[
        "www-authenticate"
    ] == "ApiKey"


def test_missing_server_api_key_fails_closed(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(
        "SOC_API_KEY",
        raising=False,
    )

    app = create_app(
        database_path=tmp_path / "cases.db",
        input_root=INPUT_ROOT,
        api_key=None,
    )

    client = TestClient(app)

    response = client.get("/cases")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "SOC API authentication is not configured"
    )
