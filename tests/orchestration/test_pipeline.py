import json
from pathlib import Path

import pytest

from src.cases.store import SQLiteCaseStore
from src.orchestration.pipeline import (
    PipelineRunSummary,
    run_cross_source_ssh_pipeline,
)


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

SNORT_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "test_events"
    / "sample_snort_ssh_recon.json"
)

WAZUH_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "test_events"
    / "sample_wazuh_ssh_compromise.json"
)


def test_pipeline_creates_persistent_case(
    tmp_path,
):
    database = tmp_path / "cases.db"

    summary = run_cross_source_ssh_pipeline(
        snort_file=SNORT_FIXTURE,
        wazuh_file=WAZUH_FIXTURE,
        database_path=database,
        provider_name="fallback",
    )

    assert summary.snort_event_count == 1
    assert summary.wazuh_event_count == 4
    assert summary.total_event_count == 5

    assert summary.finding_count == 1
    assert summary.saved_case_count == 1
    assert len(summary.case_ids) == 1

    store = SQLiteCaseStore(database)

    case = store.get_case(
        summary.case_ids[0]
    )

    assert case is not None
    assert case.priority == "P1"
    assert case.risk_score == 100
    assert case.status == "new"
    assert case.copilot_result is not None

    audit_types = [
        event.event_type
        for event in store.get_audit_events(
            case.case_id
        )
    ]

    assert audit_types == [
        "case_created",
        "copilot_result_saved",
    ]


def test_pipeline_with_unmatched_scan_creates_no_case(
    tmp_path,
):
    snort_payload = json.loads(
        SNORT_FIXTURE.read_text(
            encoding="utf-8"
        )
    )

    snort_payload["src_ip"] = (
        "203.0.113.200"
    )

    unmatched_file = (
        tmp_path / "unmatched-snort.json"
    )

    unmatched_file.write_text(
        json.dumps(snort_payload),
        encoding="utf-8",
    )

    database = tmp_path / "cases.db"

    summary = run_cross_source_ssh_pipeline(
        snort_file=unmatched_file,
        wazuh_file=WAZUH_FIXTURE,
        database_path=database,
        provider_name="fallback",
    )

    assert summary.finding_count == 0
    assert summary.saved_case_count == 0
    assert summary.case_ids == []

    store = SQLiteCaseStore(database)

    assert store.list_cases() == []


def test_pipeline_summary_can_be_serialized(
    tmp_path,
):
    summary = run_cross_source_ssh_pipeline(
        snort_file=SNORT_FIXTURE,
        wazuh_file=WAZUH_FIXTURE,
        database_path=tmp_path / "cases.db",
        provider_name="fallback",
    )

    result = summary.to_dict()

    assert result["provider"] == "fallback"
    assert result["saved_case_count"] == 1
    assert len(result["case_ids"]) == 1


def test_empty_provider_is_rejected(
    tmp_path,
):
    with pytest.raises(
        ValueError,
        match="provider_name is required",
    ):
        run_cross_source_ssh_pipeline(
            snort_file=SNORT_FIXTURE,
            wazuh_file=WAZUH_FIXTURE,
            database_path=tmp_path / "cases.db",
            provider_name=" ",
        )


def test_summary_rejects_invalid_total():
    with pytest.raises(
        ValueError,
        match="total_event_count",
    ):
        PipelineRunSummary(
            snort_event_count=1,
            wazuh_event_count=4,
            total_event_count=4,
            finding_count=1,
            saved_case_count=1,
            provider="fallback",
            database_path="cases.db",
            case_ids=["case-one"],
        )
