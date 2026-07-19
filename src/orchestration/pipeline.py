"""End-to-end orchestration for the Version 2 SOC Copilot."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.cases.store import SQLiteCaseStore
from src.copilot.service import run_copilot
from src.correlation_engine.cross_source_ssh import (
    detect_cross_source_ssh_compromise,
)
from src.ingestion.snort_loader import ingest_snort_file
from src.ingestion.wazuh_loader import ingest_wazuh_file
from src.triage.builder import build_triage_packet


@dataclass(slots=True)
class PipelineRunSummary:
    """Summary of one end-to-end SOC pipeline execution."""

    snort_event_count: int
    wazuh_event_count: int
    total_event_count: int

    finding_count: int
    saved_case_count: int

    provider: str
    database_path: str

    case_ids: list[str] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        self.provider = self.provider.strip().lower()
        self.database_path = self.database_path.strip()

        if not self.provider:
            raise ValueError(
                "Pipeline provider is required"
            )

        if not self.database_path:
            raise ValueError(
                "Pipeline database path is required"
            )

        numeric_values = (
            self.snort_event_count,
            self.wazuh_event_count,
            self.total_event_count,
            self.finding_count,
            self.saved_case_count,
        )

        if any(value < 0 for value in numeric_values):
            raise ValueError(
                "Pipeline counts cannot be negative"
            )

        if self.total_event_count != (
            self.snort_event_count
            + self.wazuh_event_count
        ):
            raise ValueError(
                "total_event_count does not match "
                "the source event counts"
            )

        if self.saved_case_count != len(
            self.case_ids
        ):
            raise ValueError(
                "saved_case_count does not match case_ids"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable summary."""

        return asdict(self)


def run_cross_source_ssh_pipeline(
    *,
    snort_file: str | Path,
    wazuh_file: str | Path,
    database_path: str | Path,
    provider_name: str = "fallback",
    actor: str = "soc-pipeline",
) -> PipelineRunSummary:
    """Run the complete Snort and Wazuh SSH pipeline."""

    normalized_provider = provider_name.strip().lower()

    if not normalized_provider:
        raise ValueError(
            "provider_name is required"
        )

    normalized_actor = actor.strip()

    if not normalized_actor:
        raise ValueError(
            "actor is required"
        )

    snort_events = ingest_snort_file(
        snort_file
    )

    wazuh_events = ingest_wazuh_file(
        wazuh_file
    )

    all_events = [
        *snort_events,
        *wazuh_events,
    ]

    findings = detect_cross_source_ssh_compromise(
        all_events
    )

    store = SQLiteCaseStore(
        database_path
    )

    saved_case_ids: list[str] = []

    for finding in findings:
        packet = build_triage_packet(
            finding
        )

        copilot_result = run_copilot(
            packet,
            provider_name=normalized_provider,
        )

        case = store.save_packet(
            packet,
            actor=normalized_actor,
        )

        store.save_copilot_result(
            case.case_id,
            copilot_result,
            actor=(
                f"copilot:{copilot_result.provider}"
            ),
        )

        saved_case_ids.append(
            case.case_id
        )

    return PipelineRunSummary(
        snort_event_count=len(snort_events),
        wazuh_event_count=len(wazuh_events),
        total_event_count=len(all_events),
        finding_count=len(findings),
        saved_case_count=len(saved_case_ids),
        provider=normalized_provider,
        database_path=str(
            Path(database_path)
        ),
        case_ids=saved_case_ids,
    )
