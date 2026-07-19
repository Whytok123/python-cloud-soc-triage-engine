"""Build deterministic analyst triage packets."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from src.correlation_engine.models import (
    CorrelationFinding,
)
from src.mitre.mapping import map_finding_to_mitre
from src.risk.scoring import score_correlation_finding
from src.triage.models import AnalystTriagePacket


def _finding_to_dict(
    finding: CorrelationFinding | dict[str, Any],
) -> dict[str, Any]:
    """Convert a supported finding into a dictionary."""

    if isinstance(finding, CorrelationFinding):
        return asdict(finding)

    if isinstance(finding, dict):
        return dict(finding)

    raise TypeError(
        "Triage packet creation requires a "
        "CorrelationFinding or dictionary"
    )


def _required_text(
    finding: dict[str, Any],
    field_name: str,
) -> str:
    """Return a required nonempty string field."""

    value = finding.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} is required for triage"
        )

    return value.strip()


def _optional_text(
    finding: dict[str, Any],
    field_name: str,
) -> str | None:
    """Return an optional nonempty string field."""

    value = finding.get(field_name)

    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _string_list(value: Any) -> list[str]:
    """Return valid string values from a list."""

    if not isinstance(value, list):
        return []

    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def _build_analyst_note(
    *,
    priority: str,
    risk_level: str,
    risk_score: int,
    title: str,
    summary: str,
    evidence_count: int,
    technique_labels: list[str],
    recommended_action: str,
) -> str:
    """Build a deterministic analyst-facing note."""

    technique_text = (
        ", ".join(technique_labels)
        if technique_labels
        else "No deterministic ATT&CK mapping"
    )

    return (
        f"{priority} {risk_level} incident: {title}. "
        f"{summary} "
        f"Risk score: {risk_score}/100. "
        f"Supporting evidence events: {evidence_count}. "
        f"MITRE ATT&CK: {technique_text}. "
        f"Recommended action: {recommended_action}"
    )


def build_triage_packet(
    finding: CorrelationFinding | dict[str, Any],
) -> AnalystTriagePacket:
    """Build one complete analyst triage packet."""

    finding_data = _finding_to_dict(finding)

    correlation_id = _required_text(
        finding_data,
        "correlation_id",
    )

    title = _required_text(
        finding_data,
        "title",
    )

    severity = _required_text(
        finding_data,
        "severity",
    ).lower()

    first_seen = _required_text(
        finding_data,
        "first_seen",
    )

    last_seen = _required_text(
        finding_data,
        "last_seen",
    )

    summary = (
        _optional_text(
            finding_data,
            "evidence_summary",
        )
        or _required_text(
            finding_data,
            "description",
        )
    )

    recommended_action = (
        _optional_text(
            finding_data,
            "recommended_action",
        )
        or "Review the supporting evidence and validate "
        "whether the activity was authorized."
    )

    try:
        confidence = float(
            finding_data.get("confidence")
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "confidence must be numeric for triage"
        ) from error

    event_ids = _string_list(
        finding_data.get("event_ids")
    )

    source_products = _string_list(
        finding_data.get("source_products")
    )

    tags = _string_list(
        finding_data.get("tags")
    )

    risk = score_correlation_finding(
        finding_data
    )

    mitre = map_finding_to_mitre(
        finding_data
    )

    if risk.correlation_id != correlation_id:
        raise ValueError(
            "Risk assessment correlation ID mismatch"
        )

    if mitre.correlation_id != correlation_id:
        raise ValueError(
            "MITRE mapping correlation ID mismatch"
        )

    mitre_techniques = [
        technique.to_dict()
        if hasattr(technique, "to_dict")
        else asdict(technique)
        for technique in mitre.techniques
    ]

    technique_labels = [
        (
            f"{technique.technique_id} "
            f"{technique.name}"
        )
        for technique in mitre.techniques
    ]

    analyst_note = _build_analyst_note(
        priority=risk.priority,
        risk_level=risk.risk_level,
        risk_score=risk.risk_score,
        title=title,
        summary=summary,
        evidence_count=len(event_ids),
        technique_labels=technique_labels,
        recommended_action=recommended_action,
    )

    return AnalystTriagePacket(
        correlation_id=correlation_id,
        title=title,
        summary=summary,
        severity=severity,
        confidence=confidence,
        risk_score=risk.risk_score,
        risk_level=risk.risk_level,
        priority=risk.priority,
        source_products=source_products,
        event_ids=event_ids,
        first_seen=first_seen,
        last_seen=last_seen,
        source_ip=_optional_text(
            finding_data,
            "source_ip",
        ),
        username=_optional_text(
            finding_data,
            "username",
        ),
        destination_host=_optional_text(
            finding_data,
            "destination_host",
        ),
        mitre_techniques=mitre_techniques,
        recommended_action=recommended_action,
        analyst_note=analyst_note,
        tags=tags,
    )


def build_triage_packets(
    findings: list[
        CorrelationFinding | dict[str, Any]
    ],
) -> list[AnalystTriagePacket]:
    """Build triage packets for multiple findings."""

    if not isinstance(findings, list):
        raise TypeError(
            "Correlation findings must be provided as a list"
        )

    return [
        build_triage_packet(finding)
        for finding in findings
    ]
