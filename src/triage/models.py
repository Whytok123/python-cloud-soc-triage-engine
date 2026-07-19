"""Models for deterministic SOC analyst triage packets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


ALLOWED_RISK_LEVELS = {
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_PRIORITIES = {
    "P1",
    "P2",
    "P3",
    "P4",
}


@dataclass(slots=True)
class AnalystTriagePacket:
    """Evidence-backed incident packet for SOC analyst review."""

    correlation_id: str
    title: str
    summary: str
    severity: str
    confidence: float

    risk_score: int
    risk_level: str
    priority: str

    source_products: list[str]
    event_ids: list[str]

    first_seen: str
    last_seen: str

    source_ip: str | None = None
    username: str | None = None
    destination_host: str | None = None

    mitre_techniques: list[
        dict[str, Any]
    ] = field(default_factory=list)

    recommended_action: str = ""
    analyst_note: str = ""
    tags: list[str] = field(default_factory=list)

    case_id: str = field(init=False)
    evidence_count: int = field(init=False)
    packet_version: str = "1.0"

    def __post_init__(self) -> None:
        """Validate and normalize triage packet values."""

        self.correlation_id = self.correlation_id.strip()
        self.title = self.title.strip()
        self.summary = self.summary.strip()
        self.severity = self.severity.strip().lower()
        self.risk_level = self.risk_level.strip().lower()
        self.priority = self.priority.strip().upper()
        self.first_seen = self.first_seen.strip()
        self.last_seen = self.last_seen.strip()
        self.recommended_action = (
            self.recommended_action.strip()
        )
        self.analyst_note = self.analyst_note.strip()

        if not self.correlation_id:
            raise ValueError(
                "correlation_id is required"
            )

        if not self.title:
            raise ValueError(
                "triage packet title is required"
            )

        if not self.summary:
            raise ValueError(
                "triage packet summary is required"
            )

        if not 0 <= self.confidence <= 1:
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                "risk_score must be between 0 and 100"
            )

        if self.risk_level not in ALLOWED_RISK_LEVELS:
            raise ValueError(
                f"Unsupported risk level: {self.risk_level}"
            )

        if self.priority not in ALLOWED_PRIORITIES:
            raise ValueError(
                f"Unsupported priority: {self.priority}"
            )

        self.source_products = self._normalize_list(
            self.source_products
        )

        self.event_ids = self._normalize_list(
            self.event_ids
        )

        self.tags = self._normalize_list(
            self.tags,
            lowercase=True,
        )

        self.evidence_count = len(self.event_ids)

        fingerprint = json.dumps(
            {
                "correlation_id": self.correlation_id,
                "packet_version": self.packet_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(
            fingerprint.encode("utf-8")
        ).hexdigest()

        self.case_id = f"case-{digest[:16]}"

    @staticmethod
    def _normalize_list(
        values: list[str],
        *,
        lowercase: bool = False,
    ) -> list[str]:
        """Strip and deduplicate a list of text values."""

        normalized_values: list[str] = []

        for value in values:
            if not isinstance(value, str):
                continue

            normalized = value.strip()

            if lowercase:
                normalized = normalized.lower()

            if (
                normalized
                and normalized not in normalized_values
            ):
                normalized_values.append(normalized)

        return normalized_values

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)
