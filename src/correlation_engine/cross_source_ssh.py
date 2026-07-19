"""Correlate Snort SSH reconnaissance with Wazuh authentication activity."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from src.correlation_engine.models import CorrelationFinding
from src.normalization.schema import NormalizedEvent


RULE_ID = "CORR-XDR-001"
RULE_TITLE = (
    "SSH reconnaissance followed by possible account compromise"
)


def _to_dict(
    event: NormalizedEvent | dict[str, Any],
) -> dict[str, Any]:
    """Convert a supported event into a dictionary."""

    if isinstance(event, NormalizedEvent):
        return event.to_dict()

    if isinstance(event, dict):
        return dict(event)

    raise TypeError(
        "Correlation input must contain NormalizedEvent "
        "objects or dictionaries"
    )


def _parse_timestamp(value: Any) -> datetime:
    """Parse an ISO timestamp and return a UTC datetime."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "Correlation event timestamp is required"
        )

    timestamp = value.strip()

    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(
            f"Invalid correlation timestamp: {value}"
        ) from error

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _is_snort_ssh_scan(
    event: dict[str, Any],
) -> bool:
    """Identify a normalized Snort scan targeting SSH."""

    return (
        event.get("source_product") == "snort"
        and event.get("action") == "network_scan"
        and event.get("destination_port") == 22
    )


def _is_wazuh_ssh_event(
    event: dict[str, Any],
) -> bool:
    """Identify a normalized Wazuh SSH authentication event."""

    return (
        event.get("source_product") == "wazuh"
        and event.get("category") == "authentication"
        and event.get("action") == "ssh_authentication"
        and event.get("outcome") in {
            "failure",
            "success",
        }
    )


def _required_text(
    event: dict[str, Any],
    field_name: str,
) -> str | None:
    """Return a stripped nonempty text value."""

    value = event.get(field_name)

    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _event_id(
    event: dict[str, Any],
) -> str:
    """Return the event ID required for evidence tracking."""

    event_id = _required_text(event, "event_id")

    if event_id is None:
        raise ValueError(
            "Every correlated event must contain an event_id"
        )

    return event_id


def detect_cross_source_ssh_compromise(
    events: Iterable[
        NormalizedEvent | dict[str, Any]
    ],
    *,
    minimum_failures: int = 3,
    window_minutes: int = 30,
) -> list[CorrelationFinding]:
    """Detect scan -> SSH failures -> successful login sequences."""

    if minimum_failures < 1:
        raise ValueError(
            "minimum_failures must be at least 1"
        )

    if window_minutes < 1:
        raise ValueError(
            "window_minutes must be at least 1"
        )

    prepared: list[
        tuple[datetime, dict[str, Any]]
    ] = []

    for original_event in events:
        event = _to_dict(original_event)

        prepared.append(
            (
                _parse_timestamp(
                    event.get("timestamp")
                ),
                event,
            )
        )

    prepared.sort(key=lambda item: item[0])

    snort_scans = [
        item
        for item in prepared
        if _is_snort_ssh_scan(item[1])
    ]

    wazuh_events = [
        item
        for item in prepared
        if _is_wazuh_ssh_event(item[1])
    ]

    findings: list[CorrelationFinding] = []

    for success_time, success_event in wazuh_events:
        if success_event.get("outcome") != "success":
            continue

        source_ip = _required_text(
            success_event,
            "source_ip",
        )
        destination_ip = _required_text(
            success_event,
            "destination_ip",
        )
        username = _required_text(
            success_event,
            "username",
        )
        destination_host = _required_text(
            success_event,
            "destination_host",
        )

        if (
            source_ip is None
            or destination_ip is None
            or username is None
        ):
            continue

        window_start = success_time - timedelta(
            minutes=window_minutes
        )

        failures = [
            (
                event_time,
                event,
            )
            for event_time, event in wazuh_events
            if (
                event.get("outcome") == "failure"
                and _required_text(
                    event,
                    "source_ip",
                )
                == source_ip
                and _required_text(
                    event,
                    "destination_ip",
                )
                == destination_ip
                and _required_text(
                    event,
                    "username",
                )
                == username
                and window_start
                <= event_time
                < success_time
            )
        ]

        if len(failures) < minimum_failures:
            continue

        failures.sort(key=lambda item: item[0])
        first_failure_time = failures[0][0]

        matching_scans = [
            (
                event_time,
                event,
            )
            for event_time, event in snort_scans
            if (
                _required_text(
                    event,
                    "source_ip",
                )
                == source_ip
                and _required_text(
                    event,
                    "destination_ip",
                )
                == destination_ip
                and window_start
                <= event_time
                <= first_failure_time
            )
        ]

        if not matching_scans:
            continue

        scan_time, scan_event = max(
            matching_scans,
            key=lambda item: item[0],
        )

        evidence = [
            (
                scan_time,
                scan_event,
            ),
            *failures,
            (
                success_time,
                success_event,
            ),
        ]

        event_ids = [
            _event_id(event)
            for _, event in evidence
        ]

        confidence = min(
            0.88
            + (
                len(failures)
                - minimum_failures
            )
            * 0.02,
            0.98,
        )

        findings.append(
            CorrelationFinding(
                rule_id=RULE_ID,
                title=RULE_TITLE,
                description=(
                    "A Snort SSH reconnaissance alert was "
                    f"followed by {len(failures)} failed SSH "
                    "authentication attempts and then a "
                    f"successful login within {window_minutes} "
                    "minutes."
                ),
                severity="critical",
                confidence=confidence,
                category="multi_stage_intrusion",
                first_seen=scan_time.isoformat(),
                last_seen=success_time.isoformat(),
                event_ids=event_ids,
                source_products=[
                    "snort",
                    "wazuh",
                ],
                source_ip=source_ip,
                username=username,
                destination_host=destination_host,
                evidence_summary=(
                    f"Snort detected an SSH scan from "
                    f"{source_ip} against {destination_ip}. "
                    f"Wazuh then recorded {len(failures)} "
                    f"failed SSH logins followed by a "
                    f"successful login for {username}."
                ),
                recommended_action=(
                    "Validate whether the successful SSH login "
                    "was authorized. Review session commands, "
                    "process creation, authentication logs, and "
                    "network activity. Investigate or block the "
                    "source IP, rotate affected credentials, and "
                    "preserve forensic evidence."
                ),
                tags=[
                    "cross_source",
                    "snort",
                    "wazuh",
                    "ssh",
                    "network_reconnaissance",
                    "credential_access",
                    "possible_account_compromise",
                ],
            )
        )

    return findings
