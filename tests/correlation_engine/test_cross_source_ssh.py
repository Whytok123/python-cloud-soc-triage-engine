from datetime import datetime, timedelta, timezone

import pytest

from src.correlation_engine.cross_source_ssh import (
    detect_cross_source_ssh_compromise,
)
from src.normalization.schema import NormalizedEvent


BASE_TIME = datetime(
    2026,
    7,
    18,
    16,
    18,
    tzinfo=timezone.utc,
)


def build_snort_scan(
    *,
    minute_offset: int = 0,
    source_ip: str = "192.168.119.131",
    destination_ip: str = "192.168.119.132",
) -> NormalizedEvent:
    timestamp = (
        BASE_TIME
        + timedelta(minutes=minute_offset)
    ).isoformat()

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network",
        source_product="snort",
        category="network_intrusion",
        action="network_scan",
        outcome="unknown",
        severity="high",
        source_ip=source_ip,
        source_port=44001,
        destination_ip=destination_ip,
        destination_port=22,
        network_protocol="tcp",
        rule_id="1:1000001:1",
        rule_name="Possible SSH SYN scan",
        raw_event={
            "timestamp": timestamp,
            "type": "snort_scan",
        },
    )


def build_wazuh_event(
    *,
    minute_offset: int,
    outcome: str,
    source_ip: str = "192.168.119.131",
    destination_ip: str = "192.168.119.132",
    username: str = "admin",
) -> NormalizedEvent:
    timestamp = (
        BASE_TIME
        + timedelta(minutes=minute_offset)
    ).isoformat()

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="endpoint",
        source_product="wazuh",
        category="authentication",
        action="ssh_authentication",
        outcome=outcome,
        severity="low",
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_host="ubuntu-server",
        rule_id="5710",
        rule_name="SSH authentication event",
        raw_event={
            "timestamp": timestamp,
            "outcome": outcome,
        },
    )


def build_attack_sequence() -> list[NormalizedEvent]:
    return [
        build_snort_scan(
            minute_offset=0
        ),
        build_wazuh_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=4,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=6,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=10,
            outcome="success",
        ),
    ]


def test_complete_attack_sequence_triggers():
    findings = detect_cross_source_ssh_compromise(
        build_attack_sequence()
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CORR-XDR-001"
    assert finding.severity == "critical"
    assert finding.confidence == 0.88
    assert finding.source_products == [
        "snort",
        "wazuh",
    ]
    assert finding.source_ip == "192.168.119.131"
    assert finding.username == "admin"
    assert len(finding.event_ids) == 5


def test_missing_snort_scan_does_not_trigger():
    events = build_attack_sequence()[1:]

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert findings == []


def test_too_few_failures_does_not_trigger():
    events = [
        build_snort_scan(),
        build_wazuh_event(
            minute_offset=2,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=4,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=8,
            outcome="success",
        ),
    ]

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert findings == []


def test_different_target_does_not_trigger():
    events = build_attack_sequence()

    events[0] = build_snort_scan(
        destination_ip="192.168.119.200"
    )

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert findings == []


def test_different_username_does_not_trigger():
    events = build_attack_sequence()

    events[-1] = build_wazuh_event(
        minute_offset=10,
        outcome="success",
        username="different-user",
    )

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert findings == []


def test_scan_after_success_does_not_trigger():
    events = build_attack_sequence()

    events[0] = build_snort_scan(
        minute_offset=15
    )

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert findings == []


def test_activity_outside_window_does_not_trigger():
    events = [
        build_snort_scan(
            minute_offset=0
        ),
        build_wazuh_event(
            minute_offset=35,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=37,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=39,
            outcome="failure",
        ),
        build_wazuh_event(
            minute_offset=42,
            outcome="success",
        ),
    ]

    findings = detect_cross_source_ssh_compromise(
        events,
        window_minutes=30,
    )

    assert findings == []


def test_dictionary_events_are_supported():
    events = [
        event.to_dict()
        for event in build_attack_sequence()
    ]

    findings = detect_cross_source_ssh_compromise(
        events
    )

    assert len(findings) == 1


def test_invalid_minimum_failures_is_rejected():
    with pytest.raises(
        ValueError,
        match="minimum_failures",
    ):
        detect_cross_source_ssh_compromise(
            [],
            minimum_failures=0,
        )


def test_invalid_window_is_rejected():
    with pytest.raises(
        ValueError,
        match="window_minutes",
    ):
        detect_cross_source_ssh_compromise(
            [],
            window_minutes=0,
        )
