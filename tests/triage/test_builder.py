import pytest

from src.triage.builder import (
    build_triage_packet,
    build_triage_packets,
)


def build_finding() -> dict:
    return {
        "correlation_id": "corr-test-001",
        "rule_id": "CORR-XDR-001",
        "title": (
            "SSH reconnaissance followed by "
            "possible account compromise"
        ),
        "description": (
            "Snort reconnaissance was followed by "
            "Wazuh authentication activity."
        ),
        "severity": "critical",
        "confidence": 0.88,
        "category": "multi_stage_intrusion",
        "first_seen": "2026-07-18T16:18:00+00:00",
        "last_seen": "2026-07-18T16:28:00+00:00",
        "event_ids": [
            "event-1",
            "event-2",
            "event-3",
            "event-4",
            "event-5",
        ],
        "source_products": [
            "snort",
            "wazuh",
        ],
        "source_ip": "192.168.119.131",
        "username": "admin",
        "destination_host": "ubuntu-server",
        "evidence_summary": (
            "Snort detected an SSH scan. Wazuh then "
            "recorded three failed SSH logins followed "
            "by a successful login."
        ),
        "recommended_action": (
            "Validate the SSH session and inspect the host."
        ),
        "tags": [
            "cross_source",
            "network_reconnaissance",
            "credential_access",
            "possible_account_compromise",
        ],
    }


def test_triage_packet_contains_complete_context():
    packet = build_triage_packet(
        build_finding()
    )

    assert packet.correlation_id == "corr-test-001"
    assert packet.priority == "P1"
    assert packet.risk_score == 100
    assert packet.risk_level == "critical"
    assert packet.evidence_count == 5

    assert packet.source_products == [
        "snort",
        "wazuh",
    ]

    assert packet.source_ip == "192.168.119.131"
    assert packet.username == "admin"
    assert packet.destination_host == "ubuntu-server"


def test_triage_packet_contains_mitre_mapping():
    packet = build_triage_packet(
        build_finding()
    )

    technique_ids = [
        technique["technique_id"]
        for technique in packet.mitre_techniques
    ]

    assert technique_ids == [
        "T1078",
        "T1110.001",
        "T1595",
    ]


def test_analyst_note_contains_key_evidence():
    packet = build_triage_packet(
        build_finding()
    )

    assert "P1 critical incident" in packet.analyst_note
    assert "Risk score: 100/100" in packet.analyst_note
    assert "Supporting evidence events: 5" in (
        packet.analyst_note
    )
    assert "T1078 Valid Accounts" in packet.analyst_note
    assert "Validate the SSH session" in (
        packet.analyst_note
    )


def test_case_id_is_deterministic():
    first = build_triage_packet(
        build_finding()
    )

    second = build_triage_packet(
        build_finding()
    )

    assert first.case_id == second.case_id


def test_packet_can_be_serialized():
    packet = build_triage_packet(
        build_finding()
    )

    result = packet.to_dict()

    assert result["case_id"].startswith("case-")
    assert result["risk_score"] == 100
    assert result["evidence_count"] == 5
    assert len(result["mitre_techniques"]) == 3


def test_description_is_used_without_evidence_summary():
    finding = build_finding()
    del finding["evidence_summary"]

    packet = build_triage_packet(finding)

    assert packet.summary == finding["description"]


def test_default_recommendation_is_added():
    finding = build_finding()
    del finding["recommended_action"]

    packet = build_triage_packet(finding)

    assert (
        "Review the supporting evidence"
        in packet.recommended_action
    )


def test_missing_title_is_rejected():
    finding = build_finding()
    del finding["title"]

    with pytest.raises(
        ValueError,
        match="title is required",
    ):
        build_triage_packet(finding)


def test_invalid_confidence_is_rejected():
    finding = build_finding()
    finding["confidence"] = "invalid"

    with pytest.raises(
        ValueError,
        match="confidence must be numeric",
    ):
        build_triage_packet(finding)


def test_invalid_finding_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CorrelationFinding or dictionary",
    ):
        build_triage_packet(
            "invalid"
        )  # type: ignore[arg-type]


def test_multiple_packets_are_built():
    packets = build_triage_packets(
        [
            build_finding(),
            build_finding(),
        ]
    )

    assert len(packets) == 2
    assert all(
        packet.priority == "P1"
        for packet in packets
    )


def test_collection_must_be_a_list():
    with pytest.raises(
        TypeError,
        match="must be provided as a list",
    ):
        build_triage_packets(
            {}
        )  # type: ignore[arg-type]
