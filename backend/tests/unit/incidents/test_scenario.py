from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address
from types import MappingProxyType

import pytest

from shieldchain.incidents.integrity import verify_evidence_integrity
from shieldchain.incidents.scenario import collect_evidence, seed_phishing_scenario

NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)


def test_seed_has_exact_safe_simulation_contract() -> None:
    state = seed_phishing_scenario(NOW)

    assert state.generation == 1
    assert state.environment == "simulation"
    assert state.external_incident_id == "INC-2026-0001"
    assert state.alert_id == "ALT-2026-0001"
    assert state.endpoint == "PC-023"
    assert state.username == "zhangsan"
    assert state.source_ip == ip_address("10.10.23.17")
    assert state.alert_status == "pending"
    assert state.remote_ip == ip_address("198.51.100.24")
    assert state.remote_port == 443
    assert state.process_name == "powershell.exe"
    assert state.parent_process_name == "WINWORD.EXE"
    assert state.command_summary == "执行经过脱敏的编码脚本"
    assert state.threat_label == "known-malicious-c2"
    assert state.connection_status == "active"
    assert state.firewall_status == "not_blocked"
    assert state.fail_block_consumed is False
    assert state.created_at == state.updated_at == NOW


def test_seed_creates_fresh_identifiers() -> None:
    first = seed_phishing_scenario(NOW)
    second = seed_phishing_scenario(NOW)

    assert first.simulation_id != second.simulation_id
    assert first.incident_id != second.incident_id


def test_command_summary_is_exact_utf8_without_mojibake_code_points() -> None:
    summary = seed_phishing_scenario(NOW).command_summary
    assert summary.encode("utf-8").decode("utf-8") == summary
    assert "\ufffd" not in summary
    assert all(not 0xE000 <= ord(character) <= 0xF8FF for character in summary)


def test_collect_evidence_has_exact_order_sources_confidence_and_payloads() -> None:
    state = seed_phishing_scenario(NOW)
    evidence = collect_evidence(state, NOW)

    assert tuple(item.evidence_type for item in evidence) == (
        "alert",
        "network_connection",
        "threat_intelligence",
        "process",
        "parent_process",
    )
    assert tuple(item.source for item in evidence) == (
        "simulated_siem",
        "simulated_edr",
        "simulated_ti",
        "simulated_edr",
        "simulated_edr",
    )
    assert tuple(item.confidence for item in evidence) == (0.98, 0.98, 1.0, 0.98, 0.98)
    assert all(item.observed_at == NOW and item.confirmed for item in evidence)
    assert [dict(item.payload) for item in evidence] == [
        {
            "alert_id": "ALT-2026-0001",
            "status": "pending",
            "endpoint": "PC-023",
            "username": "zhangsan",
        },
        {
            "source_ip": "10.10.23.17",
            "remote_ip": "198.51.100.24",
            "remote_port": 443,
            "status": "active",
            "process_name": "powershell.exe",
        },
        {
            "remote_ip": "198.51.100.24",
            "label": "known-malicious-c2",
            "malicious": True,
        },
        {"endpoint": "PC-023", "process_name": "powershell.exe"},
        {
            "endpoint": "PC-023",
            "process_name": "powershell.exe",
            "parent_process_name": "WINWORD.EXE",
            "parent_family": "office",
        },
    ]
    assert tuple(item.raw_reference for item in evidence) == (
        "simulation://alerts/ALT-2026-0001",
        f"simulation://connections/{state.simulation_id}",
        "simulation://threat-intel/198.51.100.24",
        "simulation://processes/PC-023/powershell.exe",
        "simulation://processes/PC-023/powershell.exe/parent",
    )
    assert all(isinstance(item.payload, MappingProxyType) for item in evidence)


def test_collect_evidence_is_deterministic_and_does_not_mutate_state() -> None:
    state = seed_phishing_scenario(NOW)
    original = replace(state)

    first = collect_evidence(state, NOW)
    second = collect_evidence(state, NOW)

    assert state == original
    assert tuple(item.id for item in first) == tuple(item.id for item in second)
    assert tuple(item.integrity_sha256 for item in first) == tuple(
        item.integrity_sha256 for item in second
    )


def test_collect_evidence_hashes_canonical_structured_fields() -> None:
    evidence = collect_evidence(seed_phishing_scenario(NOW), NOW)

    assert all(verify_evidence_integrity(item) for item in evidence)
    assert len({item.integrity_sha256 for item in evidence}) == len(evidence)
    assert len({item.id for item in evidence}) == len(evidence)


def test_collect_evidence_rejects_non_utc_now() -> None:
    state = seed_phishing_scenario(NOW)
    with pytest.raises(ValueError, match="observed_at must be an aware UTC datetime"):
        collect_evidence(state, NOW.replace(tzinfo=None))
