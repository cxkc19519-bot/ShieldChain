from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_address
from types import MappingProxyType

import pytest

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
    assert state.command_summary == "鎵ц缁忚繃鑴辨晱鐨勭紪鐮佽剼鏈琡"
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

    assert tuple(item.integrity_sha256 for item in evidence) == (
        "17dd4b5dfd2bed526fd490a5282846e0f484495e98eb6b97eeafeb9085e76e3c",
        "35cf0f28ef763dd0e7ea9eb8421b072a18f158178940468469eaa3f9ceffe30a",
        "f0acd9e7d62e582a6b496b0e249c648c52302ed65fc5277cf60ca750fc0213c0",
        "21c6fe5e87a4de5e8e516561953461009c60dc64af00ed79e63f50cd36f7d123",
        "2c3105bc6bcca9920e94b54f5632ca19bf8952da6754611587d6d9106b6cc4b8",
    )
    assert tuple(str(item.id) for item in evidence) == (
        "97419c68-080f-58ec-8e71-38900d2f717e",
        "51bfca6a-31ec-546e-9375-48dc515aeb8b",
        "73ee1a46-3fc5-5ae2-b02d-2fa1901259ec",
        "bff6d743-bc8f-5c02-9762-9c74fb7cdd2c",
        "72795a74-6f93-5912-99e2-e942bc4e550a",
    )


def test_collect_evidence_rejects_non_utc_now() -> None:
    state = seed_phishing_scenario(NOW)
    with pytest.raises(ValueError, match="observed_at must be an aware UTC datetime"):
        collect_evidence(state, NOW.replace(tzinfo=None))
