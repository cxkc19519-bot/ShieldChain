from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from shieldchain.incidents.domain import Evidence, EvidenceScalar, PhishingScenarioState
from shieldchain.incidents.integrity import create_evidence


def seed_phishing_scenario(now: datetime) -> PhishingScenarioState:
    return PhishingScenarioState(
        simulation_id=uuid4(),
        generation=1,
        environment="simulation",
        incident_id=uuid4(),
        external_incident_id="INC-2026-0001",
        alert_id="ALT-2026-0001",
        endpoint="PC-023",
        username="zhangsan",
        source_ip=IPv4Address("10.10.23.17"),
        alert_status="pending",
        remote_ip=IPv4Address("198.51.100.24"),
        remote_port=443,
        process_name="powershell.exe",
        parent_process_name="WINWORD.EXE",
        command_summary="执行经过脱敏的编码脚本",
        threat_label="known-malicious-c2",
        connection_status="active",
        firewall_status="not_blocked",
        fail_block_consumed=False,
        created_at=now,
        updated_at=now,
    )


def _evidence(
    *,
    evidence_type: str,
    source: str,
    observed_at: datetime,
    summary: str,
    raw_reference: str,
    confidence: float,
    payload: Mapping[str, EvidenceScalar],
) -> Evidence:
    return create_evidence(
        evidence_type=evidence_type,
        source=source,
        observed_at=observed_at,
        summary=summary,
        raw_reference=raw_reference,
        confidence=confidence,
        confirmed=True,
        payload=payload,
    )


def collect_evidence(
    state: PhishingScenarioState, now: datetime
) -> tuple[Evidence, ...]:
    remote_ip = str(state.remote_ip)
    endpoint = state.endpoint
    process_name = state.process_name
    return (
        _evidence(
            evidence_type="alert",
            source="simulated_siem",
            observed_at=now,
            summary="Pending phishing alert for endpoint and user",
            raw_reference=f"simulation://alerts/{state.alert_id}",
            confidence=0.98,
            payload={
                "alert_id": state.alert_id,
                "status": state.alert_status,
                "endpoint": endpoint,
                "username": state.username,
            },
        ),
        _evidence(
            evidence_type="network_connection",
            source="simulated_edr",
            observed_at=now,
            summary="Active outbound connection from suspicious process",
            raw_reference=f"simulation://connections/{state.simulation_id}",
            confidence=0.98,
            payload={
                "source_ip": str(state.source_ip),
                "remote_ip": remote_ip,
                "remote_port": state.remote_port,
                "status": state.connection_status,
                "process_name": process_name,
            },
        ),
        _evidence(
            evidence_type="threat_intelligence",
            source="simulated_ti",
            observed_at=now,
            summary="Target IP is identified as malicious",
            raw_reference=f"simulation://threat-intel/{remote_ip}",
            confidence=1.0,
            payload={
                "remote_ip": remote_ip,
                "label": state.threat_label,
                "malicious": True,
            },
        ),
        _evidence(
            evidence_type="process",
            source="simulated_edr",
            observed_at=now,
            summary="Suspicious process observed on endpoint",
            raw_reference=f"simulation://processes/{endpoint}/{process_name}",
            confidence=0.98,
            payload={"endpoint": endpoint, "process_name": process_name},
        ),
        _evidence(
            evidence_type="parent_process",
            source="simulated_edr",
            observed_at=now,
            summary="Office process launched the suspicious process",
            raw_reference=f"simulation://processes/{endpoint}/{process_name}/parent",
            confidence=0.98,
            payload={
                "endpoint": endpoint,
                "process_name": process_name,
                "parent_process_name": state.parent_process_name,
                "parent_family": "office",
            },
        ),
    )
