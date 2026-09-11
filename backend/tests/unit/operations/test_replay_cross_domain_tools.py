from datetime import UTC, datetime
from uuid import UUID, uuid4

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.operations.mcp_tools import AlertMcpTool, VulnerabilityMcpTool, WeakPasswordMcpTool
from shieldchain.wazuh.persistence import WazuhAlertRow


def test_replay_context_projects_network_endpoint_identity_and_vulnerability(tmp_path) -> None:
    tenant_id = UUID("00000000-0000-4000-8000-000000000001")
    now = datetime(2026, 9, 8, tzinfo=UTC)
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'cross-domain.db'}")
    Base.metadata.create_all(engine)
    sessions = create_session_factory(engine)
    with sessions.begin() as session:
        session.add(
            WazuhAlertRow(
                id=str(uuid4()),
                tenant_id=str(tenant_id),
                external_id="nta-replay:test",
                occurred_at=now,
                severity=12,
                rule_id="suricata:9000091",
                title="NTA 隔离回放：ThinkPHP command execution",
                agent_id="002",
                agent_name="nta-isolated-replay-suricata",
                mitre_ids_json=["T1190"],
                process_name=None,
                parent_process_name=None,
                source_ip="198.51.100.103",
                destination_ip="172.18.0.10",
                destination_port=8080,
                evidence_json={
                    "source_kind": "nta_pcap_isolated_replay",
                    "endpoint_process": "php-fpm",
                    "endpoint_parent_process": "nginx",
                    "identity_account": "www-data",
                    "identity_activity": "服务账号与同一回放运行关联；属于演示映射",
                    "vulnerability_indicator": "ThinkPHP/PHP Web 应用入口",
                    "vulnerability_evidence_level": "signature_only_unconfirmed",
                },
                received_at=now,
            )
        )

    alerts = AlertMcpTool(sessions, tenant_id).call(now, now)
    vulnerabilities = VulnerabilityMcpTool(sessions, tenant_id).call(now, now)
    identities = WeakPasswordMcpTool(sessions, tenant_id).call(now, now)

    assert alerts.result_count == 1
    assert "198.51.100.103 → 172.18.0.10:8080" in alerts.items[0]
    assert "nginx → php-fpm" in alerts.items[0]
    assert vulnerabilities.result_count == 1
    assert "ThinkPHP/PHP Web 应用入口" in vulnerabilities.items[0]
    assert "资产版本尚未确认" in vulnerabilities.items[0]
    assert identities.result_count == 1
    assert "www-data" in identities.items[0]
    assert "演示映射" in identities.summary
    engine.dispose()
