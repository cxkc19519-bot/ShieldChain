from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url
from shieldchain.main import create_app
from shieldchain.wazuh.persistence import WazuhAlertRow


class FailingAlertTool:
    name = "security.alerts.list"
    label = "告警 MCP"

    def call(self, _start_at: datetime, _end_at: datetime):
        raise RuntimeError("private upstream failure")


def test_operations_report_uses_ingested_alerts_and_disables_simulation_endpoints(
    tmp_path: Path,
) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, assistant_data_root=tmp_path / "assistant")
    app = create_app(database_engine=engine, settings=settings)

    async def fallback(*_args):
        return "???????????", None, True

    app.state.security_operations_report_agent._synthesize = fallback
    with app.state.incident_session_factory.begin() as session:
        session.add(
            WazuhAlertRow(
                id="a" * 36,
                tenant_id=str(settings.rag_demo_tenant_id),
                external_id="nta-offline:test",
                occurred_at=datetime(2026, 8, 1, tzinfo=UTC),
                severity=12,
                rule_id="nta.alert",
                title="CVE-2026-1234 WebShell evidence",
                agent_id=None,
                agent_name="nta-offline",
                mitre_ids_json=[],
                process_name=None,
                parent_process_name=None,
                source_ip=None,
                destination_ip=None,
                destination_port=None,
                evidence_json={"pcap_filename": "CVE-2026-1234.pcap"},
                received_at=datetime(2026, 8, 1, tzinfo=UTC),
            )
        )
    with TestClient(app) as client:
        assert client.post("/api/v1/simulations/phishing/reset").status_code == 404
        assert client.post("/api/v1/investigations", json={}).status_code == 404
        response = client.post(
            "/api/v1/operations/reports",
            json={"start_at": "2026-08-01T00:00:00Z", "end_at": "2026-08-02T00:00:00Z"},
        )
        assert response.status_code == 201
        body = response.json()
        calls = {item["name"]: item for item in body["tool_calls"]}
        assert calls["security.alerts.list"]["result_count"] == 1
        assert calls["security.vulnerabilities.list"]["items"][0].startswith("CVE-2026-1234")
        assert len(body["stages"]) == 6
    engine.dispose()


def test_operations_report_exposes_sanitized_tool_failure(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations-failure.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, assistant_data_root=tmp_path / "assistant")
    app = create_app(database_engine=engine, settings=settings)
    agent = app.state.security_operations_report_agent
    agent._tools = tuple(
        FailingAlertTool() if tool.name == "security.alerts.list" else tool
        for tool in agent._tools
    )

    async def fallback(*_args):
        return "工具失败，必须人工复核。", None, True

    agent._synthesize = fallback
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/operations/reports",
            json={"start_at": "2026-08-01T00:00:00Z", "end_at": "2026-08-02T00:00:00Z"},
        )

    assert response.status_code == 201
    body = response.json()
    failed = next(
        item for item in body["tool_calls"] if item["name"] == "security.alerts.list"
    )
    assert failed["status"] == "failed"
    assert failed["reason_code"] == "tool_dependency_failed"
    assert failed["result_count"] == 0
    assert failed["items"] == []
    assert "private upstream failure" not in str(failed)
    assert next(stage for stage in body["stages"] if stage["key"] == "mcp_tools")["status"] == (
        "fallback"
    )
    engine.dispose()
