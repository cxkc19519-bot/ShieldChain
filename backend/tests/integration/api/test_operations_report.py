from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url
from shieldchain.main import create_app
from shieldchain.operations.persistence import OperationsRunRow
from shieldchain.wazuh.persistence import WazuhAlertRow


class FailingAlertTool:
    identity = UUID("00000000-0000-4000-8000-000000009997")
    name = "security.alerts.list"
    label = "告警 MCP"
    provider_kind = "builtin"
    provider_id = "test.operations"
    catalog_revision = "test-v1"
    schema_revision = "test-v1"

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
                evidence_json={
                    "pcap_filename": "CVE-2026-1234.pcap",
                    "behavior_findings": ('[{"category":"疑似 UDP/ICMP 洪泛拒绝服务"}]'),
                },
                received_at=datetime(2026, 8, 1, tzinfo=UTC),
            )
        )
    with TestClient(app) as client:
        assert client.post("/api/v1/simulations/phishing/reset").status_code == 404
        assert client.post("/api/v1/investigations", json={}).status_code == 404
        response = client.post(
            "/api/v1/operations/reports",
            headers={"X-Request-ID": "operations-audit-test"},
            json={"start_at": "2026-08-01T00:00:00Z", "end_at": "2026-08-02T00:00:00Z"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["run_id"]
        assert body["run_status"] == "completed"
        calls = {item["name"]: item for item in body["tool_calls"]}
        assert calls["security.alerts.list"]["result_count"] == 1
        assert "疑似 UDP/ICMP 洪泛拒绝服务" in calls["security.alerts.list"]["items"][0]
        assert calls["security.vulnerabilities.list"]["items"][0].startswith("CVE-2026-1234")
        assert len(body["stages"]) == 7
        assert body["response_plan"]["status"] == "completed_advisory"
        assert body["response_plan"]["execution_status"] == "not_executed"
        response_role = next(
            item for item in body["collaboration"] if item["role"] == "response_planning"
        )
        assert response_role["response_plan"]["plan_id"] == body["response_plan"]["plan_id"]
        assert "未执行任何响应计划动作" in body["markdown"]
        calls_response = client.get(f"/api/v1/mcp/runs/{body['run_id']}/calls")
        assert calls_response.status_code == 200
        audit_calls = calls_response.json()["items"]
        assert audit_calls
        assert {item["direction"] for item in audit_calls} == {"internal"}
        assert {item["request_id"] for item in audit_calls} == {"operations-audit-test"}
        assert all("items" not in item for item in audit_calls)
    with app.state.incident_session_factory() as session:
        run = session.get(AgentRunRow, body["run_id"])
        operations_run = session.get(OperationsRunRow, body["run_id"])
        assert run is not None
        assert run.run_kind == "operations_report"
        assert run.status == "completed"
        assert operations_run is not None
        assert operations_run.report_id == body["id"]
        assert session.scalar(select(AgentRunRow).where(AgentRunRow.id == body["run_id"])) is run
    engine.dispose()


def test_operations_report_exposes_sanitized_tool_failure(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations-failure.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, assistant_data_root=tmp_path / "assistant")
    app = create_app(database_engine=engine, settings=settings)
    agent = app.state.security_operations_report_agent
    agent._tools = tuple(
        FailingAlertTool() if tool.name == "security.alerts.list" else tool for tool in agent._tools
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
    failed = next(item for item in body["tool_calls"] if item["name"] == "security.alerts.list")
    assert failed["status"] == "failed"
    assert failed["reason_code"] == "tool_dependency_failed"
    assert failed["result_count"] == 0
    assert failed["items"] == []
    assert "private upstream failure" not in str(failed)
    assert next(stage for stage in body["stages"] if stage["key"] == "mcp_tools")["status"] == (
        "fallback"
    )
    engine.dispose()


def test_operations_report_failure_marks_generic_run_failed(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations-run-failure.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, assistant_data_root=tmp_path / "assistant")
    app = create_app(database_engine=engine, settings=settings)

    async def fail(*_args):
        raise RuntimeError("controlled report failure")

    app.state.security_operations_report_agent._team.run = fail
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/v1/operations/reports",
            json={"start_at": "2026-08-01T00:00:00Z", "end_at": "2026-08-02T00:00:00Z"},
        )

    assert response.status_code == 500
    with app.state.incident_session_factory() as session:
        run = session.scalar(select(AgentRunRow).where(AgentRunRow.run_kind == "operations_report"))
        assert run is not None
        assert run.status == "failed"
        assert run.completed_at is not None
        assert session.get(OperationsRunRow, run.id) is not None
    engine.dispose()
