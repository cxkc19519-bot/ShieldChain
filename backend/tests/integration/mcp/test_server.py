from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from mcp import Client
from sqlalchemy import select

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.main import create_app
from shieldchain.mcp_server import create_mcp_server
from shieldchain.operations.persistence import AgentToolCallRow
from shieldchain.wazuh.persistence import WazuhAlertRow


def test_official_client_discovers_and_calls_read_only_security_tools(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'mcp.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        session.add(
            WazuhAlertRow(
                id="mcp-alert-id",
                tenant_id=str(settings.rag_demo_tenant_id),
                external_id="mcp:test-alert",
                occurred_at=datetime(2026, 8, 1, 12, tzinfo=UTC),
                severity=12,
                rule_id="shieldchain.mcp.test",
                title="MCP test alert",
                agent_id=None,
                agent_name="test",
                mitre_ids_json=[],
                process_name=None,
                parent_process_name=None,
                source_ip=None,
                destination_ip=None,
                destination_port=None,
                evidence_json={},
                received_at=datetime(2026, 8, 1, 12, tzinfo=UTC),
            )
        )
    server = create_mcp_server(
        session_factory,
        tenant_id=settings.rag_demo_tenant_id,
        principal_id=settings.rag_demo_principal_id,
    )

    async def verify() -> None:
        async with Client(server, raise_exceptions=True) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "security.alerts.list",
                {
                    "start_at": "2026-08-01T00:00:00Z",
                    "end_at": "2026-08-02T00:00:00Z",
                },
            )

            assert client.protocol_version == "2026-07-28"
            assert [tool.name for tool in tools.tools] == [
                "security.alerts.list",
                "security.events.list",
                "security.vulnerabilities.list",
                "security.weak_passwords.list",
            ]
            assert all(tool.annotations and tool.annotations.read_only_hint for tool in tools.tools)
            assert result.is_error is False
            assert result.structured_content is not None
            assert result.structured_content["status"] == "succeeded"
            assert result.structured_content["result_count"] == 1
            assert result.structured_content["items"] == [
                "等级 12｜规则 shieldchain.mcp.test｜MCP test alert"
            ]

    asyncio.run(verify())
    with session_factory() as session:
        audit = session.scalar(select(AgentToolCallRow))
        assert audit is not None
        assert audit.direction == "mcp_inbound"
        assert audit.run_id is None
        assert audit.status == "succeeded"
    engine.dispose()


def test_app_only_mounts_mcp_when_explicitly_enabled(tmp_path: Path) -> None:
    discover = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "server/discover",
    }
    disabled_engine = create_engine_from_url(f"sqlite:///{tmp_path / 'disabled.db'}")
    disabled = create_app(
        database_engine=disabled_engine,
        settings=Settings(_env_file=None, mcp_server_enabled=False),
    )
    assert disabled.state.mcp_server is None
    with TestClient(disabled) as client:
        assert client.post("/mcp", headers=headers, json=discover).status_code == 404

    enabled_engine = create_engine_from_url(f"sqlite:///{tmp_path / 'enabled.db'}")
    enabled = create_app(
        database_engine=enabled_engine,
        settings=Settings(
            _env_file=None,
            environment="testing",
            mcp_server_enabled=True,
        ),
    )
    assert enabled.state.mcp_server is not None
    with TestClient(enabled) as client:
        assert enabled.state.accepting_requests is True
        response = client.post("/mcp", headers=headers, json=discover, follow_redirects=False)
        assert response.status_code == 200
        assert response.json()["result"]["_meta"]["io.modelcontextprotocol/serverInfo"] == {
            "name": "shieldchain",
            "title": "ShieldChain read-only security tools",
            "version": "0.1.0",
            "description": "Read-only security evidence queries; no response actions are exposed.",
        }

    disabled_engine.dispose()
    enabled_engine.dispose()
