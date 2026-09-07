"""Offline MCP conformance gate using the official SDK and public contracts."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from mcp import Client
from sqlalchemy import select

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.mcp_server import create_mcp_server
from shieldchain.operations.persistence import AgentToolCallRow
from shieldchain.wazuh.persistence import WazuhAlertRow


async def _verify(database: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, environment="testing")
    sessions = create_session_factory(engine)
    observed_at = datetime(2026, 8, 24, 0, tzinfo=UTC)
    with sessions.begin() as session:
        session.add(
            WazuhAlertRow(
                id="task14-mcp-alert",
                tenant_id=str(settings.rag_demo_tenant_id),
                external_id="task14:mcp:alert",
                occurred_at=observed_at,
                severity=12,
                rule_id="shieldchain.task14.conformance",
                title="Offline MCP conformance alert",
                agent_id=None,
                agent_name="task14",
                mitre_ids_json=[],
                process_name=None,
                parent_process_name=None,
                source_ip=None,
                destination_ip=None,
                destination_port=None,
                evidence_json={},
                received_at=observed_at,
            )
        )
    server = create_mcp_server(
        sessions,
        tenant_id=settings.rag_demo_tenant_id,
        principal_id=settings.rag_demo_principal_id,
    )
    async with Client(server, raise_exceptions=True) as client:
        catalog = await client.list_tools()
        names = [tool.name for tool in catalog.tools]
        expected = [
            "security.alerts.list",
            "security.events.list",
            "security.vulnerabilities.list",
            "security.weak_passwords.list",
        ]
        if client.protocol_version != "2026-07-28" or names != expected:
            raise RuntimeError("MCP protocol or fixed catalog did not match the approved contract")
        if not all(
            tool.annotations
            and tool.annotations.read_only_hint is True
            and tool.annotations.destructive_hint is False
            for tool in catalog.tools
        ):
            raise RuntimeError("MCP catalog exposed a tool outside the read-only boundary")
        result = await client.call_tool(
            "security.alerts.list",
            {
                "start_at": "2026-08-24T00:00:00Z",
                "end_at": "2026-08-24T01:00:00Z",
            },
        )
        if result.is_error or result.structured_content is None:
            raise RuntimeError("MCP tool call did not return a trusted structured result")
        if result.structured_content.get("result_count") != 1:
            raise RuntimeError("MCP tool result did not preserve the bounded test evidence")
    with sessions() as session:
        audit = session.scalar(select(AgentToolCallRow))
        if audit is None or audit.direction != "mcp_inbound" or audit.status != "succeeded":
            raise RuntimeError("MCP tool call did not create the required public audit record")
        if audit.arguments_json.keys() != {"start_at", "end_at", "limit"}:
            raise RuntimeError("MCP audit retained fields outside the public argument allowlist")
    engine.dispose()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="shieldchain-task14-mcp-") as temporary:
        asyncio.run(_verify(Path(temporary) / "conformance.db"))
    print("MCP_CONFORMANCE_TESTED=True")
    print("MCP_PROTOCOL_VERSION=2026-07-28")
    print("NETWORK_ACCESS_TESTED=False")
    print("REAL_IDENTITY_PLATFORM_TESTED=False")
    print("REAL_EXTERNAL_MCP_PEER_TESTED=False")
    print("REAL_DEVICE_PATHS_TESTED=False")


if __name__ == "__main__":
    main()
