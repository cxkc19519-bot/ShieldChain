import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from uuid import UUID

from mcp import Client
from mcp.server import MCPServer

from shieldchain.core.config import Settings
from shieldchain.mcp_remote.peer_config import McpPeerConfig
from shieldchain.mcp_remote.persistence import McpPeerSnapshot, McpToolSnapshot
from shieldchain.mcp_remote.remote_provider import (
    PeerCallGuard,
    RemoteCallBudget,
    RemoteMcpProvider,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


async def _scenario():
    server = MCPServer("approved-peer")

    @server.tool(name="alerts_list", structured_output=True)
    def alerts_list(start_at: str, end_at: str, limit: int = 50) -> dict[str, object]:
        return {
            "summary": f"Queried {start_at} through {end_at}.",
            "items": ["approved remote alert"][:limit],
        }

    async with Client(server, mode="auto", cache=None) as discovery_client:
        listed = (await discovery_client.list_tools()).tools[0]

    peer = McpPeerConfig.model_validate(
        {
            "id": "approved-peer",
            "enabled": True,
            "transport": "streamable_http",
            "endpoint": "https://security.example.test/mcp",
            "auth": {"mode": "bearer_env", "token_env": "REMOTE_MCP_TOKEN"},
            "network_policy": "public_https",
            "allowed_tools": [
                {
                    "remote_name": "alerts_list",
                    "alias": "external.approved.alerts.list",
                    "schema_revision": "approved-v1",
                    "classification": "read_only",
                    "allowed_roles": ["alert_triage"],
                }
            ],
        }
    )
    tool_snapshot = McpToolSnapshot(
        tool_identity=UUID("00000000-0000-4000-8000-000000009001"),
        remote_name="alerts_list",
        alias="external.approved.alerts.list",
        label="Remote alerts",
        description="Remote metadata",
        classification="read_only",
        allowed_roles=("alert_triage",),
        input_schema=listed.input_schema,
        output_schema=listed.output_schema,
        remote_annotations={},
        schema_revision="approved-v1",
    )
    peer_snapshot = McpPeerSnapshot(
        id=UUID("00000000-0000-4000-8000-000000009000"),
        peer_id="approved-peer",
        endpoint=peer.endpoint,
        protocol_version="2026-07-28",
        catalog_revision="catalog-v1",
        discovered_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        tools=(tool_snapshot,),
    )

    @asynccontextmanager
    async def factory(_peer, _token, _resolved):
        async with Client(server, mode="auto", cache=None) as client:
            yield client

    async def resolver(_host, _port):
        return (ip_address("8.8.8.8"),)

    settings = Settings(_env_file=None)
    provider = RemoteMcpProvider(
        peer=peer,
        peer_snapshot=peer_snapshot,
        tool_snapshot=tool_snapshot,
        settings=settings,
        budget=RemoteCallBudget(10),
        guard=PeerCallGuard(settings),
        client_factory=factory,
        resolver=resolver,
        getenv=lambda _name: "dedicated-token",
        now=lambda: NOW,
    )
    return await provider.call(NOW, NOW + timedelta(minutes=5))


def test_official_client_calls_approved_remote_tool_and_returns_bounded_view() -> None:
    execution = asyncio.run(_scenario())

    assert execution.view.status == "succeeded"
    assert execution.view.items == ["approved remote alert"]
    assert execution.view.name == "external.approved.alerts.list"
