from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace

from mcp import Client
from mcp.server import MCPServer

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.main import create_app
from shieldchain.mcp_remote.discovery import McpDiscoveryService
from shieldchain.mcp_remote.peer_config import McpPeerConfig
from shieldchain.mcp_remote.persistence import McpSnapshotStore

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def _peer(*, schema_revision: str = "approved-v1") -> McpPeerConfig:
    return McpPeerConfig.model_validate(
        {
            "id": "approved-security-platform",
            "enabled": True,
            "transport": "streamable_http",
            "endpoint": "https://security-platform.example.test/mcp",
            "auth": {"mode": "bearer_env", "token_env": "REMOTE_MCP_TOKEN"},
            "network_policy": "public_https",
            "allowed_tools": [
                {
                    "remote_name": "alerts_list",
                    "alias": "external.approved_security_platform.alerts.list",
                    "schema_revision": schema_revision,
                    "classification": "read_only",
                    "allowed_roles": ["alert_triage", "threat_investigation"],
                }
            ],
        }
    )


def _remote_tool(*, schema_type: str = "string", name: str = "alerts_list"):
    return SimpleNamespace(
        name=name,
        title="Remote alerts",
        description="Read remote alerts.",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": schema_type}},
        },
        output_schema={"type": "object"},
        annotations=SimpleNamespace(
            model_dump=lambda **_kwargs: {
                "readOnlyHint": False,
                "destructiveHint": True,
            }
        ),
    )


class FakeClient:
    protocol_version = "2026-07-28"

    def __init__(self, tools) -> None:
        self._tools = tools

    async def list_tools(self, *, cursor=None):
        assert cursor is None
        return SimpleNamespace(tools=self._tools, next_cursor=None)


def _factory(tools, seen_tokens: list[str]):
    @asynccontextmanager
    async def open_client(_peer, token: str, _resolved):
        seen_tokens.append(token)
        yield FakeClient(tools)

    return open_client


async def _resolver(_host: str, _port: int):
    return (ip_address("8.8.8.8"),)


def _service(tmp_path, tools, *, tokens=None):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'snapshots.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    seen_tokens = [] if tokens is None else tokens
    service = McpDiscoveryService(
        McpSnapshotStore(factory),
        Settings(_env_file=None),
        client_factory=_factory(tools, seen_tokens),
        resolver=_resolver,
        getenv=lambda name: "top-secret-token" if name == "REMOTE_MCP_TOKEN" else None,
    )
    return engine, McpSnapshotStore(factory), service, seen_tokens


def test_discovery_persists_only_allowlisted_local_policy_and_no_credentials(tmp_path) -> None:
    engine, store, service, seen_tokens = _service(
        tmp_path,
        [_remote_tool(), _remote_tool(name="unapproved_admin_action")],
    )

    outcome = asyncio.run(service.refresh_peer(_peer(), now=NOW))
    snapshot = store.latest_accepted("approved-security-platform")

    assert outcome.status == "refreshed"
    assert seen_tokens == ["top-secret-token"]
    assert snapshot is not None
    assert snapshot.protocol_version == "2026-07-28"
    assert len(snapshot.tools) == 1
    tool = snapshot.tools[0]
    assert tool.remote_name == "alerts_list"
    assert tool.classification == "read_only"
    assert tool.allowed_roles == ("alert_triage", "threat_investigation")
    assert tool.remote_annotations == {"readOnlyHint": False, "destructiveHint": True}
    assert "top-secret-token" not in repr(snapshot)
    engine.dispose()


def test_schema_change_is_blocked_until_admin_revision_changes(tmp_path) -> None:
    engine, store, first, _ = _service(tmp_path, [_remote_tool(schema_type="string")])
    assert asyncio.run(first.refresh_peer(_peer(), now=NOW)).status == "refreshed"

    changed = McpDiscoveryService(
        store,
        Settings(_env_file=None),
        client_factory=_factory([_remote_tool(schema_type="integer")], []),
        resolver=_resolver,
        getenv=lambda _name: "replacement-token",
    )
    rejected = asyncio.run(changed.refresh_peer(_peer(), now=NOW + timedelta(minutes=1)))
    still_approved = store.latest_accepted("approved-security-platform")

    assert rejected.status == "rejected"
    assert rejected.reason_code == "mcp_schema_changed"
    assert still_approved is not None
    assert still_approved.tools[0].input_schema["properties"]["query"]["type"] == "string"

    accepted = asyncio.run(
        changed.refresh_peer(
            _peer(schema_revision="approved-v2"),
            now=NOW + timedelta(minutes=2),
        )
    )
    latest = store.latest_accepted("approved-security-platform")
    assert accepted.status == "refreshed"
    assert latest is not None
    assert latest.tools[0].schema_revision == "approved-v2"
    assert latest.tools[0].input_schema["properties"]["query"]["type"] == "integer"
    engine.dispose()


def test_expired_snapshot_is_displayable_but_not_usable(tmp_path) -> None:
    engine, store, service, _ = _service(tmp_path, [_remote_tool()])
    asyncio.run(service.refresh_peer(_peer(), now=NOW))

    assert store.latest_accepted("approved-security-platform") is not None
    assert store.latest_usable("approved-security-platform", now=NOW + timedelta(hours=2)) is None
    engine.dispose()


def test_dns_rebinding_rejects_discovery_without_replacing_catalog(tmp_path) -> None:
    engine, store, service, _ = _service(tmp_path, [_remote_tool()])
    answers = iter(((ip_address("8.8.8.8"),), (ip_address("1.1.1.1"),)))

    async def rebinding_resolver(_host: str, _port: int):
        return next(answers)

    service._resolver = rebinding_resolver
    outcome = asyncio.run(service.refresh_peer(_peer(), now=NOW))

    assert outcome.status == "rejected"
    assert outcome.reason_code == "mcp_endpoint_rejected"
    assert store.latest_accepted("approved-security-platform") is None
    engine.dispose()


def test_nested_transport_peer_rejection_keeps_stable_security_reason(tmp_path) -> None:
    engine, store, service, _ = _service(tmp_path, [_remote_tool()])

    @asynccontextmanager
    async def rejected_client(_peer, _token: str, _resolved):
        from shieldchain.mcp_remote.transport_security import EndpointRejected

        raise ExceptionGroup("transport", [EndpointRejected("socket peer changed")])
        yield

    service._client_factory = rejected_client
    outcome = asyncio.run(service.refresh_peer(_peer(), now=NOW))

    assert outcome.status == "rejected"
    assert outcome.reason_code == "mcp_endpoint_rejected"
    assert store.latest_accepted("approved-security-platform") is None
    engine.dispose()


def test_official_client_auto_mode_discovers_current_protocol(tmp_path) -> None:
    server = MCPServer("approved-security-platform")

    @server.tool(name="alerts_list")
    def alerts_list(query: str = "") -> dict[str, object]:
        return {"items": [], "query": query}

    @asynccontextmanager
    async def official_client(_peer, _token: str, _resolved):
        async with Client(server, mode="auto", cache=None) as client:
            yield client

    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'official-client.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = McpSnapshotStore(factory)
    service = McpDiscoveryService(
        store,
        Settings(_env_file=None),
        client_factory=official_client,
        resolver=_resolver,
        getenv=lambda _name: "dedicated-remote-token",
    )

    outcome = asyncio.run(service.refresh_peer(_peer(), now=NOW))
    snapshot = store.latest_accepted("approved-security-platform")

    assert outcome.status == "refreshed"
    assert snapshot is not None
    assert snapshot.protocol_version == "2026-07-28"
    engine.dispose()


def test_checked_in_example_is_disabled_and_causes_no_startup_network(tmp_path) -> None:
    root = Path(__file__).resolve().parents[4]
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'disabled-example.db'}")
    Base.metadata.create_all(engine)
    app = create_app(
        database_engine=engine,
        settings=Settings(
            _env_file=None,
            environment="testing",
            mcp_remote_config_path=root / "config/mcp/servers.example.yaml",
        ),
    )

    from fastapi.testclient import TestClient

    with TestClient(app):
        assert app.state.mcp_remote_discovery_outcomes == ()
    engine.dispose()
