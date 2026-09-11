from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from sqlalchemy import select

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.main import create_app
from shieldchain.mcp_auth import MCP_BASE_SCOPE, MCP_TOOL_SCOPES, McpAuthRuntime
from shieldchain.mcp_server import create_mcp_http_app, create_mcp_server
from shieldchain.operations.audit import AgentToolAuditStore
from shieldchain.operations.persistence import AgentToolCallRow


class StaticTokenVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        scopes = {
            "alerts-token": [MCP_BASE_SCOPE, MCP_TOOL_SCOPES["security.alerts.list"]],
            "events-token": [MCP_BASE_SCOPE, MCP_TOOL_SCOPES["security.events.list"]],
            "missing-base-token": [MCP_TOOL_SCOPES["security.alerts.list"]],
        }.get(token)
        if scopes is None:
            return None
        return AccessToken(
            token="",
            client_id="test-client",
            scopes=scopes,
            expires_at=int(datetime(2030, 1, 1, tzinfo=UTC).timestamp()),
            resource="https://shieldchain.example.test/mcp",
            subject="security-operator",
            claims={
                "iss": "https://identity.example.test",
                "shieldchain_tenant_id": "00000000-0000-4000-8000-000000000001",
                "shieldchain_principal_id": "00000000-0000-4000-8000-000000000010",
            },
        )


def _meta() -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _headers(method: str, *, token: str | None = None, tool_name: str | None = None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tool_name:
        headers["Mcp-Name"] = tool_name
    return headers


def test_oauth_resource_server_metadata_challenge_and_scope_matrix(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'mcp-auth.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    settings = Settings(
        _env_file=None,
        environment="testing",
        mcp_server_enabled=True,
    )
    runtime = McpAuthRuntime(
        auth_settings=AuthSettings(
            issuer_url="https://identity.example.test",
            resource_server_url="https://shieldchain.example.test/mcp",
            required_scopes=[MCP_BASE_SCOPE],
        ),
        token_verifier=StaticTokenVerifier(),
        testing_tenant_id=settings.rag_demo_tenant_id,
        testing_principal_id=settings.rag_demo_principal_id,
    )
    server = create_mcp_server(
        factory,
        tenant_id=settings.rag_demo_tenant_id,
        principal_id=settings.rag_demo_principal_id,
        audit_store=AgentToolAuditStore(factory),
        auth_runtime=runtime,
    )
    app = create_mcp_http_app(server, settings)
    discover = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {"_meta": _meta()},
    }
    tool_call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "security.alerts.list",
            "arguments": {
                "start_at": "2026-08-01T00:00:00Z",
                "end_at": "2026-08-02T00:00:00Z",
            },
            "_meta": _meta(),
        },
    }

    with TestClient(app) as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json() == {
            "resource": "https://shieldchain.example.test/mcp",
            "authorization_servers": ["https://identity.example.test"],
            "scopes_supported": [MCP_BASE_SCOPE],
            "bearer_methods_supported": ["header"],
        }

        missing = client.post("/mcp", headers=_headers("server/discover"), json=discover)
        assert missing.status_code == 401
        assert (
            'resource_metadata="https://shieldchain.example.test/'
            in missing.headers["WWW-Authenticate"]
        )

        invalid = client.post(
            "/mcp",
            headers=_headers("server/discover", token="invalid-token"),
            json=discover,
        )
        assert invalid.status_code == 401

        bad_origin = client.post(
            "/mcp",
            headers={
                **_headers("server/discover", token="alerts-token"),
                "Origin": "https://attacker.example.test",
            },
            json=discover,
        )
        assert bad_origin.status_code == 403

        bad_host = client.post(
            "/mcp",
            headers={
                **_headers("server/discover", token="alerts-token"),
                "Host": "attacker.example.test",
            },
            json=discover,
        )
        assert bad_host.status_code == 421

        oversized = client.post(
            "/mcp",
            headers=_headers("server/discover", token="alerts-token"),
            content=json.dumps({**discover, "padding": "x" * (257 * 1024)}),
        )
        assert oversized.status_code == 413

        no_base = client.post(
            "/mcp",
            headers=_headers("server/discover", token="missing-base-token"),
            json=discover,
        )
        assert no_base.status_code == 403

        allowed = client.post(
            "/mcp",
            headers=_headers(
                "tools/call",
                token="alerts-token",
                tool_name="security.alerts.list",
            ),
            json=tool_call,
        )
        assert allowed.status_code == 200
        assert allowed.json()["result"]["structuredContent"]["status"] == "empty"

        denied = client.post(
            "/mcp",
            headers=_headers(
                "tools/call",
                token="events-token",
                tool_name="security.alerts.list",
            ),
            json=tool_call,
        )
        assert denied.status_code == 200
        assert denied.json()["result"]["isError"] is True
        assert "shieldchain:alerts:read" in denied.text

    with factory() as session:
        rows = list(session.scalars(select(AgentToolCallRow).order_by(AgentToolCallRow.created_at)))
        assert [row.status for row in rows] == ["empty", "rejected"]
        assert {row.principal_id for row in rows} == {"00000000-0000-4000-8000-000000000010"}
        assert rows[1].reason_code == "insufficient_scope"

    engine.dispose()


def test_production_app_can_mount_mcp_only_with_complete_oauth_config(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'mcp-production.db'}")
    settings = Settings(
        _env_file=None,
        environment="production",
        mcp_server_enabled=True,
        mcp_auth_mode="oauth",
        mcp_auth_issuer="https://identity.example.test",
        mcp_auth_resource="https://shieldchain.example.test/mcp",
        mcp_auth_jwks_url="https://identity.example.test/.well-known/jwks.json",
        mcp_auth_audience="shieldchain-mcp",
        mcp_auth_subject_principals={"security-operator": "00000000-0000-4000-8000-000000000010"},
    )
    app = create_app(database_engine=engine, settings=settings)
    discover = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {"_meta": _meta()},
    }

    with TestClient(app) as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        response = client.post(
            "/mcp",
            headers=_headers("server/discover"),
            json=discover,
        )
        assert response.status_code == 401

    engine.dispose()
