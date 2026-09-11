from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.main import create_app


def _config(path: Path) -> None:
    path.write_text(
        """version: 1
servers:
  - id: approved-peer
    enabled: false
    transport: streamable_http
    endpoint: https://private.example/mcp
    auth:
      mode: bearer_env
      token_env: PRIVATE_MCP_TOKEN
    network_policy: public_https
    allowed_tools:
      - remote_name: alerts.list
        alias: external.approved.alerts_list
        schema_revision: alerts-v1
        classification: read_only
        allowed_roles: [reporting]
""",
        encoding="utf-8",
    )


def test_mcp_status_catalog_and_peers_are_read_only_and_redacted(tmp_path: Path) -> None:
    config = tmp_path / "mcp-remote.yaml"
    _config(config)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    app = create_app(
        database_engine=engine,
        settings=Settings(
            environment="testing",
            mcp_server_enabled=True,
            mcp_auth_mode="disabled",
            mcp_remote_config_path=config,
            simulation_step_delay_ms=0,
        ),
    )

    with TestClient(app) as client:
        status = client.get("/api/v1/mcp/status")
        tools = client.get("/api/v1/mcp/tools")
        peers = client.get("/api/v1/mcp/peers")
        write_attempt = client.post("/api/v1/mcp/peers", json={"endpoint": "https://evil/mcp"})

    assert status.status_code == tools.status_code == peers.status_code == 200
    assert status.json()["server_enabled"] is True
    assert status.json()["boundary"] == "read_only"
    assert status.json()["published_tool_count"] == 4
    assert len(tools.json()["items"]) == 4
    assert {item["classification"] for item in tools.json()["items"]} == {"read_only"}
    assert peers.json()["items"] == [
        {
            "peer_id": "approved-peer",
            "enabled": False,
            "network_policy": "public_https",
            "health": "disabled",
            "protocol_version": None,
            "catalog_revision": None,
            "tool_count": 0,
            "reason_code": None,
            "discovered_at": None,
            "expires_at": None,
        }
    ]
    assert write_attempt.status_code in {404, 405}
    combined = f"{status.text}{tools.text}{peers.text}".casefold()
    for forbidden in (
        "private.example",
        "private_mcp_token",
        "endpoint",
        "bearer_env",
        "client_secret",
        "stack",
    ):
        assert forbidden not in combined
