"""Public-safe projections for MCP server, catalogs, and configured peers."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictMcpView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class McpStatusView(StrictMcpView):
    server_enabled: bool
    auth_mode: Literal["disabled", "oauth"]
    supported_protocol_versions: list[str]
    server_version: str
    published_tool_count: int = Field(ge=0)
    configured_peer_count: int = Field(ge=0)
    boundary: Literal["read_only"] = "read_only"


class McpToolPublicView(StrictMcpView):
    name: str
    label: str
    description: str
    provider_kind: Literal["builtin", "remote_mcp"]
    provider_id: str
    classification: Literal["read_only"] = "read_only"
    allowed_roles: list[str]
    catalog_revision: str
    schema_revision: str


class McpToolListView(StrictMcpView):
    items: list[McpToolPublicView]


class McpPeerPublicView(StrictMcpView):
    peer_id: str
    enabled: bool
    network_policy: Literal["public_https", "internal_https"]
    health: Literal["disabled", "undiscovered", "healthy", "expired", "rejected"]
    protocol_version: str | None
    catalog_revision: str | None
    tool_count: int = Field(ge=0)
    reason_code: str | None
    discovered_at: datetime | None
    expires_at: datetime | None


class McpPeerListView(StrictMcpView):
    items: list[McpPeerPublicView]
