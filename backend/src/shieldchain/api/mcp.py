from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError
from shieldchain.mcp_remote.discovery import SUPPORTED_PROTOCOL_VERSIONS
from shieldchain.mcp_remote.peer_config import McpRemoteConfig
from shieldchain.mcp_remote.persistence import McpSnapshotStore
from shieldchain.mcp_remote.schemas import (
    McpPeerListView,
    McpPeerPublicView,
    McpStatusView,
    McpToolListView,
    McpToolPublicView,
)
from shieldchain.operations.audit import AgentToolAuditStore, AgentToolRunNotFound
from shieldchain.operations.mcp_tools import standard_agent_tools
from shieldchain.operations.react_collaboration import AGENT_TOOL_CATALOG
from shieldchain.operations.schemas import AgentToolCallAuditListResponse

router = APIRouter(prefix="/mcp", tags=["mcp"])


@router.get("/status", response_model=McpStatusView)
def status(request: Request) -> McpStatusView:
    settings = cast(Settings, request.app.state.settings)
    config = cast(McpRemoteConfig | None, request.app.state.mcp_remote_config)
    published = len(_builtin_tools(request)) if settings.mcp_server_enabled else 0
    return McpStatusView(
        server_enabled=settings.mcp_server_enabled,
        auth_mode=settings.mcp_auth_mode,
        supported_protocol_versions=sorted(SUPPORTED_PROTOCOL_VERSIONS, reverse=True),
        server_version="0.1.0",
        published_tool_count=published,
        configured_peer_count=len(config.servers) if config is not None else 0,
    )


@router.get("/tools", response_model=McpToolListView)
def tools(request: Request) -> McpToolListView:
    settings = cast(Settings, request.app.state.settings)
    config = cast(McpRemoteConfig | None, request.app.state.mcp_remote_config)
    store = cast(McpSnapshotStore, request.app.state.mcp_snapshot_store)
    items: list[McpToolPublicView] = []
    if settings.mcp_server_enabled:
        for tool in _builtin_tools(request):
            catalog = AGENT_TOOL_CATALOG[tool.name]
            items.append(
                McpToolPublicView(
                    name=tool.name,
                    label=tool.label,
                    description=str(catalog["description"]),
                    provider_kind="builtin",
                    provider_id=tool.provider_id,
                    allowed_roles=["mcp_client"],
                    catalog_revision=tool.catalog_revision,
                    schema_revision=tool.schema_revision,
                )
            )
    if config is not None:
        now = datetime.now(UTC)
        for peer in config.servers:
            snapshot = store.latest_usable(peer.id, now=now) if peer.enabled else None
            if snapshot is None:
                continue
            items.extend(
                McpToolPublicView(
                    name=tool.alias,
                    label=tool.label,
                    description=tool.description,
                    provider_kind="remote_mcp",
                    provider_id=peer.id,
                    allowed_roles=list(tool.allowed_roles),
                    catalog_revision=snapshot.catalog_revision,
                    schema_revision=tool.schema_revision,
                )
                for tool in snapshot.tools
            )
    return McpToolListView(items=items)


@router.get("/peers", response_model=McpPeerListView)
def peers(request: Request) -> McpPeerListView:
    config = cast(McpRemoteConfig | None, request.app.state.mcp_remote_config)
    store = cast(McpSnapshotStore, request.app.state.mcp_snapshot_store)
    now = datetime.now(UTC)
    items: list[McpPeerPublicView] = []
    for peer in config.servers if config is not None else ():
        snapshot = store.latest_status(peer.id)
        if not peer.enabled:
            health = "disabled"
        elif snapshot is None:
            health = "undiscovered"
        elif snapshot.status == "rejected":
            health = "rejected"
        elif snapshot.expires_at <= now:
            health = "expired"
        else:
            health = "healthy"
        items.append(
            McpPeerPublicView(
                peer_id=peer.id,
                enabled=peer.enabled,
                network_policy=peer.network_policy,
                health=health,
                protocol_version=snapshot.protocol_version if snapshot else None,
                catalog_revision=snapshot.catalog_revision if snapshot else None,
                tool_count=snapshot.tool_count if snapshot else 0,
                reason_code=snapshot.reason_code if snapshot else None,
                discovered_at=snapshot.discovered_at if snapshot else None,
                expires_at=snapshot.expires_at if snapshot else None,
            )
        )
    return McpPeerListView(items=items)


@router.get("/runs/{run_id}/calls", response_model=AgentToolCallAuditListResponse)
def list_agent_tool_calls(run_id: UUID, request: Request) -> AgentToolCallAuditListResponse:
    store = cast(AgentToolAuditStore, request.app.state.agent_tool_audit_store)
    tenant_id = cast(UUID, request.app.state.rag_demo_tenant_id)
    try:
        return AgentToolCallAuditListResponse(
            items=store.list_for_run(tenant_id=tenant_id, run_id=run_id)
        )
    except AgentToolRunNotFound:
        raise ApiError("agent_tool_run_not_found", "Agent tool run not found", 404) from None


def _builtin_tools(request: Request):
    return standard_agent_tools(
        request.app.state.incident_session_factory,
        cast(UUID, request.app.state.rag_demo_tenant_id),
    )
