from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from uuid import UUID, uuid4

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from sqlalchemy.orm import Session, sessionmaker
from starlette.applications import Starlette

from shieldchain.core.config import Settings
from shieldchain.core.request_id import REQUEST_ID_PATTERN
from shieldchain.operations.audit import AgentToolAuditContext, AgentToolAuditStore
from shieldchain.operations.mcp_tools import ReadOnlyAgentTool, standard_agent_tools
from shieldchain.operations.react_collaboration import AGENT_TOOL_CATALOG, AgentToolBroker
from shieldchain.operations.schemas import McpToolCallView

MCP_MAX_REQUEST_BYTES = 256 * 1024


def create_mcp_server(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: UUID,
    principal_id: UUID,
    audit_store: AgentToolAuditStore | None = None,
) -> MCPServer:
    tools = tuple(
        sorted(standard_agent_tools(session_factory, tenant_id), key=lambda item: item.name)
    )
    audit_store = audit_store or AgentToolAuditStore(session_factory)
    server = MCPServer(
        "shieldchain",
        title="ShieldChain read-only security tools",
        description="Read-only security evidence queries; no response actions are exposed.",
        version="0.1.0",
    )
    for tool in tools:
        catalog = AGENT_TOOL_CATALOG[tool.name]
        server.tool(
            name=tool.name,
            title=str(catalog["label"]),
            description=str(catalog["description"]),
            annotations=ToolAnnotations(
                title=str(catalog["label"]),
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            ),
            structured_output=True,
        )(_handler_for(tool.name, tools, audit_store, tenant_id, principal_id))
    return server


def create_mcp_http_app(server: MCPServer, settings: Settings) -> Starlette:
    allowed_hosts = [value for host in settings.http_allowed_hosts for value in (host, f"{host}:*")]
    transport_security = TransportSecuritySettings(
        allowed_hosts=list(dict.fromkeys(allowed_hosts)),
        allowed_origins=list(settings.http_allowed_origins),
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        max_request_body_size=MCP_MAX_REQUEST_BYTES,
        transport_security=transport_security,
    )


def _handler_for(
    tool_name: str,
    tools: tuple[ReadOnlyAgentTool, ...],
    audit_store: AgentToolAuditStore,
    tenant_id: UUID,
    principal_id: UUID,
) -> Callable[..., Awaitable[McpToolCallView]]:
    async def call(start_at: datetime, end_at: datetime, ctx: Context) -> McpToolCallView:
        broker = AgentToolBroker(
            tools,
            start_at,
            end_at,
            audit_store=audit_store,
            audit_context=AgentToolAuditContext(
                tenant_id=tenant_id,
                principal_id=principal_id,
                direction="mcp_inbound",
                request_id=_context_request_id(ctx),
            ),
        )
        return await broker.call(tool_name)

    call.__name__ = tool_name.replace(".", "_")
    return call


def _context_request_id(context: Context) -> str:
    headers = context.headers or {}
    candidate = headers.get("x-request-id") or headers.get("X-Request-ID")
    if candidate is not None and REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    sdk_request_id = context.request_id
    return sdk_request_id if REQUEST_ID_PATTERN.fullmatch(sdk_request_id) else uuid4().hex
