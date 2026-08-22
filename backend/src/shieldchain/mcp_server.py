from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from uuid import UUID

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from sqlalchemy.orm import Session, sessionmaker
from starlette.applications import Starlette

from shieldchain.core.config import Settings
from shieldchain.operations.mcp_tools import ReadOnlyAgentTool, standard_agent_tools
from shieldchain.operations.react_collaboration import AGENT_TOOL_CATALOG, AgentToolBroker
from shieldchain.operations.schemas import McpToolCallView

MCP_MAX_REQUEST_BYTES = 256 * 1024


def create_mcp_server(session_factory: sessionmaker[Session], *, tenant_id: UUID) -> MCPServer:
    tools = tuple(
        sorted(standard_agent_tools(session_factory, tenant_id), key=lambda item: item.name)
    )
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
        )(_handler_for(tool.name, tools))
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
    tool_name: str, tools: tuple[ReadOnlyAgentTool, ...]
) -> Callable[[datetime, datetime], Awaitable[McpToolCallView]]:
    async def call(start_at: datetime, end_at: datetime) -> McpToolCallView:
        broker = AgentToolBroker(tools, start_at, end_at)
        return await broker.call(tool_name)

    call.__name__ = tool_name.replace(".", "_")
    return call
