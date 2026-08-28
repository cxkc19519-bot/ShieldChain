from __future__ import annotations

import asyncio

from mcp import Client
from mcp.server import MCPServer


def test_official_sdk_negotiates_current_protocol_and_calls_tool() -> None:
    server = MCPServer("ShieldChain protocol baseline")

    @server.tool()
    def alerts_list(limit: int = 50) -> dict[str, int | str]:
        """Return a synthetic alert count for protocol verification."""
        return {"status": "succeeded", "result_count": min(limit, 1)}

    async def verify() -> None:
        async with Client(server, raise_exceptions=True) as client:
            tools = await client.list_tools()
            result = await client.call_tool("alerts_list", {"limit": 1})

            assert client.protocol_version == "2026-07-28"
            assert [tool.name for tool in tools.tools] == ["alerts_list"]
            assert tools.next_cursor is None
            assert result.is_error is False
            assert result.structured_content == {"status": "succeeded", "result_count": 1}

    asyncio.run(verify())
