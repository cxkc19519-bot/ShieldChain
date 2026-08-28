import asyncio
from ipaddress import ip_address

import httpx2
import pytest

from shieldchain.mcp_remote.client import (
    RemoteResponseTooLarge,
    _BoundedTransport,
    build_remote_http_client,
)
from shieldchain.mcp_remote.peer_config import McpPeerConfig
from shieldchain.mcp_remote.transport_security import ResolvedEndpoint


class Chunks(httpx2.AsyncByteStream):
    async def __aiter__(self):
        yield b"1234"
        yield b"5678"


class ChunkedTransport(httpx2.AsyncBaseTransport):
    async def handle_async_request(self, _request):
        return httpx2.Response(200, stream=Chunks())


async def _read_chunked_response() -> None:
    response = await _BoundedTransport(ChunkedTransport(), 6).handle_async_request(
        httpx2.Request("POST", "https://8.8.8.8/mcp")
    )
    async for _chunk in response.stream:
        pass


def test_chunked_response_is_stopped_at_hard_byte_limit() -> None:
    with pytest.raises(RemoteResponseTooLarge, match="configured limit"):
        asyncio.run(_read_chunked_response())


class DeclaredTransport(httpx2.AsyncBaseTransport):
    async def handle_async_request(self, _request):
        return httpx2.Response(200, headers={"Content-Length": "7"}, stream=Chunks())


async def _read_declared_response() -> None:
    await _BoundedTransport(DeclaredTransport(), 6).handle_async_request(
        httpx2.Request("POST", "https://8.8.8.8/mcp")
    )


def test_declared_response_is_rejected_before_body_read() -> None:
    with pytest.raises(RemoteResponseTooLarge, match="configured limit"):
        asyncio.run(_read_declared_response())


async def _reject_compressed_response() -> None:
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
    resolved = ResolvedEndpoint(
        endpoint=peer.endpoint,
        host="security.example.test",
        port=443,
        addresses=(ip_address("8.8.8.8"),),
    )
    client = build_remote_http_client(
        peer, "dedicated-token", resolved, maximum_response_bytes=1024
    )
    response = httpx2.Response(
        200,
        headers={"Content-Encoding": "gzip"},
        stream=Chunks(),
    )
    try:
        await client._event_hooks["response"][0](response)
    finally:
        await client.aclose()


def test_compressed_response_is_rejected_even_below_wire_limit() -> None:
    with pytest.raises(RemoteResponseTooLarge, match="compressed"):
        asyncio.run(_reject_compressed_response())
