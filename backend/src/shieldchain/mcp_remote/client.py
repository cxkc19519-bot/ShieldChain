from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .peer_config import McpPeerConfig
from .transport_security import ResolvedEndpoint, pinned_endpoint, validate_connected_peer


class RemoteResponseTooLarge(RuntimeError):
    pass


class _BoundedResponseStream(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, maximum_bytes: int) -> None:
        self._stream = stream
        self._maximum_bytes = maximum_bytes

    async def __aiter__(self):
        total = 0
        async for chunk in self._stream:
            total += len(chunk)
            if total > self._maximum_bytes:
                raise RemoteResponseTooLarge("remote MCP response exceeds the configured limit")
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _BoundedTransport(httpx2.AsyncBaseTransport):
    def __init__(self, transport: httpx2.AsyncBaseTransport, maximum_bytes: int) -> None:
        self._transport = transport
        self._maximum_bytes = maximum_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        response = await self._transport.handle_async_request(request)
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                if int(content_length) > self._maximum_bytes:
                    await response.aclose()
                    raise RemoteResponseTooLarge("remote MCP response exceeds the configured limit")
            except ValueError as error:
                await response.aclose()
                raise RemoteResponseTooLarge("remote MCP response length is invalid") from error
        response.stream = _BoundedResponseStream(response.stream, self._maximum_bytes)
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()


def build_remote_http_client(
    peer: McpPeerConfig,
    token: str,
    resolved: ResolvedEndpoint,
    *,
    maximum_response_bytes: int,
) -> httpx2.AsyncClient:
    timeout = httpx2.Timeout(30.0, connect=5.0)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept-Encoding": "identity",
        "Host": f"[{resolved.host}]" if ":" in resolved.host else resolved.host,
        "User-Agent": "ShieldChain-MCP-Client/0.1",
    }

    async def pin_request(request: httpx2.Request) -> None:
        request.extensions["sni_hostname"] = resolved.host

    async def verify_response(response: httpx2.Response) -> None:
        try:
            if response.headers.get("Content-Encoding", "identity").casefold() != "identity":
                raise RemoteResponseTooLarge("compressed remote MCP responses are not accepted")
            validate_connected_peer(resolved, response)
        except Exception:
            await response.aclose()
            raise

    limits = httpx2.Limits(max_connections=4, max_keepalive_connections=4)
    transport = _BoundedTransport(
        httpx2.AsyncHTTPTransport(
            verify=str(peer.tls_ca_bundle) if peer.tls_ca_bundle is not None else True,
            trust_env=False,
            limits=limits,
        ),
        maximum_response_bytes,
    )
    return httpx2.AsyncClient(
        headers=headers,
        timeout=timeout,
        follow_redirects=False,
        limits=limits,
        event_hooks={"request": [pin_request], "response": [verify_response]},
        transport=transport,
        trust_env=False,
    )


@asynccontextmanager
async def official_remote_client(
    peer: McpPeerConfig,
    token: str,
    resolved: ResolvedEndpoint,
    *,
    maximum_response_bytes: int = 2 * 1024 * 1024,
) -> AsyncIterator[Client]:
    async with build_remote_http_client(
        peer,
        token,
        resolved,
        maximum_response_bytes=maximum_response_bytes,
    ) as http_client:
        transport = streamable_http_client(
            pinned_endpoint(resolved),
            http_client=http_client,
            terminate_on_close=False,
        )
        async with Client(
            transport,
            mode="auto",
            cache=None,
            read_timeout_seconds=30,
        ) as client:
            yield client
