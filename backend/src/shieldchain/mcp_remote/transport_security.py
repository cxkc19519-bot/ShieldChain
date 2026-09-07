from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .peer_config import McpPeerConfig

IpAddress = IPv4Address | IPv6Address
AddressResolver = Callable[[str, int], Awaitable[tuple[IpAddress, ...]]]


class EndpointRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    endpoint: str
    host: str
    port: int
    addresses: tuple[IpAddress, ...]


async def system_resolver(host: str, port: int) -> tuple[IpAddress, ...]:
    def resolve() -> tuple[IpAddress, ...]:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return tuple(dict.fromkeys(ip_address(record[4][0]) for record in records))

    try:
        addresses = await asyncio.to_thread(resolve)
    except OSError as error:
        raise EndpointRejected("endpoint DNS resolution failed") from error
    if not addresses:
        raise EndpointRejected("endpoint DNS resolution returned no addresses")
    return addresses


async def resolve_and_validate_endpoint(
    peer: McpPeerConfig,
    *,
    resolver: AddressResolver = system_resolver,
) -> ResolvedEndpoint:
    parsed = urlsplit(peer.endpoint)
    host = parsed.hostname
    if host is None:
        raise EndpointRejected("endpoint host is unavailable")
    port = parsed.port or 443
    try:
        addresses = tuple(dict.fromkeys(await resolver(host, port)))
    except EndpointRejected:
        raise
    except Exception as error:
        raise EndpointRejected("endpoint DNS resolution failed") from error
    if not addresses:
        raise EndpointRejected("endpoint DNS resolution returned no addresses")

    if peer.network_policy == "public_https":
        allowed = all(_is_public_address(address) for address in addresses)
    else:
        try:
            networks = tuple(ip_network(item, strict=False) for item in peer.allowed_cidrs)
        except ValueError as error:
            raise EndpointRejected("internal network policy contains an invalid CIDR") from error
        allowed = all(
            not _is_forbidden_address(address) and any(address in network for network in networks)
            for address in addresses
        )
    if not allowed:
        raise EndpointRejected("endpoint DNS address violates network policy")
    return ResolvedEndpoint(
        endpoint=peer.endpoint,
        host=host.casefold(),
        port=port,
        addresses=addresses,
    )


def _is_public_address(address: IpAddress) -> bool:
    return address.is_global and not _is_forbidden_address(address)


def _is_forbidden_address(address: IpAddress) -> bool:
    return any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def validate_dns_rebinding(before: ResolvedEndpoint, after: ResolvedEndpoint) -> None:
    if (
        before.host != after.host
        or before.port != after.port
        or set(before.addresses) != set(after.addresses)
    ):
        raise EndpointRejected("endpoint DNS answer changed during discovery")


def pinned_endpoint(resolved: ResolvedEndpoint) -> str:
    """Use one approved address for the socket while preserving Host and TLS SNI separately."""

    parsed = urlsplit(resolved.endpoint)
    address = resolved.addresses[0]
    host = f"[{address}]" if isinstance(address, IPv6Address) else str(address)
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def validate_connected_peer(resolved: ResolvedEndpoint, response: Any) -> None:
    stream = response.extensions.get("network_stream")
    server_address = stream.get_extra_info("server_addr") if stream is not None else None
    if not server_address or len(server_address) < 2:
        raise EndpointRejected("connected endpoint address is unavailable")
    try:
        connected_ip = ip_address(server_address[0])
        connected_port = int(server_address[1])
    except (TypeError, ValueError) as error:
        raise EndpointRejected("connected endpoint address is invalid") from error
    if connected_ip not in resolved.addresses or connected_port != resolved.port:
        raise EndpointRejected("connected endpoint violates the approved DNS result")
