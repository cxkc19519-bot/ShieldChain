import asyncio
from ipaddress import ip_address

import pytest

from shieldchain.mcp_remote.client import build_remote_http_client
from shieldchain.mcp_remote.peer_config import McpPeerConfig
from shieldchain.mcp_remote.transport_security import (
    EndpointRejected,
    pinned_endpoint,
    resolve_and_validate_endpoint,
    validate_connected_peer,
    validate_dns_rebinding,
)


def _peer(**updates) -> McpPeerConfig:
    values = {
        "id": "approved-security-platform",
        "enabled": True,
        "transport": "streamable_http",
        "endpoint": "https://security-platform.example.test/mcp",
        "auth": {"mode": "bearer_env", "token_env": "REMOTE_MCP_TOKEN"},
        "network_policy": "public_https",
        "allowed_tools": [
            {
                "remote_name": "alerts_list",
                "alias": "external.approved_security_platform.alerts.list",
                "schema_revision": "approved-v1",
                "classification": "read_only",
                "allowed_roles": ["alert_triage"],
            }
        ],
    }
    values.update(updates)
    return McpPeerConfig.model_validate(values)


def _resolver(*addresses: str):
    async def resolve(_host: str, _port: int):
        return tuple(ip_address(item) for item in addresses)

    return resolve


def test_public_https_accepts_only_global_dns_results() -> None:
    resolved = asyncio.run(
        resolve_and_validate_endpoint(_peer(), resolver=_resolver("8.8.8.8", "1.1.1.1"))
    )

    assert resolved.port == 443
    assert {str(item) for item in resolved.addresses} == {"8.8.8.8", "1.1.1.1"}


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.8",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
    ],
)
def test_public_https_rejects_non_global_or_metadata_addresses(address: str) -> None:
    with pytest.raises(EndpointRejected, match="network policy"):
        asyncio.run(resolve_and_validate_endpoint(_peer(), resolver=_resolver(address)))


def test_all_dns_answers_must_satisfy_policy() -> None:
    with pytest.raises(EndpointRejected, match="network policy"):
        asyncio.run(
            resolve_and_validate_endpoint(_peer(), resolver=_resolver("8.8.8.8", "127.0.0.1"))
        )


def test_internal_https_requires_every_address_in_fixed_cidrs() -> None:
    peer = _peer(network_policy="internal_https", allowed_cidrs=["10.20.0.0/16"])
    resolved = asyncio.run(
        resolve_and_validate_endpoint(peer, resolver=_resolver("10.20.1.8", "10.20.2.9"))
    )
    assert len(resolved.addresses) == 2

    with pytest.raises(EndpointRejected, match="network policy"):
        asyncio.run(
            resolve_and_validate_endpoint(peer, resolver=_resolver("10.20.1.8", "10.21.1.8"))
        )

    for forbidden_peer, address in (
        (_peer(network_policy="internal_https", allowed_cidrs=["127.0.0.0/8"]), "127.0.0.1"),
        (
            _peer(network_policy="internal_https", allowed_cidrs=["169.254.0.0/16"]),
            "169.254.169.254",
        ),
    ):
        with pytest.raises(EndpointRejected, match="network policy"):
            asyncio.run(resolve_and_validate_endpoint(forbidden_peer, resolver=_resolver(address)))


def test_dns_rebinding_requires_the_same_approved_address_set() -> None:
    first = asyncio.run(resolve_and_validate_endpoint(_peer(), resolver=_resolver("8.8.8.8")))
    second = asyncio.run(resolve_and_validate_endpoint(_peer(), resolver=_resolver("1.1.1.1")))

    with pytest.raises(EndpointRejected, match="DNS answer changed"):
        validate_dns_rebinding(first, second)


def test_connection_is_pinned_and_actual_peer_must_match_resolution() -> None:
    resolved = asyncio.run(resolve_and_validate_endpoint(_peer(), resolver=_resolver("8.8.8.8")))

    assert pinned_endpoint(resolved) == "https://8.8.8.8/mcp"

    class Stream:
        @staticmethod
        def get_extra_info(_name: str):
            return ("8.8.8.8", 443)

    validate_connected_peer(
        resolved, type("Response", (), {"extensions": {"network_stream": Stream()}})
    )

    class ReboundStream:
        @staticmethod
        def get_extra_info(_name: str):
            return ("127.0.0.1", 443)

    with pytest.raises(EndpointRejected, match="approved DNS"):
        validate_connected_peer(
            resolved,
            type("Response", (), {"extensions": {"network_stream": ReboundStream()}}),
        )


def test_remote_http_client_never_follows_redirects_or_ambient_proxies() -> None:
    resolved = asyncio.run(resolve_and_validate_endpoint(_peer(), resolver=_resolver("8.8.8.8")))
    client = build_remote_http_client(
        _peer(), "dedicated-token", resolved, maximum_response_bytes=2 * 1024 * 1024
    )

    assert client.follow_redirects is False
    assert client._trust_env is False
    assert client.headers["Authorization"] == "Bearer dedicated-token"
    assert client.headers["Accept-Encoding"] == "identity"
    asyncio.run(client.aclose())
