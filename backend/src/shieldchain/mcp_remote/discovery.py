from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

import structlog

from shieldchain.core.config import Settings

from .client import official_remote_client
from .peer_config import McpPeerConfig, McpRemoteConfig
from .persistence import McpSnapshotStore, McpToolSnapshot
from .transport_security import (
    AddressResolver,
    EndpointRejected,
    ResolvedEndpoint,
    resolve_and_validate_endpoint,
    system_resolver,
    validate_dns_rebinding,
)

logger = structlog.get_logger()
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2026-07-28", "2025-11-25"})


class DiscoveryClient(Protocol):
    protocol_version: str

    async def list_tools(self, *, cursor: str | None = None): ...


ClientFactory = Callable[[McpPeerConfig, str, ResolvedEndpoint], Any]


class DiscoveryRejected(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class DiscoveryOutcome:
    peer_id: str
    status: str
    reason_code: str | None = None
    catalog_revision: str | None = None


@dataclass(frozen=True, slots=True)
class _PreparedCatalog:
    catalog_revision: str
    tools: tuple[McpToolSnapshot, ...]


class McpDiscoveryService:
    def __init__(
        self,
        store: McpSnapshotStore,
        settings: Settings,
        *,
        client_factory: ClientFactory | None = None,
        resolver: AddressResolver = system_resolver,
        getenv: Callable[[str], str | None] = os.getenv,
    ) -> None:
        self._store = store
        self._settings = settings
        self._client_factory = client_factory or (
            lambda peer, token, resolved: official_remote_client(
                peer,
                token,
                resolved,
                maximum_response_bytes=settings.mcp_remote_max_response_bytes,
            )
        )
        self._resolver = resolver
        self._getenv = getenv

    async def refresh_enabled(self, config: McpRemoteConfig) -> tuple[DiscoveryOutcome, ...]:
        return tuple(
            await asyncio.gather(
                *(self.refresh_peer(peer) for peer in config.servers if peer.enabled)
            )
        )

    async def refresh_peer(
        self,
        peer: McpPeerConfig,
        *,
        now: datetime | None = None,
    ) -> DiscoveryOutcome:
        now = now or datetime.now(UTC)
        if not peer.enabled:
            return DiscoveryOutcome(peer_id=peer.id, status="disabled")
        try:
            async with asyncio.timeout(self._settings.mcp_remote_discovery_timeout_seconds):
                tools, protocol_version = await self._discover(peer)
            snapshot = self._prepare_snapshot(peer, protocol_version, tools)
        except EndpointRejected:
            return self._reject(peer, "mcp_endpoint_rejected", now)
        except DiscoveryRejected as error:
            return self._reject(peer, error.reason_code, now)
        except TimeoutError:
            return self._reject(peer, "mcp_discovery_timed_out", now)
        except Exception as error:
            if _find_exception(error, EndpointRejected) is not None:
                return self._reject(peer, "mcp_endpoint_rejected", now)
            nested_rejection = _find_exception(error, DiscoveryRejected)
            if isinstance(nested_rejection, DiscoveryRejected):
                return self._reject(peer, nested_rejection.reason_code, now)
            if _find_exception(error, TimeoutError) is not None:
                return self._reject(peer, "mcp_discovery_timed_out", now)
            logger.warning(
                "mcp_peer_discovery_failed",
                peer_id=peer.id,
                error_type=type(error).__name__,
            )
            return self._reject(peer, "mcp_discovery_failed", now)

        expires_at = now + timedelta(seconds=self._settings.mcp_remote_snapshot_ttl_seconds)
        self._store.save_accepted(
            peer_id=peer.id,
            endpoint=peer.endpoint,
            network_policy=peer.network_policy,
            protocol_version=protocol_version,
            catalog_revision=snapshot.catalog_revision,
            discovered_at=now,
            expires_at=expires_at,
            tools=snapshot.tools,
        )
        return DiscoveryOutcome(
            peer_id=peer.id,
            status="refreshed",
            catalog_revision=snapshot.catalog_revision,
        )

    async def _discover(self, peer: McpPeerConfig) -> tuple[list[Any], str]:
        before = await resolve_and_validate_endpoint(peer, resolver=self._resolver)
        token = self._getenv(peer.auth.token_env)
        if token is None or not token.strip():
            raise DiscoveryRejected("mcp_credentials_missing")

        discovered: list[Any] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        async with self._client_factory(peer, token, before) as client:
            protocol_version = client.protocol_version
            if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
                raise DiscoveryRejected("mcp_protocol_unsupported")
            for _page in range(self._settings.mcp_remote_max_discovery_pages):
                result = await client.list_tools(cursor=cursor)
                discovered.extend(result.tools)
                if len(discovered) > self._settings.mcp_remote_max_tools:
                    raise DiscoveryRejected("mcp_discovery_limit")
                cursor = result.next_cursor
                if cursor is None:
                    break
                if cursor in seen_cursors:
                    raise DiscoveryRejected("mcp_discovery_limit")
                seen_cursors.add(cursor)
            else:
                raise DiscoveryRejected("mcp_discovery_limit")

        after = await resolve_and_validate_endpoint(peer, resolver=self._resolver)
        validate_dns_rebinding(before, after)
        return discovered, protocol_version

    def _prepare_snapshot(
        self,
        peer: McpPeerConfig,
        protocol_version: str,
        discovered: list[Any],
    ) -> _PreparedCatalog:
        remote_by_name: dict[str, Any] = {}
        total_schema_bytes = 0
        for remote in discovered:
            name = getattr(remote, "name", None)
            if not isinstance(name, str) or not name or len(name) > 128 or name in remote_by_name:
                raise DiscoveryRejected("mcp_discovery_invalid")
            input_schema = self._schema(remote, "input_schema", required=True)
            output_schema = self._schema(remote, "output_schema", required=False)
            input_bytes = _json_size(input_schema)
            output_bytes = _json_size(output_schema) if output_schema is not None else 0
            if max(input_bytes, output_bytes) > self._settings.mcp_remote_max_schema_bytes:
                raise DiscoveryRejected("mcp_discovery_limit")
            total_schema_bytes += input_bytes + output_bytes
            if total_schema_bytes > self._settings.mcp_remote_max_catalog_schema_bytes:
                raise DiscoveryRejected("mcp_discovery_limit")
            remote_by_name[name] = remote

        previous = self._store.latest_accepted(peer.id)
        previous_by_alias = {tool.alias: tool for tool in previous.tools} if previous else {}
        tools: list[McpToolSnapshot] = []
        for approved in peer.allowed_tools:
            remote = remote_by_name.get(approved.remote_name)
            if remote is None:
                raise DiscoveryRejected("mcp_allowed_tool_missing")
            input_schema = self._schema(remote, "input_schema", required=True)
            output_schema = self._schema(remote, "output_schema", required=False)
            prior = previous_by_alias.get(approved.alias)
            schema_changed = prior is not None and (
                prior.input_schema != input_schema or prior.output_schema != output_schema
            )
            if schema_changed and prior.schema_revision == approved.schema_revision:
                raise DiscoveryRejected("mcp_schema_changed")
            annotations = getattr(remote, "annotations", None)
            if annotations is None:
                annotation_data = {}
            elif hasattr(annotations, "model_dump"):
                annotation_data = annotations.model_dump(mode="json", by_alias=True)
            elif isinstance(annotations, dict):
                annotation_data = annotations
            else:
                raise DiscoveryRejected("mcp_discovery_invalid")
            if not isinstance(annotation_data, dict) or _json_size(annotation_data) > 4096:
                raise DiscoveryRejected("mcp_discovery_limit")
            description = getattr(remote, "description", None) or ""
            title = getattr(remote, "title", None) or approved.alias
            if not isinstance(description, str) or len(description) > 4096:
                raise DiscoveryRejected("mcp_discovery_limit")
            if not isinstance(title, str) or not title or len(title) > 256:
                raise DiscoveryRejected("mcp_discovery_invalid")
            tools.append(
                McpToolSnapshot(
                    tool_identity=prior.tool_identity if prior else uuid4(),
                    remote_name=approved.remote_name,
                    alias=approved.alias,
                    label=title,
                    description=description,
                    classification=approved.classification,
                    allowed_roles=approved.allowed_roles,
                    input_schema=input_schema,
                    output_schema=output_schema,
                    remote_annotations=annotation_data,
                    schema_revision=approved.schema_revision,
                )
            )

        ordered = tuple(sorted(tools, key=lambda item: item.alias))
        if previous and previous.protocol_version == protocol_version and previous.tools == ordered:
            catalog_revision = previous.catalog_revision
        else:
            catalog_revision = str(uuid4())
        return _PreparedCatalog(
            catalog_revision=catalog_revision,
            tools=ordered,
        )

    @staticmethod
    def _schema(remote: Any, attribute: str, *, required: bool) -> dict[str, object] | None:
        value = getattr(remote, attribute, None)
        if value is None and not required:
            return None
        if not isinstance(value, dict):
            raise DiscoveryRejected("mcp_discovery_invalid")
        if required and value.get("type") != "object":
            raise DiscoveryRejected("mcp_discovery_invalid")
        _json_size(value)
        return value

    def _reject(self, peer: McpPeerConfig, reason_code: str, now: datetime) -> DiscoveryOutcome:
        self._store.save_rejected(
            peer_id=peer.id,
            endpoint=peer.endpoint,
            network_policy=peer.network_policy,
            error_code=reason_code,
            now=now,
        )
        return DiscoveryOutcome(peer_id=peer.id, status="rejected", reason_code=reason_code)


def _json_size(value: object) -> int:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise DiscoveryRejected("mcp_discovery_invalid") from error
    return len(encoded)


def _find_exception(error: BaseException, expected: type[BaseException]) -> BaseException | None:
    if isinstance(error, expected):
        return error
    if isinstance(error, BaseExceptionGroup):
        for item in error.exceptions:
            match = _find_exception(item, expected)
            if match is not None:
                return match
    return None
