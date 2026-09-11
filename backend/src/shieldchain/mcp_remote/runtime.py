from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from shieldchain.core.config import Settings
from shieldchain.operations.mcp_tools import ReadOnlyAgentTool

from .peer_config import McpRemoteConfig
from .persistence import McpSnapshotStore
from .remote_provider import PeerCallGuard, RemoteCallBudget, RemoteMcpProvider


@dataclass(frozen=True, slots=True)
class RemoteSnapshotBinding:
    peer_id: str
    peer_snapshot_id: UUID
    catalog_revision: str


@dataclass(frozen=True, slots=True)
class RemoteRunCatalog:
    catalog_revision: str
    tools: tuple[ReadOnlyAgentTool, ...]
    bindings: tuple[RemoteSnapshotBinding, ...]


class McpRemoteRuntime:
    def __init__(
        self,
        store: McpSnapshotStore,
        config: McpRemoteConfig,
        settings: Settings,
        *,
        client_factory=None,
        resolver=None,
        getenv=None,
    ) -> None:
        self._store = store
        self._config = config
        self._settings = settings
        self._client_factory = client_factory
        self._resolver = resolver
        self._getenv = getenv
        self._guards = {peer.id: PeerCallGuard(settings) for peer in config.servers if peer.enabled}

    def prepare_run(self, *, now: datetime) -> RemoteRunCatalog:
        budget = RemoteCallBudget(self._settings.mcp_remote_max_calls_per_run)
        providers: list[ReadOnlyAgentTool] = []
        bindings: list[RemoteSnapshotBinding] = []
        for peer in self._config.servers:
            if not peer.enabled:
                continue
            snapshot = self._store.latest_usable(peer.id, now=now)
            if snapshot is None or snapshot.endpoint != peer.endpoint:
                continue
            bindings.append(
                RemoteSnapshotBinding(
                    peer_id=peer.id,
                    peer_snapshot_id=snapshot.id,
                    catalog_revision=snapshot.catalog_revision,
                )
            )
            for tool in snapshot.tools:
                kwargs = {
                    "peer": peer,
                    "peer_snapshot": snapshot,
                    "tool_snapshot": tool,
                    "settings": self._settings,
                    "budget": budget,
                    "guard": self._guards[peer.id],
                }
                if self._client_factory is not None:
                    kwargs["client_factory"] = self._client_factory
                if self._resolver is not None:
                    kwargs["resolver"] = self._resolver
                if self._getenv is not None:
                    kwargs["getenv"] = self._getenv
                providers.append(RemoteMcpProvider(**kwargs))
        return RemoteRunCatalog(
            catalog_revision=str(uuid4()) if bindings else "builtin-read-only-v1",
            tools=tuple(providers),
            bindings=tuple(bindings),
        )
