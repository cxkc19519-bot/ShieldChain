"""Thread-safe in-memory registration and Phase 3 contact-state persistence."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saga.domain.agents import AgentId, AgentRegistration
    from saga.domain.otk import PublicOtkId
    from saga.domain.token_state import SotkMapping, TokenRecord
    from saga.domain.users import UserId, UserRegistration
    from saga.ports.registration import AgentCreateOutcome, UserCreateOutcome
    from saga.ports.token_state import SotkClaimOutcome, TokenCreateOutcome, TokenUseOutcome

from saga.domain.contact import ContactCommit, ContactSnapshot
from saga.domain.errors import (
    ActPersistenceError,
    ContactPersistenceError,
    RegistrationPersistenceError,
)
from saga.domain.otk import AvailablePublicOtk, PairCounter, PublicOtkId
from saga.domain.users import UserId, UserRegistration
from saga.ports.contact_state import (
    ContactCommitOutcome,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome


class InMemoryUserRegistry:
    """An atomic, thread-safe UserRegistry adapter."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[UserId, UserRegistration] = {}

    def get(self, user_id: UserId) -> UserRegistration | None:
        if type(user_id) is not UserId:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                return self._registrations.get(user_id)
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None

    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome:
        if type(registration) is not UserRegistration:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                if registration.user_id in self._registrations:
                    return UserCreateOutcome.USER_ID_CONFLICT
                self._registrations[registration.user_id] = registration
                return UserCreateOutcome.CREATED
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None


@dataclass(slots=True)
class _MemoryAgentState:
    active: bool
    agent_revision: int
    contact_policy_document: bytes
    policy_version: int
    public_otks: list[AvailablePublicOtk]
    issued_public_keys: set[bytes]
    otk_pool_revision: int


class InMemoryAgentRegistry:
    """An atomic, thread-safe AgentRegistry with global endpoint uniqueness."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[AgentId, AgentRegistration] = {}
        self._agent_ids_by_endpoint: dict[tuple[str, str, int], AgentId] = {}
        self._contact_states: dict[AgentId, _MemoryAgentState] = {}
        self._pair_counters: dict[tuple[AgentId, AgentId], PairCounter] = {}

    def get(self, agent_id: AgentId) -> AgentRegistration | None:
        if type(agent_id) is not AgentId:
            raise RegistrationPersistenceError()
        try:
            with self._lock:
                return self._registrations.get(agent_id)
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None

    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome:
        if type(registration) is not AgentRegistration:
            raise RegistrationPersistenceError()
        endpoint = registration.endpoint
        endpoint_key: tuple[str, str, int] = (endpoint.device, endpoint.ip, endpoint.port)
        try:
            with self._lock:
                if registration.agent_id in self._registrations:
                    return AgentCreateOutcome.AGENT_ID_CONFLICT
                if endpoint_key in self._agent_ids_by_endpoint:
                    return AgentCreateOutcome.ENDPOINT_CONFLICT
                try:
                    self._registrations[registration.agent_id] = registration
                    self._agent_ids_by_endpoint[endpoint_key] = registration.agent_id
                    self._contact_states[registration.agent_id] = _MemoryAgentState(
                        active=True,
                        agent_revision=0,
                        contact_policy_document=registration.contact_policy_document,
                        policy_version=0,
                        public_otks=[
                            AvailablePublicOtk(
                                PublicOtkId(registration.agent_id, ordinal),
                                item.public_key,
                                item.user_signature,
                            )
                            for ordinal, item in enumerate(registration.public_otks)
                        ],
                        issued_public_keys=set(),
                        otk_pool_revision=0,
                    )
                except BaseException:
                    self._registrations.pop(registration.agent_id, None)
                    self._agent_ids_by_endpoint.pop(endpoint_key, None)
                    self._contact_states.pop(registration.agent_id, None)
                    raise
                return AgentCreateOutcome.CREATED
        except (OSError, OverflowError, TypeError, ValueError):
            raise RegistrationPersistenceError() from None

    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot:
        """Return a coherent opaque state view; this adapter never evaluates policy."""
        if type(receiving_agent_id) is not AgentId or type(initiating_agent_id) is not AgentId:
            raise ContactPersistenceError()
        try:
            with self._lock:
                receiving = self._registrations.get(receiving_agent_id)
                initiating = self._registrations.get(initiating_agent_id)
                state = self._contact_states.get(receiving_agent_id)
                if receiving is None or state is None:
                    return ContactSnapshot(
                        None,
                        initiating,
                        False,
                        0,
                        b"{}",
                        0,
                        None,
                        (),
                        0,
                    )
                return ContactSnapshot(
                    receiving,
                    initiating,
                    state.active,
                    state.agent_revision,
                    state.contact_policy_document,
                    state.policy_version,
                    self._pair_counters.get((receiving_agent_id, initiating_agent_id)),
                    tuple(state.public_otks),
                    state.otk_pool_revision,
                )
        except (OSError, OverflowError, TypeError, ValueError):
            raise ContactPersistenceError() from None

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome:
        if type(command) is not ContactCommit:
            raise ContactPersistenceError()
        try:
            with self._lock:
                state = self._contact_states.get(command.receiving_agent_id)
                if state is None or not self._matches_resolution(command, state):
                    return ContactCommitOutcome.CONFLICT
                selected = next(
                    (
                        public_otk
                        for public_otk in state.public_otks
                        if public_otk.otk_id == command.selected_public_otk_id
                    ),
                    None,
                )
                if selected is None:
                    return ContactCommitOutcome.CONFLICT
                key = (command.receiving_agent_id, command.initiating_agent_id)
                state.public_otks.remove(selected)
                state.issued_public_keys.add(selected.public_key)
                state.otk_pool_revision += 1
                self._pair_counters[key] = PairCounter(
                    command.receiving_agent_id,
                    command.initiating_agent_id,
                    command.remaining,
                    0
                    if command.expected_counter is None
                    else command.expected_counter.revision + 1,
                )
                return ContactCommitOutcome.COMMITTED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ContactPersistenceError() from None

    def _matches_resolution(self, command: ContactCommit, state: _MemoryAgentState) -> bool:
        current_counter = self._pair_counters.get(
            (command.receiving_agent_id, command.initiating_agent_id)
        )
        return (
            state.agent_revision == command.expected_agent_revision
            and state.active == command.expected_active
            and state.policy_version == command.expected_policy_version
            and state.otk_pool_revision == command.expected_otk_pool_revision
            and current_counter == command.expected_counter
        )

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        if type(command) is not PolicyReplaceCommit:
            raise ContactPersistenceError()
        try:
            with self._lock:
                state = self._contact_states.get(command.receiving_agent_id)
                if (
                    state is None
                    or state.agent_revision != command.expected_agent_revision
                    or state.active != command.expected_active
                    or state.policy_version != command.expected_policy_version
                ):
                    return ContactCommitOutcome.CONFLICT
                state.contact_policy_document = command.contact_policy_document
                state.policy_version += 1
                state.agent_revision += 1
                return ContactCommitOutcome.COMMITTED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ContactPersistenceError() from None

    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome:
        if type(command) is not OtkAppendCommit:
            raise ContactPersistenceError()
        try:
            with self._lock:
                state = self._contact_states.get(command.receiving_agent_id)
                if (
                    state is None
                    or state.agent_revision != command.expected_agent_revision
                    or state.active != command.expected_active
                    or state.otk_pool_revision != command.expected_otk_pool_revision
                ):
                    return ContactCommitOutcome.CONFLICT
                known_keys = state.issued_public_keys | {
                    public_otk.public_key for public_otk in state.public_otks
                }
                if any(item.public_key in known_keys for item in command.public_otks):
                    return ContactCommitOutcome.CONFLICT
                start = len(known_keys)
                state.public_otks.extend(
                    AvailablePublicOtk(
                        PublicOtkId(command.receiving_agent_id, start + offset),
                        item.public_key,
                        item.user_signature,
                    )
                    for offset, item in enumerate(command.public_otks)
                )
                state.otk_pool_revision += 1
                state.agent_revision += 1
                return ContactCommitOutcome.COMMITTED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ContactPersistenceError() from None

    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome:
        if type(command) is not DeactivateCommit:
            raise ContactPersistenceError()
        try:
            with self._lock:
                state = self._contact_states.get(command.receiving_agent_id)
                if (
                    state is None
                    or state.agent_revision != command.expected_agent_revision
                    or state.active != command.expected_active
                    or not state.active
                ):
                    return ContactCommitOutcome.CONFLICT
                state.active = False
                state.agent_revision += 1
                return ContactCommitOutcome.COMMITTED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ContactPersistenceError() from None


class InMemorySotkStore:
    """Thread-safe in-memory SOTK store with atomic claim-and-delete."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._mappings: dict[PublicOtkId, bytes] = {}
        self._consumed: set[PublicOtkId] = set()

    def store(self, mapping: SotkMapping) -> None:
        from saga.domain.token_state import SotkMapping as _SotkMapping

        if type(mapping) is not _SotkMapping:
            raise ActPersistenceError()
        try:
            with self._lock:
                self._mappings[mapping.otk_id] = mapping.secret_key
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def claim_and_return(
        self, otk_id: PublicOtkId
    ) -> tuple[SotkClaimOutcome, bytes | None]:
        from saga.ports.token_state import SotkClaimOutcome

        if type(otk_id) is not PublicOtkId:
            raise ActPersistenceError()
        try:
            with self._lock:
                if otk_id in self._consumed:
                    return (SotkClaimOutcome.ALREADY_CONSUMED, None)
                secret = self._mappings.pop(otk_id, None)
                if secret is None:
                    return (SotkClaimOutcome.NOT_FOUND, None)
                self._consumed.add(otk_id)
                return (SotkClaimOutcome.CLAIMED, secret)
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def claim_and_delete(self, otk_id: PublicOtkId) -> SotkClaimOutcome:
        outcome, _ = self.claim_and_return(otk_id)
        return outcome

    def get_secret_key(self, otk_id: PublicOtkId) -> bytes | None:
        if type(otk_id) is not PublicOtkId:
            raise ActPersistenceError()
        try:
            with self._lock:
                return self._mappings.get(otk_id)
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None


class InMemoryTokenStateStore:
    """Thread-safe in-memory token state store with CAS semantics."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[tuple[AgentId, bytes], _TokenEntry] = {}

    def create(self, record: TokenRecord) -> TokenCreateOutcome:
        from saga.domain.token_state import TokenRecord as _TokenRecord
        from saga.ports.token_state import TokenCreateOutcome

        if type(record) is not _TokenRecord:
            raise ActPersistenceError()
        try:
            with self._lock:
                key = (record.receiving_agent_id, record.token_nonce)
                if key in self._records:
                    return TokenCreateOutcome.DUPLICATE
                self._records[key] = _TokenEntry(
                    token_nonce=record.token_nonce,
                    receiving_agent_id=record.receiving_agent_id,
                    initiating_agent_access_control_public_key=(
                        record.initiating_agent_access_control_public_key
                    ),
                    sdhk=record.sdhk,
                    issued_at=record.issued_at,
                    expires_at=record.expires_at,
                    q_max=record.q_max,
                    use_count=record.use_count,
                    revision=record.revision,
                )
                return TokenCreateOutcome.CREATED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def get(
        self, *, receiving_agent_id: AgentId, token_nonce: bytes
    ) -> TokenRecord | None:
        from saga.domain.token_state import TokenRecord as _TokenRecord

        try:
            with self._lock:
                entry = self._records.get((receiving_agent_id, token_nonce))
                if entry is None:
                    return None
                return _TokenRecord(
                    token_nonce=entry.token_nonce,
                    receiving_agent_id=entry.receiving_agent_id,
                    initiating_agent_access_control_public_key=(
                        entry.initiating_agent_access_control_public_key
                    ),
                    sdhk=entry.sdhk,
                    issued_at=entry.issued_at,
                    expires_at=entry.expires_at,
                    q_max=entry.q_max,
                    use_count=entry.use_count,
                    revision=entry.revision,
                )
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def try_increment_use(
        self,
        *,
        receiving_agent_id: AgentId,
        token_nonce: bytes,
        expected_revision: int,
    ) -> TokenUseOutcome:
        from saga.ports.token_state import TokenUseOutcome

        try:
            with self._lock:
                key = (receiving_agent_id, token_nonce)
                entry = self._records.get(key)
                if entry is None:
                    return TokenUseOutcome.NOT_FOUND
                if entry.revision != expected_revision:
                    return TokenUseOutcome.CONFLICT
                if entry.use_count >= entry.q_max:
                    return TokenUseOutcome.CONFLICT
                entry.use_count += 1
                entry.revision += 1
                return TokenUseOutcome.INCREMENTED
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def discard(
        self, *, receiving_agent_id: AgentId, token_nonce: bytes
    ) -> bool:
        try:
            with self._lock:
                key = (receiving_agent_id, token_nonce)
                if key in self._records:
                    del self._records[key]
                    return True
                return False
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None

    def find_by_initiator(
        self,
        *,
        receiving_agent_id: AgentId,
        initiating_agent_access_control_public_key: bytes,
    ) -> tuple[TokenRecord, ...]:
        from saga.domain.token_state import TokenRecord as _TokenRecord

        try:
            with self._lock:
                results = []
                for (agent_id, _nonce), entry in self._records.items():
                    if (
                        agent_id == receiving_agent_id
                        and entry.initiating_agent_access_control_public_key
                        == initiating_agent_access_control_public_key
                    ):
                        results.append(
                            _TokenRecord(
                                token_nonce=entry.token_nonce,
                                receiving_agent_id=entry.receiving_agent_id,
                                initiating_agent_access_control_public_key=(
                                    entry.initiating_agent_access_control_public_key
                                ),
                                sdhk=entry.sdhk,
                                issued_at=entry.issued_at,
                                expires_at=entry.expires_at,
                                q_max=entry.q_max,
                                use_count=entry.use_count,
                                revision=entry.revision,
                            )
                        )
                return tuple(results)
        except (OSError, OverflowError, TypeError, ValueError):
            raise ActPersistenceError() from None


@dataclass(slots=True)
class _TokenEntry:
    """Mutable internal token entry for in-memory CAS."""

    token_nonce: bytes
    receiving_agent_id: AgentId
    initiating_agent_access_control_public_key: bytes
    sdhk: bytes
    issued_at: int
    expires_at: int
    q_max: int
    use_count: int
    revision: int


__all__ = (
    "InMemoryAgentRegistry",
    "InMemorySotkStore",
    "InMemoryTokenStateStore",
    "InMemoryUserRegistry",
)

