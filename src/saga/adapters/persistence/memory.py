"""Thread-safe in-memory registration and Phase 3 contact-state persistence."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from saga.domain.agents import AgentId, AgentRegistration
from saga.domain.contact import ContactCommit, ContactSnapshot
from saga.domain.errors import ContactPersistenceError, RegistrationPersistenceError
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


__all__ = ("InMemoryAgentRegistry", "InMemoryUserRegistry")
