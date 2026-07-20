"""Versioned structural persistence contracts for Phase 3 contact state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum as _StrEnum
from typing import Protocol, runtime_checkable

from saga.domain.agents import AgentId, RegisteredPublicOtk
from saga.domain.contact import ContactCommit, ContactSnapshot
from saga.domain.errors import InvalidContactInput


def _non_negative(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidContactInput()
    return value


def _policy_document(value: object) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 65_536:
        raise InvalidContactInput()
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise InvalidContactInput() from None
    return value


def _new_public_otks(value: object) -> tuple[RegisteredPublicOtk, ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 1_024:
        raise InvalidContactInput()
    if any(type(public_otk) is not RegisteredPublicOtk for public_otk in value):
        raise InvalidContactInput()
    if len({public_otk.public_key for public_otk in value}) != len(value):
        raise InvalidContactInput()
    return value


@dataclass(frozen=True, slots=True, repr=False)
class PolicyReplaceCommit:
    """A policy replacement whose validity was decided by the protocol service."""

    receiving_agent_id: AgentId
    contact_policy_document: bytes
    expected_agent_revision: int
    expected_active: bool
    expected_policy_version: int

    def __post_init__(self) -> None:
        if type(self.receiving_agent_id) is not AgentId or type(self.expected_active) is not bool:
            raise InvalidContactInput()
        _policy_document(self.contact_policy_document)
        _non_negative(self.expected_agent_revision)
        _non_negative(self.expected_policy_version)

    def __repr__(self) -> str:
        return f"PolicyReplaceCommit(receiving_agent_id={self.receiving_agent_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class OtkAppendCommit:
    """An already authenticated OTK refill; stores append it structurally only."""

    receiving_agent_id: AgentId
    public_otks: tuple[RegisteredPublicOtk, ...]
    expected_agent_revision: int
    expected_active: bool
    expected_otk_pool_revision: int

    def __post_init__(self) -> None:
        if type(self.receiving_agent_id) is not AgentId or type(self.expected_active) is not bool:
            raise InvalidContactInput()
        _new_public_otks(self.public_otks)
        _non_negative(self.expected_agent_revision)
        _non_negative(self.expected_otk_pool_revision)

    def __repr__(self) -> str:
        return f"OtkAppendCommit(receiving_agent_id={self.receiving_agent_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class DeactivateCommit:
    """A structural terminal-deactivation compare-and-swap request."""

    receiving_agent_id: AgentId
    expected_agent_revision: int
    expected_active: bool

    def __post_init__(self) -> None:
        if type(self.receiving_agent_id) is not AgentId or type(self.expected_active) is not bool:
            raise InvalidContactInput()
        _non_negative(self.expected_agent_revision)


class ContactCommitOutcome(_StrEnum):
    COMMITTED = "committed"
    CONFLICT = "conflict"


@runtime_checkable
class ContactStateStore(Protocol):
    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot: ...

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome: ...

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome: ...

    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome: ...

    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome: ...


__all__ = (
    "ContactCommitOutcome",
    "ContactStateStore",
    "DeactivateCommit",
    "OtkAppendCommit",
    "PolicyReplaceCommit",
)
