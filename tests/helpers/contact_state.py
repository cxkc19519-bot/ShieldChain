"""Deterministic, policy-blind substitutes for contact-state port tests."""

from __future__ import annotations

from collections.abc import Callable
from threading import Barrier, Lock, Thread
from typing import TypeVar

from saga.domain import AgentId, ContactCommit, ContactSnapshot
from saga.ports.contact_state import (
    ContactCommitOutcome,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)

_Mutation = ContactCommit | PolicyReplaceCommit | OtkAppendCommit | DeactivateCommit
_Result = TypeVar("_Result")


def run_barrier_workers(participants: int, operation: Callable[[], _Result]) -> tuple[_Result, ...]:
    """Run contenders from one deterministic barrier, without timing sleeps."""
    if type(participants) is not int or participants < 2:
        raise ValueError("barrier participants invalid")
    barrier = Barrier(participants)
    results: list[_Result | None] = [None] * participants

    def run(index: int) -> None:
        barrier.wait(timeout=10)
        results[index] = operation()

    threads = tuple(Thread(target=run, args=(index,)) for index in range(participants))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    if any(thread.is_alive() for thread in threads) or any(result is None for result in results):
        raise RuntimeError("barrier operation incomplete")
    return tuple(results)  # type: ignore[return-value]


class ConflictContactStateStore:
    """Records exact CAS requests and always leaves the supplied snapshot unchanged."""

    def __init__(self, snapshot: ContactSnapshot) -> None:
        if type(snapshot) is not ContactSnapshot:
            raise ValueError("contact snapshot invalid")
        self.snapshot = snapshot
        self._commands: list[_Mutation] = []

    @property
    def commands(self) -> tuple[_Mutation, ...]:
        return tuple(self._commands)

    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot:
        del receiving_agent_id, initiating_agent_id
        return self.snapshot

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome:
        self._commands.append(command)
        return ContactCommitOutcome.CONFLICT

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        self._commands.append(command)
        return ContactCommitOutcome.CONFLICT

    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome:
        self._commands.append(command)
        return ContactCommitOutcome.CONFLICT

    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome:
        self._commands.append(command)
        return ContactCommitOutcome.CONFLICT


class BarrierConflictContactStateStore(ConflictContactStateStore):
    """A two-writer barrier for deterministic conflict tests without polling or sleep."""

    def __init__(self, snapshot: ContactSnapshot, *, participants: int) -> None:
        if type(participants) is not int or participants < 2:
            raise ValueError("barrier participants invalid")
        super().__init__(snapshot)
        self._participants = participants
        self._barrier = Barrier(participants)
        self._lock = Lock()

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome:
        with self._lock:
            self._commands.append(command)
        self._barrier.wait(timeout=5)
        return ContactCommitOutcome.CONFLICT

    def run_two(
        self, operation: Callable[[], ContactCommitOutcome]
    ) -> tuple[ContactCommitOutcome, ContactCommitOutcome]:
        if self._participants != 2:
            raise ValueError("two-writer operation requires two participants")
        results: list[ContactCommitOutcome | None] = [None, None]

        def run(index: int) -> None:
            results[index] = operation()

        threads = tuple(Thread(target=run, args=(index,)) for index in range(2))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads) or any(
            result is None for result in results
        ):
            raise RuntimeError("barrier operation incomplete")
        return (results[0], results[1])


class PolicyBlindContactStateStore(ConflictContactStateStore):
    """A structural fixture that stores opaque policy bytes without evaluating them."""

    def __init__(self, snapshot: ContactSnapshot) -> None:
        super().__init__(snapshot)
        self.last_policy_document: bytes | None = None
        self.policy_match_attempts = 0

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        self._commands.append(command)
        self.last_policy_document = command.contact_policy_document
        return ContactCommitOutcome.COMMITTED


__all__ = (
    "BarrierConflictContactStateStore",
    "ConflictContactStateStore",
    "PolicyBlindContactStateStore",
    "run_barrier_workers",
)
