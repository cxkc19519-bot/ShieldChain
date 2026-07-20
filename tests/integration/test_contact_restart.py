"""Phase 3 restart and post-commit delivery evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Barrier, Event, Thread

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.domain.contact import ContactCommit, ResolveContactCommand
from saga.domain.errors import (
    ConcurrentContactConflict,
    ContactBundleVerificationFailed,
    ContactPersistenceError,
    PairBudgetExhausted,
)
from saga.protocols.contact_resolution import ContactBundleVerifier, ContactResolutionService
from tests.helpers.registration import FixedClock
from tests.integration.test_contact_atomicity import make_backend


def test_restart_never_reissues_a_committed_public_otk_or_restores_pair_budget(
    tmp_path: Path,
) -> None:
    database = tmp_path / "restart.sqlite3"
    state = make_backend(
        backend="sqlite",
        database=database,
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    command = ResolveContactCommand(state.agent_id, state.agent_id)
    first = ContactResolutionService(
        contact_state_store=state.agents,
        user_registry=state.users,  # type: ignore[arg-type]
    ).resolve(command)

    reopened_agents = SQLiteAgentRegistry(database)
    reopened_users = SQLiteUserRegistry(database)
    second = ContactResolutionService(
        contact_state_store=reopened_agents, user_registry=reopened_users
    ).resolve(command)
    reopened_again = SQLiteAgentRegistry(database)

    assert (first.public_otk.otk_id.ordinal, second.public_otk.otk_id.ordinal) == (0, 1)
    with pytest.raises(PairBudgetExhausted):
        ContactResolutionService(
            contact_state_store=reopened_again, user_registry=SQLiteUserRegistry(database)
        ).resolve(command)
    final = reopened_again.read_snapshot(
        receiving_agent_id=state.agent_id, initiating_agent_id=state.agent_id
    )
    assert final.pair_counter is not None and final.pair_counter.remaining == 0
    assert final.available_public_otks == ()


def test_commit_survives_post_delivery_verification_failure_and_restart(tmp_path: Path) -> None:
    database = tmp_path / "post-delivery.sqlite3"
    state = make_backend(
        backend="sqlite",
        database=database,
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    command = ResolveContactCommand(state.agent_id, state.agent_id)
    first = ContactResolutionService(
        contact_state_store=state.agents,
        user_registry=state.users,  # type: ignore[arg-type]
    ).resolve(command)
    with pytest.raises(ContactBundleVerificationFailed):
        ContactBundleVerifier(
            clock=FixedClock(state.fixtures.now_ms),
            trust_anchor_der=state.fixtures.anchor_der,
            provider_public_key=b"x" * 32,
        ).verify(first)

    second = ContactResolutionService(
        contact_state_store=SQLiteAgentRegistry(database),
        user_registry=SQLiteUserRegistry(database),
    ).resolve(command)
    assert (first.public_otk.otk_id.ordinal, second.public_otk.otk_id.ordinal) == (0, 1)


def test_failed_sqlite_commit_never_partially_issues_an_otk_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "commit-failure.sqlite3"
    state = make_backend(
        backend="sqlite",
        database=database,
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}',
        public_otk_count=1,
    )
    store = state.agents
    before = store.read_snapshot(  # type: ignore[union-attr]
        receiving_agent_id=state.agent_id, initiating_agent_id=state.agent_id
    )
    command = ContactCommit(
        state.agent_id,
        state.agent_id,
        before.available_public_otks[0].otk_id,
        0,
        before.agent_revision,
        before.receiving_active,
        before.policy_version,
        before.pair_counter,
        before.otk_pool_revision,
    )
    original_open = sqlite_adapter._open_connection

    class CommitFailure:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

        def commit(self) -> None:
            raise sqlite3.OperationalError("backend commit detail")

    monkeypatch.setattr(
        sqlite_adapter, "_open_connection", lambda path: CommitFailure(original_open(path))
    )
    with pytest.raises(ContactPersistenceError, match="^contact persistence failed$"):
        store.try_commit(command)  # type: ignore[union-attr]
    monkeypatch.setattr(sqlite_adapter, "_open_connection", original_open)

    reopened = SQLiteAgentRegistry(database).read_snapshot(
        receiving_agent_id=state.agent_id, initiating_agent_id=state.agent_id
    )
    assert reopened == before


def test_independent_sqlite_lock_exhausts_exactly_eight_retries_without_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "separate-connections.sqlite3"
    state = make_backend(
        backend="sqlite",
        database=database,
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}',
        public_otk_count=1,
    )
    command = ResolveContactCommand(state.agent_id, state.agent_id)
    service = ContactResolutionService(
        contact_state_store=SQLiteAgentRegistry(database),
        user_registry=SQLiteUserRegistry(database),
    )
    original_try_commit = SQLiteAgentRegistry.try_commit
    attempts = 0

    def count_try_commit(store, commit):  # type: ignore[no-untyped-def]
        nonlocal attempts
        attempts += 1
        return original_try_commit(store, commit)

    def zero_timeout_connection(path: str) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=0.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    monkeypatch.setattr(SQLiteAgentRegistry, "try_commit", count_try_commit)
    monkeypatch.setattr(sqlite_adapter, "_open_connection", zero_timeout_connection)
    acquired = Event()
    release = Event()
    barrier = Barrier(2)
    holder_failure: list[BaseException] = []
    request_result: list[object] = []

    def hold_writer_lock() -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(database, timeout=0.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            acquired.set()
            barrier.wait(timeout=10)
            release.wait(timeout=20)
        except BaseException as error:
            holder_failure.append(error)
        finally:
            if connection is not None:
                connection.rollback()
                connection.close()

    def request_while_locked() -> None:
        barrier.wait(timeout=10)
        try:
            request_result.append(service.resolve(command))
        except Exception as error:
            request_result.append(error)

    holder = Thread(target=hold_writer_lock)
    holder.start()
    assert acquired.wait(timeout=10)
    requester = Thread(target=request_while_locked)
    requester.start()
    requester.join(timeout=20)
    assert not requester.is_alive()
    assert holder_failure == []
    assert request_result and isinstance(request_result[0], ConcurrentContactConflict)
    assert attempts == 8
    locked_snapshot = state.agents.read_snapshot(  # type: ignore[union-attr]
        receiving_agent_id=state.agent_id, initiating_agent_id=state.agent_id
    )
    assert locked_snapshot.available_public_otks[0].otk_id.ordinal == 0
    assert locked_snapshot.pair_counter is None

    release.set()
    holder.join(timeout=20)
    assert not holder.is_alive()
    assert holder_failure == []
    # This fresh operation obtains a new snapshot after the lock is released.
    bundle = service.resolve(command)
    assert bundle.public_otk.otk_id.ordinal == 0
