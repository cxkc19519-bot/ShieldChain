"""SQLite ContactStateStore migration and structural CAS evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.domain.agents import RegisteredPublicOtk
from saga.domain.contact import ContactCommit
from saga.domain.errors import ContactPersistenceError, RegistrationPersistenceError
from saga.ports.contact_state import (
    ContactCommitOutcome,
    ContactStateStore,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome
from tests.integration.test_sqlite_agent_registry import _registration, _user_registration


def _store(database: Path) -> tuple[SQLiteAgentRegistry, object]:
    assert (
        SQLiteUserRegistry(database).create_if_absent(_user_registration())
        is UserCreateOutcome.CREATED
    )
    store = SQLiteAgentRegistry(database)
    registration = _registration()
    assert store.create_if_unique(registration) is AgentCreateOutcome.CREATED
    return store, registration.agent_id


def test_contact_state_migration_is_idempotent_and_preserves_opaque_legacy_policy(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.sqlite3"
    store, agent_id = _store(database)

    snapshot = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    reopened = SQLiteAgentRegistry(database).read_snapshot(
        receiving_agent_id=agent_id, initiating_agent_id=agent_id
    )

    assert snapshot == reopened
    assert snapshot.contact_policy_document == b"opaque policy"
    assert snapshot.receiving_active is True
    assert snapshot.agent_revision == snapshot.policy_version == snapshot.otk_pool_revision == 0
    assert [otk.otk_id.ordinal for otk in snapshot.available_public_otks] == [0, 1]
    assert isinstance(store, ContactStateStore)


def test_real_phase_two_rows_migrate_without_parsing_or_rewriting_opaque_policy(
    tmp_path: Path,
) -> None:
    database = tmp_path / "phase-two.sqlite3"
    registration = _registration()
    assert (
        SQLiteUserRegistry(database).create_if_absent(_user_registration())
        is UserCreateOutcome.CREATED
    )
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE agents (
                agent_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(user_id),
                endpoint_device TEXT NOT NULL, endpoint_ip TEXT NOT NULL, endpoint_port INTEGER NOT NULL,
                certificate_der BLOB NOT NULL, access_control_public_key BLOB NOT NULL,
                contact_policy_document BLOB NOT NULL, user_metadata_signature BLOB NOT NULL,
                UNIQUE(endpoint_device, endpoint_ip, endpoint_port)
            );
            CREATE TABLE registered_public_otks (
                agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL, public_key BLOB NOT NULL, user_signature BLOB NOT NULL,
                PRIMARY KEY(agent_id, ordinal), UNIQUE(agent_id, public_key)
            );
            """
        )
        connection.execute(
            """
            INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                registration.agent_id.value,
                registration.owner_id.value,
                registration.endpoint.device,
                registration.endpoint.ip,
                registration.endpoint.port,
                registration.certificate_der,
                registration.access_control_public_key,
                registration.contact_policy_document,
                registration.user_metadata_signature,
            ),
        )
        connection.executemany(
            "INSERT INTO registered_public_otks VALUES (?, ?, ?, ?)",
            [
                (registration.agent_id.value, ordinal, item.public_key, item.user_signature)
                for ordinal, item in enumerate(registration.public_otks)
            ],
        )

    migrated = SQLiteAgentRegistry(database)

    users = SQLiteUserRegistry(database)
    assert users.get(registration.owner_id) == _user_registration()
    assert users.create_if_absent(_user_registration()) is UserCreateOutcome.USER_ID_CONFLICT
    assert migrated.get(registration.agent_id) == registration
    assert migrated.create_if_unique(registration) is AgentCreateOutcome.AGENT_ID_CONFLICT
    assert (
        migrated.create_if_unique(_registration("other", registration.endpoint))
        is AgentCreateOutcome.ENDPOINT_CONFLICT
    )
    assert (
        migrated.read_snapshot(
            receiving_agent_id=registration.agent_id, initiating_agent_id=registration.agent_id
        ).contact_policy_document
        == b"opaque policy"
    )


def test_contact_cas_is_atomic_and_stale_command_has_zero_mutation(tmp_path: Path) -> None:
    store, agent_id = _store(tmp_path / "state.sqlite3")
    snapshot = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    command = ContactCommit(
        agent_id,
        agent_id,
        snapshot.available_public_otks[0].otk_id,
        4,
        snapshot.agent_revision,
        snapshot.receiving_active,
        snapshot.policy_version,
        snapshot.pair_counter,
        snapshot.otk_pool_revision,
    )

    assert store.try_commit(command) is ContactCommitOutcome.COMMITTED
    after = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert store.try_commit(command) is ContactCommitOutcome.CONFLICT
    assert store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == after
    assert after.pair_counter is not None and after.pair_counter.remaining == 4
    assert [otk.otk_id.ordinal for otk in after.available_public_otks] == [1]


def test_structural_management_mutations_preserve_their_independent_revisions(
    tmp_path: Path,
) -> None:
    store, agent_id = _store(tmp_path / "state.sqlite3")
    first = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)

    assert (
        store.replace_policy(PolicyReplaceCommit(agent_id, b'{"version":1,"rules":[]}', 0, True, 0))
        is ContactCommitOutcome.COMMITTED
    )
    second = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert (second.agent_revision, second.policy_version, second.otk_pool_revision) == (1, 1, 0)
    assert (
        store.append_otks(
            OtkAppendCommit(
                agent_id,
                (RegisteredPublicOtk(b"z" * 32, b"q" * 64),),
                1,
                True,
                0,
            )
        )
        is ContactCommitOutcome.COMMITTED
    )
    third = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert (third.agent_revision, third.policy_version, third.otk_pool_revision) == (2, 1, 1)
    assert [otk.otk_id.ordinal for otk in third.available_public_otks] == [0, 1, 2]
    assert store.deactivate(DeactivateCommit(agent_id, 2, True)) is ContactCommitOutcome.COMMITTED
    assert store.deactivate(DeactivateCommit(agent_id, 2, True)) is ContactCommitOutcome.CONFLICT
    assert (
        store.read_snapshot(
            receiving_agent_id=agent_id, initiating_agent_id=agent_id
        ).receiving_active
        is False
    )
    assert first.contact_policy_document == b"opaque policy"


def test_failed_otk_insert_or_issue_rolls_back_without_exposing_backend_text(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.sqlite3"
    store, agent_id = _store(database)
    initial = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_issue BEFORE UPDATE OF issued ON registered_public_otks
            BEGIN SELECT RAISE(ABORT, 'backend secret'); END
            """
        )
    command = ContactCommit(
        agent_id,
        agent_id,
        initial.available_public_otks[0].otk_id,
        0,
        initial.agent_revision,
        initial.receiving_active,
        initial.policy_version,
        initial.pair_counter,
        initial.otk_pool_revision,
    )
    with pytest.raises(ContactPersistenceError, match="^contact persistence failed$") as error:
        store.try_commit(command)
    assert "backend" not in str(error.value)
    assert store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == initial


def test_contact_migration_failure_rolls_back_all_partial_schema_changes(tmp_path: Path) -> None:
    database = tmp_path / "migration-failure.sqlite3"
    SQLiteUserRegistry(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE saga_contact_state_schema (schema_version INTEGER PRIMARY KEY)"
        )
        connection.execute("INSERT INTO saga_contact_state_schema VALUES (2)")

    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        SQLiteAgentRegistry(database)

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        }
        state_versions = connection.execute(
            "SELECT schema_version FROM saga_contact_state_schema"
        ).fetchall()
    assert tables == {"saga_contact_state_schema", "saga_registration_schema", "users"}
    assert state_versions == [(2,)]


def test_failed_otk_append_and_commit_both_rollback_all_contact_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "rollback.sqlite3"
    store, agent_id = _store(database)
    before_append = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_append BEFORE INSERT ON registered_public_otks
            BEGIN SELECT RAISE(ABORT, 'append backend secret'); END
            """
        )
    with pytest.raises(ContactPersistenceError, match="^contact persistence failed$"):
        store.append_otks(
            OtkAppendCommit(
                agent_id,
                (RegisteredPublicOtk(b"x" * 32, b"y" * 64),),
                before_append.agent_revision,
                before_append.receiving_active,
                before_append.otk_pool_revision,
            )
        )
    assert (
        store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
        == before_append
    )

    original_open = sqlite_adapter._open_connection

    class CommitFailure:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

        def commit(self) -> None:
            raise sqlite3.OperationalError("commit backend secret")

    monkeypatch.setattr(
        sqlite_adapter,
        "_open_connection",
        lambda path: CommitFailure(original_open(path)),
    )
    command = ContactCommit(
        agent_id,
        agent_id,
        before_append.available_public_otks[0].otk_id,
        0,
        before_append.agent_revision,
        before_append.receiving_active,
        before_append.policy_version,
        before_append.pair_counter,
        before_append.otk_pool_revision,
    )
    with pytest.raises(ContactPersistenceError, match="^contact persistence failed$"):
        store.try_commit(command)
    monkeypatch.setattr(sqlite_adapter, "_open_connection", original_open)
    assert (
        store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
        == before_append
    )


def test_busy_sqlite_writer_normalizes_to_structural_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, agent_id = _store(tmp_path / "locked.sqlite3")
    snapshot = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    monkeypatch.setattr(
        sqlite_adapter,
        "_open_connection",
        lambda _path: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")),
    )

    assert (
        store.try_commit(
            ContactCommit(
                agent_id,
                agent_id,
                snapshot.available_public_otks[0].otk_id,
                0,
                snapshot.agent_revision,
                snapshot.receiving_active,
                snapshot.policy_version,
                snapshot.pair_counter,
                snapshot.otk_pool_revision,
            )
        )
        is ContactCommitOutcome.CONFLICT
    )


def test_snapshot_uses_one_read_transaction_and_never_mixes_state_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "snapshot.sqlite3"
    store, agent_id = _store(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
    original_row = SQLiteAgentRegistry._state_agent_row
    calls = 0

    def row_then_mutate(connection: sqlite3.Connection, requested_agent_id: object) -> object:
        nonlocal calls
        row = original_row(connection, requested_agent_id)  # type: ignore[arg-type]
        calls += 1
        if calls == 1:
            with sqlite3.connect(database) as writer:
                writer.execute("UPDATE agents SET active = 0, agent_revision = 1")
        return row

    monkeypatch.setattr(SQLiteAgentRegistry, "_state_agent_row", staticmethod(row_then_mutate))

    coherent = store.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)

    assert coherent.receiving_active is True
    assert coherent.agent_revision == 0
    assert (
        SQLiteAgentRegistry(database)
        .read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
        .receiving_active
        is False
    )
