"""SQLite Agent Registry transaction rollback evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.crypto.passwords import hash_password
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import StoredPasswordRecord, UserId, UserRegistration
from saga.ports.transactions import UserCreateOutcome
from tests.helpers.certificates import build_certificate_fixtures


def _registration(*, otk_count: int = 3) -> AgentRegistration:
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    return AgentRegistration(
        AgentId(owner, "worker"),
        owner,
        EndpointValue("device", "192.0.2.1", 8443),
        fixtures.agent.der,
        b"a" * 32,
        b"opaque policy",
        tuple(
            RegisteredPublicOtk(b"o" * 31 + bytes((ordinal,)), b"s" * 63 + bytes((ordinal,)))
            for ordinal in range(otk_count)
        ),
        b"m" * 64,
    )


def _registry(database: Path) -> SQLiteAgentRegistry:
    fixtures = build_certificate_fixtures()
    record = hash_password("correct horse battery staple", salt=b"s" * 16)
    user = UserRegistration(
        UserId("alice"),
        StoredPasswordRecord(
            record.version, record.n, record.r, record.p, record.dklen, record.salt, record.verifier
        ),
        fixtures.user.der,
    )
    assert SQLiteUserRegistry(database).create_if_absent(user) is UserCreateOutcome.CREATED
    return SQLiteAgentRegistry(database)


@pytest.mark.parametrize(
    "trigger_sql",
    [
        "CREATE TRIGGER reject_agent BEFORE INSERT ON agents "
        "BEGIN SELECT RAISE(ABORT, 'backend path secret'); END",
        "CREATE TRIGGER reject_second_otk BEFORE INSERT ON registered_public_otks "
        "WHEN NEW.ordinal = 1 BEGIN SELECT RAISE(ABORT, 'backend path secret'); END",
        "CREATE TRIGGER reject_final_otk BEFORE INSERT ON registered_public_otks "
        "WHEN NEW.ordinal = 2 BEGIN SELECT RAISE(ABORT, 'backend path secret'); END",
    ],
)
def test_insert_failures_before_and_after_agent_insert_rollback_everything(
    tmp_path: Path, trigger_sql: str
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    with sqlite3.connect(database) as connection:
        connection.execute(trigger_sql)

    with pytest.raises(
        RegistrationPersistenceError, match="^registration persistence failed$"
    ) as error:
        registry.create_if_unique(registration)

    assert "backend" not in str(error.value)
    assert registry.get(registration.agent_id) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM agents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM registered_public_otks").fetchone() == (0,)


def test_commit_failure_rolls_back_complete_agent_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    original_open = sqlite_adapter._open_connection

    class CommitFailingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def execute(self, statement: str, parameters: object = ()) -> sqlite3.Cursor:
            return self._connection.execute(statement, parameters)  # type: ignore[arg-type]

        def commit(self) -> None:
            raise sqlite3.OperationalError("backend path secret")

        def rollback(self) -> None:
            self._connection.rollback()

        def close(self) -> None:
            self._connection.close()

    def fail_commit(path: str) -> CommitFailingConnection:
        return CommitFailingConnection(original_open(path))

    monkeypatch.setattr(sqlite_adapter, "_open_connection", fail_commit)
    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        registry.create_if_unique(registration)

    monkeypatch.setattr(sqlite_adapter, "_open_connection", original_open)
    assert SQLiteAgentRegistry(database).get(registration.agent_id) is None
