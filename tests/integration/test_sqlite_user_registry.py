from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteUserRegistry
from saga.crypto.passwords import PasswordRecord, hash_password, verify_password
from saga.domain import RegistrationPersistenceError, UserId, UserRegistration
from saga.domain.users import StoredPasswordRecord
from saga.ports.transactions import UserCreateOutcome
from tests.helpers.certificates import build_certificate_fixtures

PASSWORD = "correct horse battery staple"


def _registration(*, user_id: str = "alice") -> UserRegistration:
    fixtures = build_certificate_fixtures()
    record = hash_password(PASSWORD, salt=b"s" * 16)
    return UserRegistration(
        user_id=UserId(user_id),
        password_record=StoredPasswordRecord(
            record.version, record.n, record.r, record.p, record.dklen, record.salt, record.verifier
        ),
        certificate_der=fixtures.user.der,
    )


def _crypto_record(record: StoredPasswordRecord) -> PasswordRecord:
    return PasswordRecord(
        record.version, record.n, record.r, record.p, record.dklen, record.salt, record.verifier
    )


def test_user_registration_survives_close_and_reopen_with_scrypt_verification(
    tmp_path: Path,
) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registry = SQLiteUserRegistry(database)

    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED
    restored = SQLiteUserRegistry(database).get(registration.user_id)

    assert restored == registration
    assert restored is not None
    assert verify_password(PASSWORD, _crypto_record(restored.password_record))
    assert not verify_password("incorrect password", _crypto_record(restored.password_record))


def test_duplicate_user_across_separate_connections_has_exactly_one_winner(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registries = [SQLiteUserRegistry(database) for _ in range(16)]

    with ThreadPoolExecutor(max_workers=len(registries)) as executor:
        outcomes = list(
            executor.map(lambda registry: registry.create_if_absent(registration), registries)
        )

    assert outcomes.count(UserCreateOutcome.CREATED) == 1
    assert outcomes.count(UserCreateOutcome.USER_ID_CONFLICT) == len(registries) - 1


def test_password_record_parameters_round_trip_exactly(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registry = SQLiteUserRegistry(database)
    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED

    restored = registry.get(registration.user_id)

    assert restored is not None
    assert restored.password_record == registration.password_record


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("password_version", 2),
        ("password_n", 2),
        ("password_r", 1),
        ("password_p", 2),
        ("password_dklen", 1),
        ("password_salt", b"short"),
        ("password_verifier", b"short"),
        ("certificate_der", b"not a certificate"),
    ],
)
def test_corrupt_persisted_user_rows_fail_closed(
    tmp_path: Path, column: str, value: object
) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registry = SQLiteUserRegistry(database)
    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED
    update_statements = {
        "password_version": "UPDATE users SET password_version = ? WHERE user_id = ?",
        "password_n": "UPDATE users SET password_n = ? WHERE user_id = ?",
        "password_r": "UPDATE users SET password_r = ? WHERE user_id = ?",
        "password_p": "UPDATE users SET password_p = ? WHERE user_id = ?",
        "password_dklen": "UPDATE users SET password_dklen = ? WHERE user_id = ?",
        "password_salt": "UPDATE users SET password_salt = ? WHERE user_id = ?",
        "password_verifier": "UPDATE users SET password_verifier = ? WHERE user_id = ?",
        "certificate_der": "UPDATE users SET certificate_der = ? WHERE user_id = ?",
    }
    with sqlite3.connect(database) as connection:
        connection.execute(update_statements[column], (value, "alice"))

    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        registry.get(registration.user_id)


def test_certificate_column_with_non_blob_value_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registry = SQLiteUserRegistry(database)
    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE users SET certificate_der = ? WHERE user_id = ?", ("text", "alice")
        )

    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        registry.get(registration.user_id)


def test_read_only_performs_structural_der_parsing_not_registration_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "registration.sqlite3"
    registration = _registration()
    registry = SQLiteUserRegistry(database)
    assert registry.create_if_absent(registration) is UserCreateOutcome.CREATED
    monkeypatch.setattr(
        sqlite_adapter.certificates,
        "validated_leaf_public_key_bytes",
        lambda **_kwargs: pytest.fail("stored records must not repeat registration validation"),
    )

    assert registry.get(registration.user_id) == registration


def test_insert_failure_rolls_back_fully_and_hides_backend_detail(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = SQLiteUserRegistry(database)
    registration = _registration()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TRIGGER reject_users BEFORE INSERT ON users "
            "BEGIN SELECT RAISE(ABORT, 'backend path secret'); END"
        )

    with pytest.raises(
        RegistrationPersistenceError, match="^registration persistence failed$"
    ) as error:
        registry.create_if_absent(registration)

    assert "backend" not in str(error.value)
    assert registry.get(registration.user_id) is None


def test_commit_failure_rolls_back_fully_and_hides_backend_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = SQLiteUserRegistry(database)
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
    with pytest.raises(
        RegistrationPersistenceError, match="^registration persistence failed$"
    ) as error:
        registry.create_if_absent(registration)

    assert "backend" not in str(error.value)
    monkeypatch.setattr(sqlite_adapter, "_open_connection", original_open)
    assert SQLiteUserRegistry(database).get(registration.user_id) is None


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_system_exceptions_from_connection_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = SQLiteUserRegistry(database)
    monkeypatch.setattr(
        sqlite_adapter,
        "_open_connection",
        lambda _path: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error)):
        registry.get(UserId("alice"))
