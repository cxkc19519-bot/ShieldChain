"""SQLite-backed registration-only User persistence."""

from __future__ import annotations

import sqlite3
from os import fspath
from pathlib import Path

from saga.crypto import certificates
from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import StoredPasswordRecord, UserId, UserRegistration
from saga.ports.transactions import UserCreateOutcome

_SCHEMA_VERSION = 1
_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS saga_registration_schema (
        schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        certificate_der BLOB NOT NULL,
        password_version INTEGER NOT NULL,
        password_n INTEGER NOT NULL,
        password_r INTEGER NOT NULL,
        password_p INTEGER NOT NULL,
        password_dklen INTEGER NOT NULL,
        password_salt BLOB NOT NULL,
        password_verifier BLOB NOT NULL
    )
    """,
)


def _open_connection(path: str) -> sqlite3.Connection:
    """Open one adapter connection with SQLite foreign keys enforced."""
    connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise sqlite3.OperationalError("foreign keys unavailable")
        return connection
    except BaseException:
        connection.close()
        raise


def _close(connection: sqlite3.Connection | None) -> None:
    if connection is None:
        return
    try:
        connection.close()
    except (sqlite3.Error, OSError, OverflowError, TypeError, ValueError):
        pass


def _rollback(connection: sqlite3.Connection | None) -> None:
    if connection is None:
        return
    try:
        connection.rollback()
    except (sqlite3.Error, OSError, OverflowError, TypeError, ValueError):
        pass


class SQLiteUserRegistry:
    """A restart-safe SQLite UserRegistry with atomic create-if-absent semantics."""

    def __init__(self, database: str | Path) -> None:
        try:
            if type(database) is not str and not isinstance(database, Path):
                raise ValueError("database path invalid")
            self._database = fspath(database)
            if not self._database or self._database == ":memory:":
                raise ValueError("database path invalid")
            self._initialize_schema()
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None

    def get(self, user_id: UserId) -> UserRegistration | None:
        if type(user_id) is not UserId:
            raise RegistrationPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            row = connection.execute(
                """
                SELECT user_id, certificate_der, password_version, password_n, password_r,
                       password_p, password_dklen, password_salt, password_verifier
                FROM users WHERE user_id = ?
                """,
                (user_id.value,),
            ).fetchone()
            if row is None:
                return None
            return self._registration_from_row(row)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        finally:
            _close(connection)

    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome:
        if type(registration) is not UserRegistration:
            raise RegistrationPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM users WHERE user_id = ?", (registration.user_id.value,)
            ).fetchone()
            if existing is not None:
                _rollback(connection)
                return UserCreateOutcome.USER_ID_CONFLICT
            record = registration.password_record
            connection.execute(
                """
                INSERT INTO users (
                    user_id, certificate_der, password_version, password_n, password_r,
                    password_p, password_dklen, password_salt, password_verifier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    registration.user_id.value,
                    registration.certificate_der,
                    record.version,
                    record.n,
                    record.r,
                    record.p,
                    record.dklen,
                    record.salt,
                    record.verifier,
                ),
            )
            connection.commit()
            return UserCreateOutcome.CREATED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise RegistrationPersistenceError() from None
        finally:
            _close(connection)

    def _initialize_schema(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT OR IGNORE INTO saga_registration_schema (schema_version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
            versions = connection.execute(
                "SELECT schema_version FROM saga_registration_schema"
            ).fetchall()
            if versions != [(_SCHEMA_VERSION,)]:
                raise sqlite3.DatabaseError("schema version invalid")
            connection.commit()
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise
        finally:
            _close(connection)

    @staticmethod
    def _registration_from_row(row: object) -> UserRegistration:
        if type(row) is not tuple or len(row) != 9:
            raise ValueError("stored row invalid")
        (
            stored_user_id,
            certificate_der,
            version,
            n,
            r,
            p,
            dklen,
            salt,
            verifier,
        ) = row
        if type(certificate_der) is not bytes or not 1 <= len(certificate_der) <= 16_384:
            raise ValueError("stored certificate invalid")
        certificates.load_der_certificate(certificate_der)
        return UserRegistration(
            user_id=UserId(stored_user_id),
            password_record=StoredPasswordRecord(version, n, r, p, dklen, salt, verifier),
            certificate_der=certificate_der,
        )


__all__ = ("SQLiteUserRegistry",)
