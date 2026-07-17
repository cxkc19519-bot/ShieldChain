"""SQLite-backed registration-only User and Agent persistence."""

from __future__ import annotations

import sqlite3
from os import fspath
from pathlib import Path

from saga.crypto import certificates
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import StoredPasswordRecord, UserId, UserRegistration
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome

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

_AGENT_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL REFERENCES users(user_id),
        endpoint_device TEXT NOT NULL,
        endpoint_ip TEXT NOT NULL,
        endpoint_port INTEGER NOT NULL,
        certificate_der BLOB NOT NULL,
        access_control_public_key BLOB NOT NULL,
        contact_policy_document BLOB NOT NULL,
        user_metadata_signature BLOB NOT NULL,
        UNIQUE(endpoint_device, endpoint_ip, endpoint_port)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS registered_public_otks (
        agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL,
        public_key BLOB NOT NULL,
        user_signature BLOB NOT NULL,
        PRIMARY KEY(agent_id, ordinal),
        UNIQUE(agent_id, public_key)
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


class SQLiteAgentRegistry:
    """A restart-safe AgentRegistry with complete transactional OTK persistence."""

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

    def get(self, agent_id: AgentId) -> AgentRegistration | None:
        if type(agent_id) is not AgentId:
            raise RegistrationPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            agent_row = connection.execute(
                """
                SELECT agent_id, owner_id, endpoint_device, endpoint_ip, endpoint_port,
                       certificate_der, access_control_public_key, contact_policy_document,
                       user_metadata_signature
                FROM agents WHERE agent_id = ?
                """,
                (agent_id.value,),
            ).fetchone()
            if agent_row is None:
                return None
            if (
                type(agent_row[1]) is not str
                or connection.execute(
                    "SELECT 1 FROM users WHERE user_id = ?", (agent_row[1],)
                ).fetchone()
                is None
            ):
                raise ValueError("stored owner missing")
            otk_rows = connection.execute(
                """
                SELECT ordinal, public_key, user_signature
                FROM registered_public_otks WHERE agent_id = ? ORDER BY ordinal
                """,
                (agent_id.value,),
            ).fetchall()
            return self._registration_from_rows(agent_row, otk_rows)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        finally:
            _close(connection)

    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome:
        if type(registration) is not AgentRegistration:
            raise RegistrationPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            if (
                connection.execute(
                    "SELECT 1 FROM agents WHERE agent_id = ?", (registration.agent_id.value,)
                ).fetchone()
                is not None
            ):
                _rollback(connection)
                return AgentCreateOutcome.AGENT_ID_CONFLICT
            endpoint = registration.endpoint
            if (
                connection.execute(
                    """
                SELECT 1 FROM agents
                WHERE endpoint_device = ? AND endpoint_ip = ? AND endpoint_port = ?
                """,
                    (endpoint.device, endpoint.ip, endpoint.port),
                ).fetchone()
                is not None
            ):
                _rollback(connection)
                return AgentCreateOutcome.ENDPOINT_CONFLICT
            connection.execute(
                """
                INSERT INTO agents (
                    agent_id, owner_id, endpoint_device, endpoint_ip, endpoint_port,
                    certificate_der, access_control_public_key, contact_policy_document,
                    user_metadata_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    registration.agent_id.value,
                    registration.owner_id.value,
                    endpoint.device,
                    endpoint.ip,
                    endpoint.port,
                    registration.certificate_der,
                    registration.access_control_public_key,
                    registration.contact_policy_document,
                    registration.user_metadata_signature,
                ),
            )
            for ordinal, public_otk in enumerate(registration.public_otks):
                connection.execute(
                    """
                    INSERT INTO registered_public_otks (agent_id, ordinal, public_key, user_signature)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        registration.agent_id.value,
                        ordinal,
                        public_otk.public_key,
                        public_otk.user_signature,
                    ),
                )
            connection.commit()
            return AgentCreateOutcome.CREATED
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
            for statement in _SCHEMA_STATEMENTS + _AGENT_SCHEMA_STATEMENTS:
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
    def _registration_from_rows(agent_row: object, otk_rows: object) -> AgentRegistration:
        if type(agent_row) is not tuple or len(agent_row) != 9:
            raise ValueError("stored agent row invalid")
        (
            stored_agent_id,
            stored_owner_id,
            device,
            ip,
            port,
            certificate_der,
            access_control_public_key,
            contact_policy_document,
            user_metadata_signature,
        ) = agent_row
        if type(stored_agent_id) is not str or stored_agent_id.count(":") != 1:
            raise ValueError("stored agent identifier invalid")
        owner_part, name = stored_agent_id.split(":")
        owner_id = UserId(stored_owner_id)
        agent_id = AgentId(UserId(owner_part), name)
        if agent_id.owner != owner_id:
            raise ValueError("stored owner invalid")
        endpoint = EndpointValue(device, ip, port)
        if type(certificate_der) is not bytes or not 1 <= len(certificate_der) <= 16_384:
            raise ValueError("stored certificate invalid")
        certificates.load_der_certificate(certificate_der)
        if (
            type(access_control_public_key) is not bytes
            or len(access_control_public_key) != 32
            or type(contact_policy_document) is not bytes
            or not 1 <= len(contact_policy_document) <= 65_536
            or type(user_metadata_signature) is not bytes
            or len(user_metadata_signature) != 64
        ):
            raise ValueError("stored agent material invalid")
        contact_policy_document.decode("utf-8", errors="strict")
        if type(otk_rows) is not list or not 1 <= len(otk_rows) <= 1_024:
            raise ValueError("stored OTK rows invalid")
        public_otks: list[RegisteredPublicOtk] = []
        for expected_ordinal, row in enumerate(otk_rows):
            if type(row) is not tuple or len(row) != 3:
                raise ValueError("stored OTK row invalid")
            ordinal, public_key, user_signature = row
            if type(ordinal) is not int or ordinal != expected_ordinal:
                raise ValueError("stored OTK ordinal invalid")
            public_otks.append(RegisteredPublicOtk(public_key, user_signature))
        if len({entry.public_key for entry in public_otks}) != len(public_otks):
            raise ValueError("stored OTK duplicate")
        return AgentRegistration(
            agent_id=agent_id,
            owner_id=owner_id,
            endpoint=endpoint,
            certificate_der=certificate_der,
            access_control_public_key=access_control_public_key,
            contact_policy_document=contact_policy_document,
            public_otks=tuple(public_otks),
            user_metadata_signature=user_metadata_signature,
        )


__all__ = ("SQLiteAgentRegistry", "SQLiteUserRegistry")
