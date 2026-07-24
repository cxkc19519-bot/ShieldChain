"""SQLite-backed registration-only User and Agent persistence."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from os import fspath
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from saga.domain.agents import AgentId
    from saga.domain.otk import PublicOtkId
    from saga.domain.registration import UserRegistration
    from saga.domain.token_state import SotkMapping, TokenRecord
    from saga.domain.users import UserId
    from saga.ports.registration import UserCreateOutcome
    from saga.ports.token_state import SotkClaimOutcome, TokenCreateOutcome, TokenUseOutcome

from saga.crypto import certificates
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.contact import ContactCommit, ContactSnapshot
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    ActPersistenceError,
    ContactPersistenceError,
    RegistrationPersistenceError,
)
from saga.domain.otk import AvailablePublicOtk, PairCounter, PublicOtkId
from saga.domain.users import StoredPasswordRecord, UserId, UserRegistration
from saga.ports.contact_state import (
    ContactCommitOutcome,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)
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

_CONTACT_STATE_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS saga_contact_state_schema (
        schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pair_otk_counters (
        receiving_agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
        initiating_agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
        remaining INTEGER NOT NULL CHECK (remaining >= 0),
        revision INTEGER NOT NULL CHECK (revision >= 0),
        PRIMARY KEY(receiving_agent_id, initiating_agent_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_registered_public_otks_available
    ON registered_public_otks(agent_id, issued, ordinal)
    """,
)

_TOKEN_STATE_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS saga_token_state_schema (
        schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sotk_mappings (
        receiving_agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL,
        secret_key BLOB NOT NULL,
        consumed INTEGER NOT NULL CHECK (consumed IN (0, 1)),
        PRIMARY KEY(receiving_agent_id, ordinal)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS token_records (
        receiving_agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
        token_nonce BLOB NOT NULL,
        initiating_agent_access_control_public_key BLOB NOT NULL,
        sdhk BLOB NOT NULL,
        issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
        expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
        q_max INTEGER NOT NULL CHECK (q_max > 0),
        use_count INTEGER NOT NULL CHECK (use_count >= 0),
        revision INTEGER NOT NULL CHECK (revision >= 0),
        PRIMARY KEY(receiving_agent_id, token_nonce)
    )
    """,
)


def _contact_lock_error(error: BaseException) -> bool:
    return isinstance(error, sqlite3.OperationalError) and (
        "locked" in str(error).lower() or "busy" in str(error).lower()
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
            self._migrate_contact_state(connection)
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
    def _migrate_contact_state(connection: sqlite3.Connection) -> None:
        """Install the independent v1 contact state without inspecting policy bytes."""
        agent_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(agents)").fetchall()
        }
        for name, statement in (
            ("active", "ALTER TABLE agents ADD COLUMN active INTEGER NOT NULL DEFAULT 1"),
            (
                "agent_revision",
                "ALTER TABLE agents ADD COLUMN agent_revision INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "policy_version",
                "ALTER TABLE agents ADD COLUMN policy_version INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "otk_pool_revision",
                "ALTER TABLE agents ADD COLUMN otk_pool_revision INTEGER NOT NULL DEFAULT 0",
            ),
        ):
            if name not in agent_columns:
                connection.execute(statement)
        otk_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(registered_public_otks)").fetchall()
        }
        if "issued" not in otk_columns:
            connection.execute(
                "ALTER TABLE registered_public_otks ADD COLUMN issued INTEGER NOT NULL DEFAULT 0"
            )
        for statement in _CONTACT_STATE_SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO saga_contact_state_schema (schema_version) VALUES (1)"
        )
        if connection.execute(
            "SELECT schema_version FROM saga_contact_state_schema"
        ).fetchall() != [(1,)]:
            raise sqlite3.DatabaseError("contact schema version invalid")

    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot:
        if type(receiving_agent_id) is not AgentId or type(initiating_agent_id) is not AgentId:
            raise ContactPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN")
            receiving_row = self._state_agent_row(connection, receiving_agent_id)
            initiating_row = self._state_agent_row(connection, initiating_agent_id)
            initiating = (
                None
                if initiating_row is None
                else self._state_registration(connection, initiating_row)
            )
            if receiving_row is None:
                connection.commit()
                return ContactSnapshot(None, initiating, False, 0, b"{}", 0, None, (), 0)
            receiving = self._state_registration(connection, receiving_row)
            active, agent_revision, policy_version, otk_pool_revision = receiving_row[9:]
            if (
                type(active) is not int
                or active not in (0, 1)
                or any(
                    type(value) is not int or value < 0
                    for value in (
                        agent_revision,
                        policy_version,
                        otk_pool_revision,
                    )
                )
            ):
                raise ValueError("stored contact state invalid")
            counter_row = connection.execute(
                """
                SELECT remaining, revision FROM pair_otk_counters
                WHERE receiving_agent_id = ? AND initiating_agent_id = ?
                """,
                (receiving_agent_id.value, initiating_agent_id.value),
            ).fetchone()
            counter = self._counter_from_row(receiving_agent_id, initiating_agent_id, counter_row)
            available_rows = connection.execute(
                """
                SELECT ordinal, public_key, user_signature FROM registered_public_otks
                WHERE agent_id = ? AND issued = 0 ORDER BY ordinal
                """,
                (receiving_agent_id.value,),
            ).fetchall()
            available = tuple(
                AvailablePublicOtk(PublicOtkId(receiving_agent_id, ordinal), public_key, signature)
                for ordinal, public_key, signature in available_rows
            )
            connection.commit()
            return ContactSnapshot(
                receiving,
                initiating,
                bool(active),
                cast(int, agent_revision),
                receiving.contact_policy_document,
                cast(int, policy_version),
                counter,
                available,
                cast(int, otk_pool_revision),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise ContactPersistenceError() from None
        finally:
            _close(connection)

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome:
        if type(command) is not ContactCommit:
            raise ContactPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            state = self._cas_state(connection, command.receiving_agent_id)
            counter = self._current_counter(
                connection, command.receiving_agent_id, command.initiating_agent_id
            )
            if (
                state is None
                or state
                != (
                    command.expected_active,
                    command.expected_agent_revision,
                    command.expected_policy_version,
                    command.expected_otk_pool_revision,
                )
                or counter != command.expected_counter
            ):
                _rollback(connection)
                return ContactCommitOutcome.CONFLICT
            updated = connection.execute(
                """
                UPDATE registered_public_otks SET issued = 1
                WHERE agent_id = ? AND ordinal = ? AND issued = 0
                """,
                (command.receiving_agent_id.value, command.selected_public_otk_id.ordinal),
            ).rowcount
            if updated != 1:
                _rollback(connection)
                return ContactCommitOutcome.CONFLICT
            revision = 0 if counter is None else counter.revision + 1
            connection.execute(
                """
                INSERT INTO pair_otk_counters (
                    receiving_agent_id, initiating_agent_id, remaining, revision
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(receiving_agent_id, initiating_agent_id) DO UPDATE SET
                    remaining = excluded.remaining, revision = excluded.revision
                """,
                (
                    command.receiving_agent_id.value,
                    command.initiating_agent_id.value,
                    command.remaining,
                    revision,
                ),
            )
            connection.execute(
                "UPDATE agents SET otk_pool_revision = otk_pool_revision + 1 WHERE agent_id = ?",
                (command.receiving_agent_id.value,),
            )
            connection.commit()
            return ContactCommitOutcome.COMMITTED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception as error:
            _rollback(connection)
            if _contact_lock_error(error):
                return ContactCommitOutcome.CONFLICT
            raise ContactPersistenceError() from None
        finally:
            _close(connection)

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        if type(command) is not PolicyReplaceCommit:
            raise ContactPersistenceError()
        return self._management_commit(
            command.receiving_agent_id,
            command.expected_agent_revision,
            command.expected_active,
            "policy_version",
            command.expected_policy_version,
            lambda connection: connection.execute(
                """
                UPDATE agents SET contact_policy_document = ?, policy_version = policy_version + 1,
                    agent_revision = agent_revision + 1 WHERE agent_id = ?
                """,
                (command.contact_policy_document, command.receiving_agent_id.value),
            ),
        )

    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome:
        if type(command) is not OtkAppendCommit:
            raise ContactPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            state = self._cas_state(connection, command.receiving_agent_id)
            if (
                state is None
                or state[0] != command.expected_active
                or state[1] != command.expected_agent_revision
                or state[3] != command.expected_otk_pool_revision
            ):
                _rollback(connection)
                return ContactCommitOutcome.CONFLICT
            known = {
                row[0]
                for row in connection.execute(
                    "SELECT public_key FROM registered_public_otks WHERE agent_id = ?",
                    (command.receiving_agent_id.value,),
                ).fetchall()
            }
            if any(entry.public_key in known for entry in command.public_otks):
                _rollback(connection)
                return ContactCommitOutcome.CONFLICT
            ordinal = connection.execute(
                "SELECT COALESCE(MAX(ordinal) + 1, 0) FROM registered_public_otks WHERE agent_id = ?",
                (command.receiving_agent_id.value,),
            ).fetchone()
            if type(ordinal) is not tuple or len(ordinal) != 1 or type(ordinal[0]) is not int:
                raise ValueError("stored OTK ordinal invalid")
            for offset, entry in enumerate(command.public_otks):
                connection.execute(
                    """
                    INSERT INTO registered_public_otks (agent_id, ordinal, public_key, user_signature)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        command.receiving_agent_id.value,
                        ordinal[0] + offset,
                        entry.public_key,
                        entry.user_signature,
                    ),
                )
            connection.execute(
                """
                UPDATE agents SET otk_pool_revision = otk_pool_revision + 1,
                    agent_revision = agent_revision + 1 WHERE agent_id = ?
                """,
                (command.receiving_agent_id.value,),
            )
            connection.commit()
            return ContactCommitOutcome.COMMITTED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception as error:
            _rollback(connection)
            if _contact_lock_error(error):
                return ContactCommitOutcome.CONFLICT
            raise ContactPersistenceError() from None
        finally:
            _close(connection)

    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome:
        if type(command) is not DeactivateCommit:
            raise ContactPersistenceError()
        return self._management_commit(
            command.receiving_agent_id,
            command.expected_agent_revision,
            command.expected_active,
            None,
            None,
            lambda connection: connection.execute(
                "UPDATE agents SET active = 0, agent_revision = agent_revision + 1 WHERE agent_id = ?",
                (command.receiving_agent_id.value,),
            ),
            require_active=True,
        )

    def _management_commit(
        self,
        agent_id: AgentId,
        expected_revision: int,
        expected_active: bool,
        version_field: str | None,
        expected_version: int | None,
        mutation: Callable[[sqlite3.Connection], object],
        *,
        require_active: bool = False,
    ) -> ContactCommitOutcome:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            state = self._cas_state(connection, agent_id)
            valid = (
                state is not None
                and state[0] == expected_active
                and state[1] == expected_revision
                and (
                    version_field is None
                    or state[2 if version_field == "policy_version" else 3] == expected_version
                )
                and (not require_active or state[0])
            )
            if not valid:
                _rollback(connection)
                return ContactCommitOutcome.CONFLICT
            mutation(connection)
            connection.commit()
            return ContactCommitOutcome.COMMITTED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception as error:
            _rollback(connection)
            if _contact_lock_error(error):
                return ContactCommitOutcome.CONFLICT
            raise ContactPersistenceError() from None
        finally:
            _close(connection)

    @staticmethod
    def _state_agent_row(
        connection: sqlite3.Connection, agent_id: AgentId
    ) -> tuple[object, ...] | None:
        row = connection.execute(
            """
            SELECT agent_id, owner_id, endpoint_device, endpoint_ip, endpoint_port,
                   certificate_der, access_control_public_key, contact_policy_document,
                   user_metadata_signature, active, agent_revision, policy_version, otk_pool_revision
            FROM agents WHERE agent_id = ?
            """,
            (agent_id.value,),
        ).fetchone()
        return cast(tuple[object, ...] | None, row)

    def _state_registration(
        self, connection: sqlite3.Connection, agent_row: tuple[object, ...]
    ) -> AgentRegistration:
        if type(agent_row) is not tuple or len(agent_row) != 13:
            raise ValueError("stored state agent row invalid")
        otk_rows = connection.execute(
            """
            SELECT ordinal, public_key, user_signature FROM registered_public_otks
            WHERE agent_id = ? ORDER BY ordinal
            """,
            (agent_row[0],),
        ).fetchall()
        return self._registration_from_rows(agent_row[:9], otk_rows)

    @staticmethod
    def _counter_from_row(
        receiving_agent_id: AgentId, initiating_agent_id: AgentId, row: object
    ) -> PairCounter | None:
        if row is None:
            return None
        if type(row) is not tuple or len(row) != 2:
            raise ValueError("stored pair counter invalid")
        return PairCounter(receiving_agent_id, initiating_agent_id, row[0], row[1])

    def _current_counter(
        self,
        connection: sqlite3.Connection,
        receiving_agent_id: AgentId,
        initiating_agent_id: AgentId,
    ) -> PairCounter | None:
        return self._counter_from_row(
            receiving_agent_id,
            initiating_agent_id,
            connection.execute(
                """
                SELECT remaining, revision FROM pair_otk_counters
                WHERE receiving_agent_id = ? AND initiating_agent_id = ?
                """,
                (receiving_agent_id.value, initiating_agent_id.value),
            ).fetchone(),
        )

    @staticmethod
    def _cas_state(
        connection: sqlite3.Connection, agent_id: AgentId
    ) -> tuple[bool, int, int, int] | None:
        row = connection.execute(
            """
            SELECT active, agent_revision, policy_version, otk_pool_revision
            FROM agents WHERE agent_id = ?
            """,
            (agent_id.value,),
        ).fetchone()
        if row is None:
            return None
        if (
            type(row) is not tuple
            or len(row) != 4
            or type(row[0]) is not int
            or row[0] not in (0, 1)
            or any(type(value) is not int or value < 0 for value in row[1:])
        ):
            raise ValueError("stored contact state invalid")
        return (bool(row[0]), row[1], row[2], row[3])

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


class SQLiteSotkStore:
    """A restart-safe SQLite SotkStore with atomic claim-and-delete semantics."""

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
            raise ActPersistenceError() from None

    def _initialize_schema(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            for statement in _TOKEN_STATE_SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT OR IGNORE INTO saga_token_state_schema (schema_version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
            versions = connection.execute(
                "SELECT schema_version FROM saga_token_state_schema"
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

    def store(self, mapping: SotkMapping) -> None:
        from saga.domain.token_state import SotkMapping as _SotkMapping

        if type(mapping) is not _SotkMapping:
            raise ActPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO sotk_mappings (receiving_agent_id, ordinal, secret_key, consumed)
                VALUES (?, ?, ?, 0)
                """,
                (mapping.otk_id.receiving_agent_id.value, mapping.otk_id.ordinal, mapping.secret_key),
            )
            connection.commit()
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def claim_and_return(
        self, otk_id: PublicOtkId
    ) -> tuple[SotkClaimOutcome, bytes | None]:
        from saga.ports.token_state import SotkClaimOutcome

        if type(otk_id) is not PublicOtkId:
            raise ActPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT secret_key, consumed FROM sotk_mappings
                WHERE receiving_agent_id = ? AND ordinal = ?
                """,
                (otk_id.receiving_agent_id.value, otk_id.ordinal),
            ).fetchone()

            if row is None:
                _rollback(connection)
                return (SotkClaimOutcome.NOT_FOUND, None)

            secret_key, consumed = row
            if consumed == 1:
                _rollback(connection)
                return (SotkClaimOutcome.ALREADY_CONSUMED, None)

            connection.execute(
                """
                UPDATE sotk_mappings SET consumed = 1, secret_key = x''
                WHERE receiving_agent_id = ? AND ordinal = ?
                """,
                (otk_id.receiving_agent_id.value, otk_id.ordinal),
            )
            connection.commit()
            return (SotkClaimOutcome.CLAIMED, secret_key)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def claim_and_delete(self, otk_id: PublicOtkId) -> SotkClaimOutcome:
        outcome, _ = self.claim_and_return(otk_id)
        return outcome

    def get_secret_key(self, otk_id: PublicOtkId) -> bytes | None:
        if type(otk_id) is not PublicOtkId:
            raise ActPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            row = connection.execute(
                """
                SELECT secret_key FROM sotk_mappings
                WHERE receiving_agent_id = ? AND ordinal = ? AND consumed = 0
                """,
                (otk_id.receiving_agent_id.value, otk_id.ordinal),
            ).fetchone()
            if row is None:
                return None
            return row[0]
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None
        finally:
            _close(connection)


class SQLiteTokenStateStore:
    """A restart-safe SQLite TokenStateStore with CAS semantics."""

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
            raise ActPersistenceError() from None

    def _initialize_schema(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            for statement in _TOKEN_STATE_SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT OR IGNORE INTO saga_token_state_schema (schema_version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
            versions = connection.execute(
                "SELECT schema_version FROM saga_token_state_schema"
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

    def create(self, record: TokenRecord) -> TokenCreateOutcome:
        from saga.domain.token_state import TokenRecord as _TokenRecord
        from saga.ports.token_state import TokenCreateOutcome

        if type(record) is not _TokenRecord:
            raise ActPersistenceError()
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM token_records WHERE receiving_agent_id = ? AND token_nonce = ?",
                (record.receiving_agent_id.value, record.token_nonce),
            ).fetchone()
            if existing is not None:
                _rollback(connection)
                return TokenCreateOutcome.DUPLICATE

            connection.execute(
                """
                INSERT INTO token_records (
                    receiving_agent_id, token_nonce, initiating_agent_access_control_public_key,
                    sdhk, issued_at, expires_at, q_max, use_count, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.receiving_agent_id.value,
                    record.token_nonce,
                    record.initiating_agent_access_control_public_key,
                    record.sdhk,
                    record.issued_at,
                    record.expires_at,
                    record.q_max,
                    record.use_count,
                    record.revision,
                ),
            )
            connection.commit()
            return TokenCreateOutcome.CREATED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception as e:
            _rollback(connection)
            print("SQLITE CREATE ERROR:", repr(e))
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def get(
        self, *, receiving_agent_id: AgentId, token_nonce: bytes
    ) -> TokenRecord | None:
        from saga.domain.token_state import TokenRecord as _TokenRecord

        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            row = connection.execute(
                """
                SELECT initiating_agent_access_control_public_key, sdhk, issued_at,
                       expires_at, q_max, use_count, revision
                FROM token_records WHERE receiving_agent_id = ? AND token_nonce = ?
                """,
                (receiving_agent_id.value, token_nonce),
            ).fetchone()
            if row is None:
                return None
            return _TokenRecord(
                token_nonce=token_nonce,
                receiving_agent_id=receiving_agent_id,
                initiating_agent_access_control_public_key=row[0],
                sdhk=row[1],
                issued_at=row[2],
                expires_at=row[3],
                q_max=row[4],
                use_count=row[5],
                revision=row[6],
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def try_increment_use(
        self,
        *,
        receiving_agent_id: AgentId,
        token_nonce: bytes,
        expected_revision: int,
    ) -> TokenUseOutcome:
        from saga.ports.token_state import TokenUseOutcome

        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT use_count, q_max, revision FROM token_records
                WHERE receiving_agent_id = ? AND token_nonce = ?
                """,
                (receiving_agent_id.value, token_nonce),
            ).fetchone()
            if row is None:
                _rollback(connection)
                return TokenUseOutcome.NOT_FOUND
            use_count, q_max, revision = row
            if revision != expected_revision or use_count >= q_max:
                _rollback(connection)
                return TokenUseOutcome.CONFLICT

            connection.execute(
                """
                UPDATE token_records SET use_count = use_count + 1, revision = revision + 1
                WHERE receiving_agent_id = ? AND token_nonce = ?
                """,
                (receiving_agent_id.value, token_nonce),
            )
            connection.commit()
            return TokenUseOutcome.INCREMENTED
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def discard(self, *, receiving_agent_id: AgentId, token_nonce: bytes) -> bool:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM token_records WHERE receiving_agent_id = ? AND token_nonce = ?",
                (receiving_agent_id.value, token_nonce),
            )
            deleted = cursor.rowcount > 0
            connection.commit()
            return deleted
        except (MemoryError, KeyboardInterrupt, SystemExit):
            _rollback(connection)
            raise
        except Exception:
            _rollback(connection)
            raise ActPersistenceError() from None
        finally:
            _close(connection)

    def find_by_initiator(
        self,
        *,
        receiving_agent_id: AgentId,
        initiating_agent_access_control_public_key: bytes,
    ) -> tuple[TokenRecord, ...]:
        from saga.domain.token_state import TokenRecord as _TokenRecord

        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(self._database)
            rows = connection.execute(
                """
                SELECT token_nonce, sdhk, issued_at, expires_at, q_max, use_count, revision
                FROM token_records WHERE receiving_agent_id = ? AND initiating_agent_access_control_public_key = ?
                """,
                (receiving_agent_id.value, initiating_agent_access_control_public_key),
            ).fetchall()

            results = []
            for row in rows:
                results.append(
                    _TokenRecord(
                        token_nonce=row[0],
                        receiving_agent_id=receiving_agent_id,
                        initiating_agent_access_control_public_key=initiating_agent_access_control_public_key,
                        sdhk=row[1],
                        issued_at=row[2],
                        expires_at=row[3],
                        q_max=row[4],
                        use_count=row[5],
                        revision=row[6],
                    )
                )
            return tuple(results)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None
        finally:
            _close(connection)


__all__ = (
    "SQLiteAgentRegistry",
    "SQLiteSotkStore",
    "SQLiteTokenStateStore",
    "SQLiteUserRegistry",
)

