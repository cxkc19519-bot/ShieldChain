from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.domain import UserId


def test_schema_is_deterministic_versioned_and_registration_only(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    SQLiteUserRegistry(database)
    SQLiteUserRegistry(database)

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        }
        version_rows = connection.execute(
            "SELECT schema_version FROM saga_registration_schema"
        ).fetchall()
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}

    assert tables == {"saga_registration_schema", "users"}
    assert version_rows == [(1,)]
    assert columns == {
        "user_id",
        "certificate_der",
        "password_version",
        "password_n",
        "password_r",
        "password_p",
        "password_dklen",
        "password_salt",
        "password_verifier",
    }
    forbidden = (
        "agent",
        "otk",
        "policy",
        "pair",
        "active",
        "deactiv",
        "act",
        "network",
        "route",
        "task",
        "tool",
        "quota",
        "innovation",
    )
    assert not any(token in name.lower() for name in tables | columns for token in forbidden)


def test_every_adapter_connection_sets_and_checks_foreign_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "registration.sqlite3"
    observed: list[int] = []
    original_open = sqlite_adapter._open_connection

    def observing_open(path: str) -> sqlite3.Connection:
        connection = original_open(path)
        observed.append(connection.execute("PRAGMA foreign_keys").fetchone()[0])
        return connection

    monkeypatch.setattr(sqlite_adapter, "_open_connection", observing_open)
    registry = SQLiteUserRegistry(database)
    assert registry.get(UserId("alice")) is None

    assert observed == [1, 1]


def test_agent_registry_adds_an_independent_contact_state_v1_schema(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    SQLiteUserRegistry(database)
    SQLiteAgentRegistry(database)

    with sqlite3.connect(database) as connection:
        agent_columns = {row[1] for row in connection.execute("PRAGMA table_info(agents)")}
        otk_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(registered_public_otks)")
        }
        state_versions = connection.execute(
            "SELECT schema_version FROM saga_contact_state_schema"
        ).fetchall()

    assert {"active", "agent_revision", "policy_version", "otk_pool_revision"} <= agent_columns
    assert "issued" in otk_columns
    assert state_versions == [(1,)]
