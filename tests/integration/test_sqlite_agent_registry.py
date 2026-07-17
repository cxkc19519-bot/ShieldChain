"""SQLite Agent Registry restart and uniqueness evidence."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import saga.adapters.persistence.sqlite as sqlite_adapter
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.crypto.passwords import hash_password
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import RegistrationPersistenceError
from saga.domain.users import StoredPasswordRecord, UserId, UserRegistration
from saga.ports.transactions import AgentCreateOutcome, UserCreateOutcome
from tests.helpers.certificates import build_certificate_fixtures


def _user_registration() -> UserRegistration:
    fixtures = build_certificate_fixtures()
    record = hash_password("correct horse battery staple", salt=b"s" * 16)
    return UserRegistration(
        UserId("alice"),
        StoredPasswordRecord(
            record.version, record.n, record.r, record.p, record.dklen, record.salt, record.verifier
        ),
        fixtures.user.der,
    )


def _registration(
    name: str = "worker", endpoint: EndpointValue | None = None, *, otk_count: int = 2
) -> AgentRegistration:
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    return AgentRegistration(
        AgentId(owner, name),
        owner,
        endpoint or EndpointValue("device", "192.0.2.1", 8443),
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
    assert (
        SQLiteUserRegistry(database).create_if_absent(_user_registration())
        is UserCreateOutcome.CREATED
    )
    return SQLiteAgentRegistry(database)


def test_complete_agent_and_ordered_otks_survive_close_and_reopen(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration(otk_count=3)

    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED
    assert SQLiteAgentRegistry(database).get(registration.agent_id) == registration


def test_agent_id_conflict_precedes_endpoint_conflict_globally(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED

    assert registry.create_if_unique(registration) is AgentCreateOutcome.AGENT_ID_CONFLICT
    assert (
        registry.create_if_unique(_registration("other", registration.endpoint))
        is AgentCreateOutcome.ENDPOINT_CONFLICT
    )


@pytest.mark.parametrize("same_field", ["agent_id", "endpoint"])
def test_concurrent_separate_connections_have_exactly_one_winner(
    tmp_path: Path, same_field: str
) -> None:
    database = tmp_path / "registration.sqlite3"
    _registry(database)
    endpoint = EndpointValue("device", "192.0.2.1", 8443)
    registrations = [
        _registration(
            "worker" if same_field == "agent_id" else f"worker-{index}",
            EndpointValue(f"device-{index}", f"192.0.2.{index + 1}", 8443)
            if same_field == "agent_id"
            else endpoint,
        )
        for index in range(12)
    ]
    registries = [SQLiteAgentRegistry(database) for _ in registrations]

    with ThreadPoolExecutor(max_workers=len(registries)) as executor:
        outcomes = list(
            executor.map(
                lambda pair: pair[0].create_if_unique(pair[1]),
                zip(registries, registrations, strict=True),
            )
        )

    assert outcomes.count(AgentCreateOutcome.CREATED) == 1
    assert (
        outcomes.count(
            AgentCreateOutcome.AGENT_ID_CONFLICT
            if same_field == "agent_id"
            else AgentCreateOutcome.ENDPOINT_CONFLICT
        )
        == len(outcomes) - 1
    )


@pytest.mark.parametrize(
    ("sql", "parameters"),
    [
        ("UPDATE agents SET access_control_public_key = ?", (b"short",)),
        ("UPDATE agents SET access_control_public_key = ?", ("text",)),
        ("UPDATE agents SET contact_policy_document = ?", (b"\xff",)),
        ("UPDATE agents SET contact_policy_document = ?", (7,)),
        ("UPDATE agents SET certificate_der = ?", (b"not a certificate",)),
        ("UPDATE agents SET certificate_der = ?", ("not a certificate",)),
        ("UPDATE agents SET owner_id = ?", (b"alice",)),
        ("UPDATE agents SET endpoint_device = ?", (b"device",)),
        ("UPDATE agents SET endpoint_ip = ?", (b"192.0.2.1",)),
        ("UPDATE agents SET endpoint_port = ?", (b"8443",)),
        ("UPDATE agents SET user_metadata_signature = ?", ("text",)),
        ("UPDATE registered_public_otks SET public_key = ? WHERE ordinal = 0", (b"short",)),
        ("UPDATE registered_public_otks SET public_key = ? WHERE ordinal = 0", (7,)),
        ("UPDATE registered_public_otks SET user_signature = ? WHERE ordinal = 0", (b"short",)),
        ("UPDATE registered_public_otks SET user_signature = ? WHERE ordinal = 0", (7,)),
        ("DELETE FROM registered_public_otks WHERE ordinal = 0", ()),
        ("UPDATE registered_public_otks SET ordinal = 3 WHERE ordinal = 0", ()),
        ("UPDATE registered_public_otks SET ordinal = ? WHERE ordinal = 0", (b"0",)),
        ("DELETE FROM users WHERE user_id = ?", ("alice",)),
    ],
)
def test_corrupt_agent_or_otk_rows_fail_closed_without_partial_read(
    tmp_path: Path, sql: str, parameters: tuple[object, ...]
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED
    with sqlite3.connect(database) as connection:
        connection.execute(sql, parameters)

    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        registry.get(registration.agent_id)


def test_read_performs_only_der_structure_parsing_not_registration_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED
    monkeypatch.setattr(
        sqlite_adapter.certificates,
        "validated_leaf_public_key_bytes",
        lambda **_kwargs: pytest.fail(
            "stored Agent records must not repeat registration validation"
        ),
    )

    assert registry.get(registration.agent_id) == registration


def test_duplicate_public_otks_in_a_corrupt_schema_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "registration.sqlite3"
    registry = _registry(database)
    registration = _registration()
    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE registered_public_otks")
        connection.execute(
            """
            CREATE TABLE registered_public_otks (
                agent_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                user_signature BLOB NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO registered_public_otks (agent_id, ordinal, public_key, user_signature)
            VALUES (?, ?, ?, ?)
            """,
            [
                (registration.agent_id.value, 0, b"o" * 32, b"s" * 64),
                (registration.agent_id.value, 1, b"o" * 32, b"t" * 64),
            ],
        )

    with pytest.raises(RegistrationPersistenceError, match="^registration persistence failed$"):
        registry.get(registration.agent_id)
