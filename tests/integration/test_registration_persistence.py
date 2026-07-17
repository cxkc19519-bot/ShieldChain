"""Shared memory/SQLite registration scenario evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.adapters.crypto import Ed25519ProviderSigner
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import ed25519_public_key_bytes, sign
from saga.domain.agents import AgentId, RegisterAgentCommand, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    AgentIdentifierExists,
    AgentRegistrationVerificationFailed,
    RegistrationPersistenceError,
)
from saga.domain.users import RegisterUserCommand, UserId
from saga.protocols.agent_registration import AgentRegistrationService
from saga.protocols.user_registration import UserRegistrationService
from tests.helpers.certificates import NOW_MS, build_certificate_fixtures
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _command(fixtures: object) -> RegisterAgentCommand:
    agent_id = AgentId(UserId("alice"), "worker")
    endpoint = EndpointValue("worker-1", "192.0.2.10", 8443)
    provider_key = ed25519_public_key_bytes(_key(3).public_key())
    access = bytes(range(32))
    metadata = encode_agent_user_attestation(
        AgentUserAttestation(
            agent_id.value, endpoint, _key(4).public_key().public_bytes_raw(), access, provider_key
        )
    )
    otk = b"o" * 32
    return RegisterAgentCommand(
        UserId("alice"),
        "parity-owner",
        agent_id,
        endpoint,
        fixtures.agent.der,
        access,
        b'{"opaque":"registration-only"}',
        (
            RegisteredPublicOtk(
                otk, sign(_key(2), encode_otk_attestation(OtkAttestation(agent_id.value, otk)))
            ),
        ),
        sign(_key(2), metadata),
    )


def _services(
    users: InMemoryUserRegistry | SQLiteUserRegistry,
    agents: InMemoryAgentRegistry | SQLiteAgentRegistry,
    fixtures: object,
) -> tuple[UserRegistrationService, AgentRegistrationService]:
    return (
        UserRegistrationService(
            identity_verifier=TrustedIdentityVerifier(frozenset({UserId("alice")})),
            user_registry=users,
            clock=FixedClock(NOW_MS),
            random_source=DeterministicRandomSource((b"s" * 16,)),
            trust_anchor_der=fixtures.anchor_der,
        ),
        AgentRegistrationService(
            user_registry=users,
            agent_registry=agents,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=Ed25519ProviderSigner(_key(3)),
        ),
    )


def _outcome_transcript(backend: str, tmp_path: Path) -> tuple[tuple[str, ...], object, object]:
    fixtures = build_certificate_fixtures()
    if backend == "memory":
        users = InMemoryUserRegistry()
        agents = InMemoryAgentRegistry()
    else:
        database = tmp_path / f"parity-{backend}.sqlite3"
        users = SQLiteUserRegistry(database)
        agents = SQLiteAgentRegistry(database)
    user_service, agent_service = _services(users, agents, fixtures)
    owner = UserId("alice")
    user_service.register(RegisterUserCommand(owner, "parity-owner", fixtures.user.der))
    command = _command(fixtures)
    result = agent_service.register(command)
    transcript = ["user_created", f"agent_created:{result.agent_id.value}"]
    with pytest.raises(AgentIdentifierExists):
        agent_service.register(command)
    transcript.append("duplicate:agent_identifier_exists")

    tampered = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        EndpointValue("other", "192.0.2.11", 8443),
        command.certificate_der,
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        agent_service.register(tampered)
    transcript.append("tamper:verification_failed")
    stored = agents.get(command.agent_id)
    assert stored is not None
    transcript.append("state:complete_record")
    if backend == "sqlite":
        assert SQLiteAgentRegistry(database).get(command.agent_id) == stored
        transcript.append("restart:complete_record")
    else:
        # Memory has no restart claim; the transcript denotes the same retained state only.
        transcript.append("restart:not_applicable")
    return tuple(transcript), stored, command


def test_memory_and_sqlite_share_success_duplicate_and_tamper_outcomes(tmp_path: Path) -> None:
    memory, memory_record, memory_command = _outcome_transcript("memory", tmp_path)
    sqlite, sqlite_record, sqlite_command = _outcome_transcript("sqlite", tmp_path)
    assert memory[:-1] == sqlite[:-1]
    assert memory_record == sqlite_record
    assert memory_command == sqlite_command
    assert memory[-1] == "restart:not_applicable"
    assert sqlite[-1] == "restart:complete_record"


def test_sqlite_partial_transaction_failure_has_the_same_no_record_outcome(tmp_path: Path) -> None:
    fixtures = build_certificate_fixtures()
    database = tmp_path / "rollback.sqlite3"
    users = SQLiteUserRegistry(database)
    agents = SQLiteAgentRegistry(database)
    user_service, agent_service = _services(users, agents, fixtures)
    user_service.register(RegisterUserCommand(UserId("alice"), "parity-owner", fixtures.user.der))
    command = _command(fixtures)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TRIGGER reject_otk BEFORE INSERT ON registered_public_otks "
            "BEGIN SELECT RAISE(ABORT, 'backend secret path'); END"
        )
    with pytest.raises(
        RegistrationPersistenceError, match="^registration persistence failed$"
    ) as error:
        agent_service.register(command)
    assert "backend" not in str(error.value)
    assert agents.get(command.agent_id) is None
