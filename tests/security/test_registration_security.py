"""Registration input tamper and secret-boundary evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.adapters.crypto import Ed25519ProviderSigner
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import ed25519_public_key_bytes, sign
from saga.domain.agents import AgentId, RegisterAgentCommand, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import AgentRegistrationVerificationFailed, InvalidRegistrationInput
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


def _ready() -> tuple[AgentRegistrationService, InMemoryAgentRegistry, RegisterAgentCommand]:
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    users = InMemoryUserRegistry()
    UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({owner})),
        user_registry=users,
        clock=FixedClock(NOW_MS),
        random_source=DeterministicRandomSource((b"s" * 16,)),
        trust_anchor_der=fixtures.anchor_der,
    ).register(RegisterUserCommand(owner, "security-owner", fixtures.user.der))
    agent_id = AgentId(owner, "worker")
    endpoint = EndpointValue("worker", "192.0.2.10", 8443)
    provider_key = ed25519_public_key_bytes(_key(3).public_key())
    access = bytes(range(32))
    metadata = encode_agent_user_attestation(
        AgentUserAttestation(
            agent_id.value, endpoint, _key(4).public_key().public_bytes_raw(), access, provider_key
        )
    )
    otk = b"o" * 32
    command = RegisterAgentCommand(
        owner,
        "security-owner",
        agent_id,
        endpoint,
        fixtures.agent.der,
        access,
        b"opaque policy",
        (
            RegisteredPublicOtk(
                otk, sign(_key(2), encode_otk_attestation(OtkAttestation(agent_id.value, otk)))
            ),
        ),
        sign(_key(2), metadata),
    )
    agents = InMemoryAgentRegistry()
    return (
        AgentRegistrationService(
            user_registry=users,
            agent_registry=agents,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=Ed25519ProviderSigner(_key(3)),
        ),
        agents,
        command,
    )


@pytest.mark.parametrize("field", ["endpoint", "access", "otk", "metadata"])
def test_forged_registration_material_fails_closed(field: str) -> None:
    service, registry, command = _ready()
    endpoint = (
        EndpointValue("altered", "192.0.2.11", 8443) if field == "endpoint" else command.endpoint
    )
    access = b"z" * 32 if field == "access" else command.access_control_public_key
    otks = (
        (RegisteredPublicOtk(b"q" * 32, command.public_otks[0].user_signature),)
        if field == "otk"
        else command.public_otks
    )
    signature = b"x" * 64 if field == "metadata" else command.user_metadata_signature
    forged = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        endpoint,
        command.certificate_der,
        access,
        command.contact_policy_document,
        otks,
        signature,
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        service.register(forged)
    assert registry.get(command.agent_id) is None


def test_wrong_owner_is_rejected_before_signature_or_state_change() -> None:
    service, registry, command = _ready()
    object.__setattr__(command, "agent_id", AgentId(UserId("mallory"), "worker"))
    with pytest.raises(InvalidRegistrationInput):
        service.register(command)
    assert registry.get(AgentId(UserId("mallory"), "worker")) is None


def test_public_results_errors_and_source_tree_do_not_contain_known_secrets() -> None:
    service, registry, command = _ready()
    with pytest.raises(AgentRegistrationVerificationFailed) as error:
        service.register(
            RegisterAgentCommand(
                command.owner_id,
                command.password,
                command.agent_id,
                command.endpoint,
                command.certificate_der,
                command.access_control_public_key,
                command.contact_policy_document,
                command.public_otks,
                b"x" * 64,
            )
        )
    public_text = f"{error.value!s} {error.value!r} {registry!r} {command!r}"
    for secret in (
        "security-owner",
        command.certificate_der.hex(),
        command.public_otks[0].user_signature.hex(),
    ):
        assert secret not in public_text
    root = Path(__file__).parents[2]
    for artifact in (root / "src", root / "tests" / "vectors"):
        for path in artifact.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".json", ".md"}:
                text = path.read_text(encoding="utf-8")
                assert "-----BEGIN PRIVATE KEY-----" not in text
                assert '"sotk"' not in text.lower()
