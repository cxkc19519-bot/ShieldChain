"""Cross-phase IV-B/IV-C evidence and exact registration-message tests."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.adapters.crypto import Ed25519ProviderSigner
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.crypto.canonical import (
    AgentUserAttestation,
    FieldSpec,
    OtkAttestation,
    ProviderAttestation,
    canonical_object_bytes,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from saga.crypto.signatures import ed25519_public_key_bytes, sign, verify
from saga.domain.agents import AgentId, RegisterAgentCommand, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import AgentRegistrationVerificationFailed
from saga.domain.users import RegisterUserCommand, UserId
from saga.protocols.agent_registration import AgentRegistrationService
from saga.protocols.user_registration import UserRegistrationService
from tests.helpers.certificates import NOW_MS, build_certificate_fixtures
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)

EVIDENCE_CLASSES = frozenset(
    {
        "phase2_executable",
        "phase1_primitive_evidence",
        "paper_assumption_or_preprovisioned_input",
        "deferred_network_evidence",
    }
)

# This is an evidence ledger, not an assertion that CA issuance or TLS ran here.
# Each substep records the exact mapping used by the Phase 2 evidence report.
LEDGER_EVIDENCE = {
    "IV-B.1": (
        ("passphrase selection", "paper_assumption_or_preprovisioned_input", "IV-B Step 1"),
    ),
    "IV-B.2": (
        ("User key generation", "phase1_primitive_evidence", "IV-B Step 2; Phase 1 signatures"),
        ("CA issuance / Cert_U", "paper_assumption_or_preprovisioned_input", "IV-B Step 2"),
    ),
    "IV-B.3": (
        ("Provider certificate input", "paper_assumption_or_preprovisioned_input", "IV-B Step 3"),
        ("TLS handshake", "deferred_network_evidence", "IV-B Step 3"),
    ),
    "IV-B.4": (("command construction", "phase2_executable", "IV-B Step 4"),),
    "IV-B.5": (("IdentityVerifier substitute", "phase2_executable", "IV-B Step 5; Decision 13"),),
    "IV-B.6": (
        ("scrypt password record / atomic user state", "phase2_executable", "IV-B Step 6"),
        ("confirmation result", "phase2_executable", "IV-B Step 6"),
    ),
    "IV-C.1": (("AgentId and EndpointValue construction", "phase2_executable", "IV-C Step 1"),),
    "IV-C.2": (
        ("key generation", "phase1_primitive_evidence", "IV-C Step 2; Phase 1 primitives"),
        ("CA certificate issuance", "paper_assumption_or_preprovisioned_input", "IV-C Step 2"),
        ("User signature construction", "phase1_primitive_evidence", "IV-C Step 2; Phase 1 tuples"),
    ),
    "IV-C.3": (("opaque CP_A input preservation", "phase2_executable", "IV-C Step 3"),),
    "IV-C.4": (
        ("TLS handshake", "deferred_network_evidence", "IV-C Step 4"),
        ("stored password authentication", "phase2_executable", "IV-C Step 4"),
    ),
    "IV-C.5": (("registration command consumption", "phase2_executable", "IV-C Step 5"),),
    "IV-C.6": (
        ("Cert_U / Cert_A profile validation", "phase2_executable", "IV-C Step 6; Phase 1 X.509"),
        ("exact User and OTK verification", "phase2_executable", "IV-C Step 6; signature ledger"),
        ("global uniqueness / atomic state", "phase2_executable", "IV-C Step 6"),
    ),
    "IV-C.7": (("Provider signer and confirmation", "phase2_executable", "IV-C Step 7"),),
}

FIGURE_EIGHT_PROVIDER_SCHEMA = (
    FieldSpec("user_certificate", "bytes"),
    FieldSpec("endpoint", "endpoint"),
    FieldSpec("agent_access_control_public_key", "bytes"),
    FieldSpec("user_signature", "bytes"),
)


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _registered_owner() -> tuple[InMemoryUserRegistry, object]:
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    users = InMemoryUserRegistry()
    UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({owner})),
        user_registry=users,
        clock=FixedClock(NOW_MS),
        random_source=DeterministicRandomSource((b"s" * 16,)),
        trust_anchor_der=fixtures.anchor_der,
    ).register(RegisterUserCommand(owner, "phase-two-owner", fixtures.user.der))
    return users, fixtures


def _command(fixtures: object) -> RegisterAgentCommand:
    agent_id = AgentId(UserId("alice"), "worker")
    endpoint = EndpointValue("worker-1", "192.0.2.10", 8443)
    provider_key = ed25519_public_key_bytes(_key(3).public_key())
    access_control = bytes(range(32))
    agent_key = _key(4).public_key().public_bytes_raw()
    metadata = encode_agent_user_attestation(
        AgentUserAttestation(agent_id.value, endpoint, agent_key, access_control, provider_key)
    )
    otk = b"o" * 32
    return RegisterAgentCommand(
        owner_id=UserId("alice"),
        password="phase-two-owner",
        agent_id=agent_id,
        endpoint=endpoint,
        certificate_der=fixtures.agent.der,
        access_control_public_key=access_control,
        contact_policy_document=b'{"opaque":"registration-only"}',
        public_otks=(
            RegisteredPublicOtk(
                otk, sign(_key(2), encode_otk_attestation(OtkAttestation(agent_id.value, otk)))
            ),
        ),
        user_metadata_signature=sign(_key(2), metadata),
    )


def test_every_registration_step_has_one_honest_evidence_class() -> None:
    expected = {f"IV-B.{step}" for step in range(1, 7)} | {f"IV-C.{step}" for step in range(1, 8)}
    assert set(LEDGER_EVIDENCE) == expected
    entries = tuple(entry for substeps in LEDGER_EVIDENCE.values() for entry in substeps)
    assert all(len(entry) == 3 and entry[1] in EVIDENCE_CLASSES for entry in entries)
    classes = {entry[1] for entry in entries}
    assert classes == EVIDENCE_CLASSES
    assert LEDGER_EVIDENCE["IV-B.1"][0][1] == "paper_assumption_or_preprovisioned_input"
    assert any(entry[1] == "deferred_network_evidence" for entry in LEDGER_EVIDENCE["IV-B.3"])
    assert any(entry[1] == "deferred_network_evidence" for entry in LEDGER_EVIDENCE["IV-C.4"])
    assert any(entry[1] == "phase1_primitive_evidence" for entry in LEDGER_EVIDENCE["IV-C.2"])


def test_phase_two_uses_exact_provider_signer_tuple_and_main_text_result() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    signer = Ed25519ProviderSigner(_key(3))
    result = AgentRegistrationService(
        user_registry=users,
        agent_registry=InMemoryAgentRegistry(),
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=signer,
    ).register(command)

    main_text = encode_provider_attestation(
        ProviderAttestation(
            command.agent_id.value,
            command.certificate_der,
            command.endpoint,
            command.access_control_public_key,
            command.user_metadata_signature,
        )
    )
    verify(_key(3).public_key(), main_text, result.provider_attestation_signature)
    figure_eight_substitute = canonical_object_bytes(
        {
            "user_certificate": fixtures.user.der,
            "endpoint": command.endpoint,
            "agent_access_control_public_key": command.access_control_public_key,
            "user_signature": command.user_metadata_signature,
        },
        FIGURE_EIGHT_PROVIDER_SCHEMA,
    )
    with pytest.raises(ValueError):
        verify(_key(3).public_key(), figure_eight_substitute, result.provider_attestation_signature)


def test_metadata_replacement_and_wrong_provider_key_fail_before_state_change() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    replacement = RegisterAgentCommand(
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
    registry = InMemoryAgentRegistry()
    service = AgentRegistrationService(
        user_registry=users,
        agent_registry=registry,
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=Ed25519ProviderSigner(_key(3)),
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        service.register(replacement)
    assert registry.get(command.agent_id) is None
    with pytest.raises(AgentRegistrationVerificationFailed):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=registry,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=Ed25519ProviderSigner(_key(9)),
        ).register(command)
    assert registry.get(command.agent_id) is None
