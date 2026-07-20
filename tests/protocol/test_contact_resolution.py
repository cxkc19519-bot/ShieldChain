"""IV-D / IV-E.2--3 contact-resolution evidence."""

from __future__ import annotations

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
from saga.domain.contact import ResolveContactCommand
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    ConcurrentContactConflict,
    ContactBundleVerificationFailed,
    ContactPersistenceError,
    ContactPolicyDenied,
    ContactPolicyNoMatch,
    InvalidContactPolicy,
    PairBudgetExhausted,
    PublicOtkPoolExhausted,
)
from saga.domain.users import RegisterUserCommand, UserId
from saga.protocols.agent_registration import AgentRegistrationService
from saga.protocols.contact_resolution import ContactBundleVerifier, ContactResolutionService
from saga.protocols.user_registration import UserRegistrationService
from tests.helpers.certificates import NOW_MS, build_certificate_fixtures
from tests.helpers.contact_state import ConflictContactStateStore
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _registered_agent(*, policy: bytes, count: int = 2):
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    users = InMemoryUserRegistry()
    UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({owner})),
        user_registry=users,
        clock=FixedClock(NOW_MS),
        random_source=DeterministicRandomSource((b"s" * 16,)),
        trust_anchor_der=fixtures.anchor_der,
    ).register(RegisterUserCommand(owner, "owner-password", fixtures.user.der))
    agent_id = AgentId(owner, "worker")
    endpoint = EndpointValue("worker-1", "192.0.2.10", 8443)
    provider_key = ed25519_public_key_bytes(_key(3).public_key())
    metadata = sign(
        _key(2),
        encode_agent_user_attestation(
            AgentUserAttestation(
                agent_id.value,
                endpoint,
                _key(4).public_key().public_bytes_raw(),
                b"a" * 32,
                provider_key,
            )
        ),
    )
    public_otks = tuple(
        RegisteredPublicOtk(
            bytes([ordinal + 1]) * 32,
            sign(
                _key(2),
                encode_otk_attestation(OtkAttestation(agent_id.value, bytes([ordinal + 1]) * 32)),
            ),
        )
        for ordinal in range(count)
    )
    agents = InMemoryAgentRegistry()
    AgentRegistrationService(
        user_registry=users,
        agent_registry=agents,
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=Ed25519ProviderSigner(_key(3)),
    ).register(
        RegisterAgentCommand(
            owner,
            "owner-password",
            agent_id,
            endpoint,
            fixtures.agent.der,
            b"a" * 32,
            policy,
            public_otks,
            metadata,
        )
    )
    return agents, users, fixtures, agent_id, provider_key


def test_resolution_issues_lowest_ordinal_and_bundle_verifies() -> None:
    agents, users, fixtures, agent_id, provider_key = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":3}]}'
    )
    service = ContactResolutionService(contact_state_store=agents, user_registry=users)

    bundle = service.resolve(ResolveContactCommand(agent_id, agent_id))

    assert bundle.public_otk.otk_id.ordinal == 0
    assert bundle.user_metadata_signature == agents.get(agent_id).user_metadata_signature  # type: ignore[union-attr]
    ContactBundleVerifier(
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_public_key=provider_key,
    ).verify(bundle)
    assert (
        agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id).pair_counter
        is not None
    )


def test_legacy_policy_fails_closed_without_public_otk_consumption() -> None:
    agents, users, _, agent_id, _ = _registered_agent(policy=b'{"legacy":true}')
    service = ContactResolutionService(contact_state_store=agents, user_registry=users)

    with pytest.raises(InvalidContactPolicy):
        service.resolve(ResolveContactCommand(agent_id, agent_id))

    snapshot = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert len(snapshot.available_public_otks) == 2
    assert snapshot.pair_counter is None


def test_committed_public_otk_is_not_reissued_after_delivery_observation_failure() -> None:
    agents, users, _, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":3}]}'
    )
    service = ContactResolutionService(contact_state_store=agents, user_registry=users)
    command = ResolveContactCommand(agent_id, agent_id)

    first = service.resolve(command)
    second = service.resolve(command)

    assert (first.public_otk.otk_id.ordinal, second.public_otk.otk_id.ordinal) == (0, 1)
    with pytest.raises(PublicOtkPoolExhausted):
        service.resolve(command)


@pytest.mark.parametrize(
    ("policy", "error"),
    (
        (
            b'{"version":1,"rules":[{"kind":"user","user_id":"bob","budget":1}]}',
            ContactPolicyNoMatch,
        ),
        (b'{"version":1,"rules":[{"kind":"global","budget":-1}]}', ContactPolicyDenied),
    ),
)
def test_non_permitting_policy_outcomes_do_not_mutate_state(
    policy: bytes, error: type[Exception]
) -> None:
    agents, users, _, agent_id, _ = _registered_agent(policy=policy)
    service = ContactResolutionService(contact_state_store=agents, user_registry=users)
    before = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)

    with pytest.raises(error):
        service.resolve(ResolveContactCommand(agent_id, agent_id))

    assert agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == before


def test_exhausted_pair_budget_and_missing_owner_do_not_consume_another_otk() -> None:
    agents, users, _, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}'
    )
    service = ContactResolutionService(contact_state_store=agents, user_registry=users)
    command = ResolveContactCommand(agent_id, agent_id)
    service.resolve(command)
    before = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)

    with pytest.raises(PairBudgetExhausted):
        service.resolve(command)
    assert agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == before
    missing_owner = ContactResolutionService(
        contact_state_store=agents, user_registry=InMemoryUserRegistry()
    )
    with pytest.raises(ContactPersistenceError):
        missing_owner.resolve(command)
    assert agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == before


def test_eight_conflicts_recompute_then_return_the_closed_conflict_error() -> None:
    agents, users, _, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}'
    )
    snapshot = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    conflicts = ConflictContactStateStore(snapshot)
    service = ContactResolutionService(contact_state_store=conflicts, user_registry=users)

    with pytest.raises(ConcurrentContactConflict):
        service.resolve(ResolveContactCommand(agent_id, agent_id))

    assert len(conflicts.commands) == 8
    assert snapshot.available_public_otks[0].otk_id == conflicts.commands[0].selected_public_otk_id


def test_post_commit_bundle_verification_failure_does_not_restore_public_otk() -> None:
    agents, users, fixtures, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}'
    )
    bundle = ContactResolutionService(contact_state_store=agents, user_registry=users).resolve(
        ResolveContactCommand(agent_id, agent_id)
    )

    with pytest.raises(ContactBundleVerificationFailed):
        ContactBundleVerifier(
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_public_key=b"w" * 32,
        ).verify(bundle)

    snapshot = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert snapshot.pair_counter is not None
    assert len(snapshot.available_public_otks) == 1
