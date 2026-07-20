"""Paper IV-E.2--3 ContactBundle evidence, with no transport claim."""

from __future__ import annotations

from dataclasses import replace

import pytest

from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
)
from saga.crypto.certificates import IdentityKind, validated_leaf_public_key_bytes
from saga.crypto.signatures import ed25519_public_key_from_bytes, verify
from saga.domain.contact import ResolveContactCommand
from saga.domain.errors import ContactBundleVerificationFailed
from saga.protocols.contact_resolution import ContactBundleVerifier, ContactResolutionService
from tests.helpers.registration import FixedClock
from tests.integration.test_contact_atomicity import make_backend

EVIDENCE_CLASSES = frozenset(
    {
        "deferred_network_evidence",
        "phase3_executable",
    }
)


CONTACT_STEP_LEDGER = {
    "IV-E.1": (("Agent-to-Provider TLS", "deferred_network_evidence"),),
    "IV-E.2": (("Provider policy/OTK resolution", "phase3_executable"),),
    "IV-E.3": (("offline certificate and User-signature verification", "phase3_executable"),),
}


def _resolved_bundle():  # type: ignore[no-untyped-def]
    backend = make_backend(
        backend="memory",
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    bundle = ContactResolutionService(
        contact_state_store=backend.agents,  # type: ignore[arg-type]
        user_registry=backend.users,  # type: ignore[arg-type]
    ).resolve(ResolveContactCommand(backend.agent_id, backend.agent_id))
    verifier = ContactBundleVerifier(
        clock=FixedClock(backend.fixtures.now_ms),
        trust_anchor_der=backend.fixtures.anchor_der,
        provider_public_key=backend.provider_public_key,
    )
    return backend, bundle, verifier


def test_iv_e_evidence_classes_leave_tls_deferred_and_steps_two_three_executable() -> None:
    assert set(CONTACT_STEP_LEDGER) == {"IV-E.1", "IV-E.2", "IV-E.3"}
    entries = tuple(entry for step in CONTACT_STEP_LEDGER.values() for entry in step)
    assert all(len(entry) == 2 and entry[1] in EVIDENCE_CLASSES for entry in entries)
    assert CONTACT_STEP_LEDGER["IV-E.1"] == (
        ("Agent-to-Provider TLS", "deferred_network_evidence"),
    )
    assert all(entry[1] == "phase3_executable" for entry in CONTACT_STEP_LEDGER["IV-E.2"])
    assert all(entry[1] == "phase3_executable" for entry in CONTACT_STEP_LEDGER["IV-E.3"])


def test_contact_bundle_maps_exact_iv_e_two_three_public_material_and_tuples() -> None:
    backend, bundle, verifier = _resolved_bundle()
    registration = backend.agents.get(backend.agent_id)
    owner = backend.users.get(backend.agent_id.owner)

    assert registration is not None
    assert owner is not None
    assert bundle.receiving_user_certificate_der == owner.certificate_der
    assert bundle.receiving_agent_id == registration.agent_id
    assert bundle.receiving_endpoint == registration.endpoint
    assert bundle.receiving_agent_certificate_der == registration.certificate_der
    assert bundle.receiving_access_control_public_key == registration.access_control_public_key
    assert bundle.user_metadata_signature == registration.user_metadata_signature
    assert bundle.public_otk.otk_id.ordinal == 0

    user_key = ed25519_public_key_from_bytes(
        validated_leaf_public_key_bytes(
            leaf_der=backend.fixtures.user.der,
            trust_anchor_der=backend.fixtures.anchor_der,
            expected_kind=IdentityKind.USER,
            expected_identifier=backend.agent_id.owner.value,
            now_ms=backend.fixtures.now_ms,
        )
    )
    verify(
        user_key,
        encode_agent_user_attestation(
            AgentUserAttestation(
                bundle.receiving_agent_id.value,
                bundle.receiving_endpoint,
                validated_leaf_public_key_bytes(
                    leaf_der=backend.fixtures.agent.der,
                    trust_anchor_der=backend.fixtures.anchor_der,
                    expected_kind=IdentityKind.AGENT,
                    expected_identifier=backend.agent_id.value,
                    now_ms=backend.fixtures.now_ms,
                ),
                bundle.receiving_access_control_public_key,
                backend.provider_public_key,
            )
        ),
        bundle.user_metadata_signature,
    )
    verify(
        user_key,
        encode_otk_attestation(
            OtkAttestation(bundle.receiving_agent_id.value, bundle.public_otk.public_key)
        ),
        bundle.public_otk.user_signature,
    )
    verifier.verify(bundle)


def test_offline_verifier_rejects_a_tampered_iv_e_three_tuple_without_transport() -> None:
    _, bundle, verifier = _resolved_bundle()

    with pytest.raises(
        ContactBundleVerificationFailed, match="^contact bundle verification failed$"
    ):
        verifier.verify(replace(bundle, user_metadata_signature=b"x" * 64))
