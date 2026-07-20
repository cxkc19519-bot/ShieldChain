"""Secret boundary and offline public-bundle tamper evidence for Phase 3."""

from __future__ import annotations

from dataclasses import fields, replace

import pytest

from saga.domain.contact import ContactBundle, ResolveContactCommand
from saga.domain.errors import ContactBundleVerificationFailed
from saga.domain.otk import AvailablePublicOtk
from saga.protocols.contact_resolution import ContactBundleVerifier, ContactResolutionService
from tests.helpers.registration import FixedClock
from tests.integration.test_contact_atomicity import make_backend


def _bundle_fixture():  # type: ignore[no-untyped-def]
    backend = make_backend(
        backend="memory",
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    bundle = ContactResolutionService(
        contact_state_store=backend.agents, user_registry=backend.users
    ).resolve(ResolveContactCommand(backend.agent_id, backend.agent_id))
    verifier = ContactBundleVerifier(
        clock=FixedClock(backend.fixtures.now_ms),
        trust_anchor_der=backend.fixtures.anchor_der,
        provider_public_key=backend.provider_public_key,
    )
    return backend, bundle, verifier


def test_offline_bundle_verifier_rejects_every_public_material_mutation() -> None:
    _, bundle, verifier = _bundle_fixture()
    mutations = (
        replace(bundle, receiving_user_certificate_der=bundle.receiving_agent_certificate_der),
        replace(bundle, receiving_agent_certificate_der=bundle.receiving_user_certificate_der),
        replace(bundle, receiving_endpoint=None),
        replace(bundle, receiving_access_control_public_key=b"x" * 32),
        replace(bundle, user_metadata_signature=b"x" * 64),
        replace(
            bundle,
            public_otk=AvailablePublicOtk(
                bundle.public_otk.otk_id, b"x" * 32, bundle.public_otk.user_signature
            ),
        ),
    )
    verifier.verify(bundle)
    for mutation in mutations:
        with pytest.raises(
            ContactBundleVerificationFailed, match="^contact bundle verification failed$"
        ):
            verifier.verify(mutation)


def test_public_bundle_surface_has_no_private_sotk_or_act_state() -> None:
    backend, bundle, _ = _bundle_fixture()
    names = {field.name.lower() for field in fields(ContactBundle)}
    assert not {"private", "sotk", "act"} & names
    assert "private" not in repr(bundle).lower()
    assert "sotk" not in repr(bundle).lower()
    snapshot = backend.agents.read_snapshot(
        receiving_agent_id=backend.agent_id, initiating_agent_id=backend.agent_id
    )
    snapshot_names = {field.name.lower() for field in fields(type(snapshot))}
    assert not {"private", "sotk", "act"} & snapshot_names
