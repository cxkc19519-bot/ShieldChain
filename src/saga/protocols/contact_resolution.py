"""Paper IV-D and IV-E.2--3 contact resolution, before any DH or token work."""

from __future__ import annotations

from saga.crypto import certificates
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import ed25519_public_key_from_bytes, verify
from saga.domain.agents import AgentRegistration
from saga.domain.contact import ContactBundle, ContactCommit, ContactSnapshot, ResolveContactCommand
from saga.domain.errors import (
    AgentInactive,
    ConcurrentContactConflict,
    ContactBundleVerificationFailed,
    ContactPersistenceError,
    InvalidContactInput,
    PairBudgetExhausted,
    PublicOtkPoolExhausted,
)
from saga.domain.otk import AvailablePublicOtk, PairCounter
from saga.domain.policies import ContactPolicy
from saga.domain.users import UserId, UserRegistration
from saga.ports.clock import Clock
from saga.ports.contact_state import ContactCommitOutcome, ContactStateStore
from saga.ports.registries import UserRegistry

_MAX_ATTEMPTS = 8


class ContactResolutionService:
    """Issue one public OTK with a protocol-owned, bounded structural CAS retry."""

    def __init__(
        self,
        *,
        contact_state_store: ContactStateStore,
        user_registry: UserRegistry,
    ) -> None:
        if not isinstance(contact_state_store, ContactStateStore) or not isinstance(
            user_registry, UserRegistry
        ):
            raise InvalidContactInput()
        self._contact_state_store = contact_state_store
        self._user_registry = user_registry

    def resolve(self, command: ResolveContactCommand) -> ContactBundle:
        if type(command) is not ResolveContactCommand:
            raise InvalidContactInput()
        for _ in range(_MAX_ATTEMPTS):
            snapshot = self._snapshot(command)
            receiving, initiating = self._registrations(snapshot)
            if not snapshot.receiving_active:
                raise AgentInactive()
            owner = self._receiving_owner(receiving.owner_id)
            policy = ContactPolicy.parse(snapshot.contact_policy_document)
            match = policy.match(initiating.agent_id)
            remaining = self._remaining(snapshot.pair_counter, match.budget)
            selected = self._selected_otk(snapshot)
            commit = ContactCommit(
                receiving_agent_id=receiving.agent_id,
                initiating_agent_id=initiating.agent_id,
                selected_public_otk_id=selected.otk_id,
                remaining=remaining,
                expected_agent_revision=snapshot.agent_revision,
                expected_active=snapshot.receiving_active,
                expected_policy_version=snapshot.policy_version,
                expected_counter=snapshot.pair_counter,
                expected_otk_pool_revision=snapshot.otk_pool_revision,
            )
            outcome = self._commit(commit)
            if outcome is ContactCommitOutcome.COMMITTED:
                return ContactBundle(
                    receiving_user_certificate_der=owner.certificate_der,
                    receiving_agent_id=receiving.agent_id,
                    receiving_endpoint=receiving.endpoint,
                    receiving_agent_certificate_der=receiving.certificate_der,
                    receiving_access_control_public_key=receiving.access_control_public_key,
                    user_metadata_signature=receiving.user_metadata_signature,
                    public_otk=selected,
                )
        raise ConcurrentContactConflict()

    def _snapshot(self, command: ResolveContactCommand) -> ContactSnapshot:
        try:
            snapshot = self._contact_state_store.read_snapshot(
                receiving_agent_id=command.receiving_agent_id,
                initiating_agent_id=command.initiating_agent_id,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(snapshot) is not ContactSnapshot:
            raise ContactPersistenceError()
        return snapshot

    @staticmethod
    def _registrations(snapshot: ContactSnapshot) -> tuple[AgentRegistration, AgentRegistration]:
        receiving = snapshot.receiving_registration
        initiating = snapshot.initiating_registration
        if type(receiving) is not AgentRegistration or type(initiating) is not AgentRegistration:
            raise ContactPersistenceError()
        return receiving, initiating

    def _receiving_owner(self, owner_id: UserId) -> UserRegistration:
        try:
            owner = self._user_registry.get(owner_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(owner) is not UserRegistration or owner.user_id != owner_id:
            raise ContactPersistenceError()
        return owner

    @staticmethod
    def _remaining(counter: PairCounter | None, budget: int) -> int:
        effective = budget if counter is None else min(counter.remaining, budget)
        if effective <= 0:
            raise PairBudgetExhausted()
        return effective - 1

    @staticmethod
    def _selected_otk(snapshot: ContactSnapshot) -> AvailablePublicOtk:
        if not snapshot.available_public_otks:
            raise PublicOtkPoolExhausted()
        return snapshot.available_public_otks[0]

    def _commit(self, command: ContactCommit) -> ContactCommitOutcome:
        try:
            outcome = self._contact_state_store.try_commit(command)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(outcome) is not ContactCommitOutcome:
            raise ContactPersistenceError()
        return outcome


class ContactBundleVerifier:
    """Offline IV-E.3 certificate and exact User-signature verification."""

    def __init__(
        self, *, clock: Clock, trust_anchor_der: bytes, provider_public_key: bytes
    ) -> None:
        if (
            not isinstance(clock, Clock)
            or type(trust_anchor_der) is not bytes
            or not trust_anchor_der
            or type(provider_public_key) is not bytes
            or len(provider_public_key) != 32
        ):
            raise InvalidContactInput()
        self._clock = clock
        self._trust_anchor_der = trust_anchor_der
        self._provider_public_key = provider_public_key

    def verify(self, bundle: ContactBundle) -> None:
        if type(bundle) is not ContactBundle:
            raise InvalidContactInput()
        try:
            now_ms = self._clock.now_ms()
            user_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=bundle.receiving_user_certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.USER,
                expected_identifier=bundle.receiving_agent_id.owner.value,
                now_ms=now_ms,
            )
            agent_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=bundle.receiving_agent_certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.AGENT,
                expected_identifier=bundle.receiving_agent_id.value,
                now_ms=now_ms,
            )
            if bundle.receiving_endpoint is None:
                raise ValueError("bundle endpoint unavailable")
            user_public = ed25519_public_key_from_bytes(user_key)
            verify(
                user_public,
                encode_agent_user_attestation(
                    AgentUserAttestation(
                        bundle.receiving_agent_id.value,
                        bundle.receiving_endpoint,
                        agent_key,
                        bundle.receiving_access_control_public_key,
                        self._provider_public_key,
                    )
                ),
                bundle.user_metadata_signature,
            )
            verify(
                user_public,
                encode_otk_attestation(
                    OtkAttestation(bundle.receiving_agent_id.value, bundle.public_otk.public_key)
                ),
                bundle.public_otk.user_signature,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactBundleVerificationFailed() from None


__all__ = ("ContactBundleVerifier", "ContactResolutionService")
