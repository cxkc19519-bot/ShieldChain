"""Authenticated Phase 3 policy, public-OTK, and deactivation management."""

from __future__ import annotations

from saga.crypto import certificates
from saga.crypto.canonical import OtkAttestation, encode_otk_attestation
from saga.crypto.passwords import PasswordRecord, verify_password
from saga.crypto.signatures import ed25519_public_key_from_bytes, verify
from saga.domain.agents import AgentRegistration, RegisteredPublicOtk
from saga.domain.contact import (
    AppendPublicOtksCommand,
    ContactSnapshot,
    DeactivateAgentCommand,
    UpdateContactPolicyCommand,
)
from saga.domain.errors import (
    AgentInactive,
    AgentOwnerAuthenticationFailed,
    ConcurrentContactConflict,
    ContactPersistenceError,
    InvalidContactInput,
)
from saga.domain.policies import ContactPolicy
from saga.domain.users import StoredPasswordRecord, UserRegistration
from saga.ports.clock import Clock
from saga.ports.contact_state import (
    ContactCommitOutcome,
    ContactStateStore,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)
from saga.ports.registries import UserRegistry

_MAX_ATTEMPTS = 8


class ContactManagementService:
    """Apply user-owned structural changes with a fresh check on every CAS retry."""

    def __init__(
        self,
        *,
        contact_state_store: ContactStateStore,
        user_registry: UserRegistry,
        clock: Clock,
        trust_anchor_der: bytes,
    ) -> None:
        if (
            not isinstance(contact_state_store, ContactStateStore)
            or not isinstance(user_registry, UserRegistry)
            or not isinstance(clock, Clock)
            or type(trust_anchor_der) is not bytes
            or not trust_anchor_der
        ):
            raise InvalidContactInput()
        self._contact_state_store = contact_state_store
        self._user_registry = user_registry
        self._clock = clock
        self._trust_anchor_der = trust_anchor_der

    def replace_policy(self, command: UpdateContactPolicyCommand) -> None:
        if type(command) is not UpdateContactPolicyCommand:
            raise InvalidContactInput()
        for _ in range(_MAX_ATTEMPTS):
            snapshot, owner = self._managed_snapshot(command.agent_id, command.owner_id)
            self._authenticate(command.password, owner)
            ContactPolicy.parse(command.contact_policy_document)
            outcome = self._replace(
                PolicyReplaceCommit(
                    command.agent_id,
                    command.contact_policy_document,
                    snapshot.agent_revision,
                    snapshot.receiving_active,
                    snapshot.policy_version,
                )
            )
            if outcome is ContactCommitOutcome.COMMITTED:
                return
        raise ConcurrentContactConflict()

    def append_public_otks(self, command: AppendPublicOtksCommand) -> None:
        if type(command) is not AppendPublicOtksCommand:
            raise InvalidContactInput()
        for _ in range(_MAX_ATTEMPTS):
            snapshot, owner = self._managed_snapshot(command.agent_id, command.owner_id)
            self._authenticate(command.password, owner)
            self._verify_otks(command.agent_id.value, command.public_otks, owner)
            outcome = self._append(
                OtkAppendCommit(
                    command.agent_id,
                    command.public_otks,
                    snapshot.agent_revision,
                    snapshot.receiving_active,
                    snapshot.otk_pool_revision,
                )
            )
            if outcome is ContactCommitOutcome.COMMITTED:
                return
        raise ConcurrentContactConflict()

    def deactivate(self, command: DeactivateAgentCommand) -> None:
        if type(command) is not DeactivateAgentCommand:
            raise InvalidContactInput()
        for _ in range(_MAX_ATTEMPTS):
            snapshot, owner = self._managed_snapshot(command.agent_id, command.owner_id)
            self._authenticate(command.password, owner)
            outcome = self._deactivate(
                DeactivateCommit(
                    command.agent_id,
                    snapshot.agent_revision,
                    snapshot.receiving_active,
                )
            )
            if outcome is ContactCommitOutcome.COMMITTED:
                return
        raise ConcurrentContactConflict()

    def _managed_snapshot(self, agent_id, owner_id) -> tuple[ContactSnapshot, UserRegistration]:  # type: ignore[no-untyped-def]
        snapshot = self._snapshot(agent_id)
        registration = snapshot.receiving_registration
        if (
            type(registration) is not AgentRegistration
            or registration.agent_id != agent_id
            or registration.owner_id != owner_id
            or not snapshot.receiving_active
        ):
            if type(registration) is AgentRegistration and not snapshot.receiving_active:
                raise AgentInactive()
            raise AgentOwnerAuthenticationFailed()
        owner = self._owner(owner_id)
        return snapshot, owner

    def _snapshot(self, agent_id) -> ContactSnapshot:  # type: ignore[no-untyped-def]
        try:
            snapshot = self._contact_state_store.read_snapshot(
                receiving_agent_id=agent_id, initiating_agent_id=agent_id
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(snapshot) is not ContactSnapshot:
            raise ContactPersistenceError()
        return snapshot

    def _owner(self, owner_id) -> UserRegistration:  # type: ignore[no-untyped-def]
        try:
            owner = self._user_registry.get(owner_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(owner) is not UserRegistration or owner.user_id != owner_id:
            raise AgentOwnerAuthenticationFailed()
        return owner

    @staticmethod
    def _password_record(record: StoredPasswordRecord) -> PasswordRecord:
        return PasswordRecord(
            record.version,
            record.n,
            record.r,
            record.p,
            record.dklen,
            record.salt,
            record.verifier,
        )

    def _authenticate(self, password: str, owner: UserRegistration) -> None:
        try:
            authenticated = verify_password(password, self._password_record(owner.password_record))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AgentOwnerAuthenticationFailed() from None
        if type(authenticated) is not bool or not authenticated:
            raise AgentOwnerAuthenticationFailed()

    def _verify_otks(
        self,
        agent_id: str,
        public_otks: tuple[RegisteredPublicOtk, ...],
        owner: UserRegistration,
    ) -> None:
        try:
            user_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=owner.certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.USER,
                expected_identifier=owner.user_id.value,
                now_ms=self._clock.now_ms(),
            )
            public_key = ed25519_public_key_from_bytes(user_key)
            for public_otk in public_otks:
                verify(
                    public_key,
                    encode_otk_attestation(OtkAttestation(agent_id, public_otk.public_key)),
                    public_otk.user_signature,
                )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AgentOwnerAuthenticationFailed() from None

    def _replace(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        return self._outcome(self._contact_state_store.replace_policy, command)

    def _append(self, command: OtkAppendCommit) -> ContactCommitOutcome:
        return self._outcome(self._contact_state_store.append_otks, command)

    def _deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome:
        return self._outcome(self._contact_state_store.deactivate, command)

    @staticmethod
    def _outcome(operation, command) -> ContactCommitOutcome:  # type: ignore[no-untyped-def]
        try:
            outcome = operation(command)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ContactPersistenceError() from None
        if type(outcome) is not ContactCommitOutcome:
            raise ContactPersistenceError()
        return outcome


__all__ = ("ContactManagementService",)
