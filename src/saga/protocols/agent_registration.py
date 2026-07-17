"""Paper IV-C Agent Registration service."""

from __future__ import annotations

from saga.crypto import certificates
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    ProviderAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from saga.crypto.passwords import PasswordRecord, verify_password
from saga.crypto.signatures import ed25519_public_key_from_bytes, verify
from saga.domain.agents import AgentRegistered, AgentRegistration, RegisterAgentCommand
from saga.domain.errors import (
    AgentEndpointExists,
    AgentIdentifierExists,
    AgentOwnerAuthenticationFailed,
    AgentRegistrationVerificationFailed,
    InvalidRegistrationInput,
    RegistrationPersistenceError,
)
from saga.domain.users import StoredPasswordRecord, UserRegistration
from saga.ports.clock import Clock
from saga.ports.registries import AgentRegistry, UserRegistry
from saga.ports.signing import ProviderSigner
from saga.ports.transactions import AgentCreateOutcome


class AgentRegistrationService:
    """Register an Agent in the exact IV-C order, without ambient dependencies."""

    def __init__(
        self,
        *,
        user_registry: UserRegistry,
        agent_registry: AgentRegistry,
        clock: Clock,
        trust_anchor_der: bytes,
        provider_signer: ProviderSigner,
    ) -> None:
        if (
            not isinstance(user_registry, UserRegistry)
            or not isinstance(agent_registry, AgentRegistry)
            or not isinstance(clock, Clock)
            or not isinstance(provider_signer, ProviderSigner)
            or type(trust_anchor_der) is not bytes
            or not trust_anchor_der
        ):
            raise InvalidRegistrationInput()
        self._user_registry = user_registry
        self._agent_registry = agent_registry
        self._clock = clock
        self._trust_anchor_der = trust_anchor_der
        self._provider_signer = provider_signer

    def register(self, command: RegisterAgentCommand) -> AgentRegistered:
        """Verify, attest, and atomically persist one public Agent registration."""
        if type(command) is not RegisterAgentCommand:
            raise InvalidRegistrationInput()
        if command.agent_id.owner != command.owner_id:
            raise InvalidRegistrationInput()
        owner = self._load_owner(command)
        self._authenticate_owner(command, owner)
        provider_key = self._verify_registration(command, owner)
        attestation = self._provider_attestation(command, provider_key)
        registration = AgentRegistration(
            agent_id=command.agent_id,
            owner_id=command.owner_id,
            endpoint=command.endpoint,
            certificate_der=command.certificate_der,
            access_control_public_key=command.access_control_public_key,
            contact_policy_document=command.contact_policy_document,
            public_otks=command.public_otks,
            user_metadata_signature=command.user_metadata_signature,
        )
        outcome = self._create(registration)
        if outcome is AgentCreateOutcome.AGENT_ID_CONFLICT:
            raise AgentIdentifierExists()
        if outcome is AgentCreateOutcome.ENDPOINT_CONFLICT:
            raise AgentEndpointExists()
        if outcome is not AgentCreateOutcome.CREATED:
            raise RegistrationPersistenceError()
        return AgentRegistered(command.agent_id, attestation)

    def _load_owner(self, command: RegisterAgentCommand) -> UserRegistration:
        try:
            owner = self._user_registry.get(command.owner_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        if type(owner) is not UserRegistration:
            raise AgentOwnerAuthenticationFailed()
        return owner

    def _authenticate_owner(self, command: RegisterAgentCommand, owner: UserRegistration) -> None:
        try:
            record = self._password_record(owner.password_record)
            authenticated = verify_password(command.password, record)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AgentOwnerAuthenticationFailed() from None
        if type(authenticated) is not bool or not authenticated:
            raise AgentOwnerAuthenticationFailed()

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

    def _verify_registration(self, command: RegisterAgentCommand, owner: UserRegistration) -> bytes:
        try:
            now_ms = self._clock.now_ms()
            user_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=owner.certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.USER,
                expected_identifier=command.owner_id.value,
                now_ms=now_ms,
            )
            agent_key = certificates.validated_leaf_public_key_bytes(
                leaf_der=command.certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=certificates.IdentityKind.AGENT,
                expected_identifier=command.agent_id.value,
                now_ms=now_ms,
            )
            provider_key = self._provider_public_key()
            metadata_message = encode_agent_user_attestation(
                AgentUserAttestation(
                    command.agent_id.value,
                    command.endpoint,
                    agent_key,
                    command.access_control_public_key,
                    provider_key,
                )
            )
            verify(
                ed25519_public_key_from_bytes(user_key),
                metadata_message,
                command.user_metadata_signature,
            )
            for otk in command.public_otks:
                verify(
                    ed25519_public_key_from_bytes(user_key),
                    encode_otk_attestation(OtkAttestation(command.agent_id.value, otk.public_key)),
                    otk.user_signature,
                )
            return provider_key
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AgentRegistrationVerificationFailed() from None

    def _provider_public_key(self) -> bytes:
        provider_key = self._provider_signer.public_key_bytes()
        if type(provider_key) is not bytes or len(provider_key) != 32:
            raise ValueError("provider public key invalid")
        return provider_key

    def _provider_attestation(self, command: RegisterAgentCommand, provider_key: bytes) -> bytes:
        try:
            message = encode_provider_attestation(
                ProviderAttestation(
                    command.agent_id.value,
                    command.certificate_der,
                    command.endpoint,
                    command.access_control_public_key,
                    command.user_metadata_signature,
                )
            )
            signature = self._provider_signer.sign(message)
            if type(signature) is not bytes or len(signature) != 64:
                raise ValueError("provider signature invalid")
            verify(ed25519_public_key_from_bytes(provider_key), message, signature)
            return signature
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise AgentRegistrationVerificationFailed() from None

    def _create(self, registration: AgentRegistration) -> AgentCreateOutcome:
        try:
            outcome = self._agent_registry.create_if_unique(registration)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise RegistrationPersistenceError() from None
        if type(outcome) is not AgentCreateOutcome:
            raise RegistrationPersistenceError()
        return outcome


__all__ = ("AgentRegistrationService",)
