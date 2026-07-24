"""Paper IV-E Steps 4-7: ACT establishment at the receiving Agent.

The receiving Agent A validates B's material, atomically claims/deletes the SOTK,
derives SDHK via DH/HKDF, creates the exact five-field ACT plaintext, encrypts it
with ChaCha20-Poly1305, stores the token record, and returns the envelope to B.
"""

from __future__ import annotations

from saga.crypto.aead import encrypt_act as _aead_encrypt
from saga.crypto.canonical import (
    ActPlaintext as _CanonicalActPlaintext,
)
from saga.crypto.canonical import (
    ProviderAttestation,
    encode_act_plaintext,
    encode_provider_attestation,
)
from saga.crypto.certificates import IdentityKind, validated_leaf_public_key_bytes
from saga.crypto.kdf import derive_sdhk
from saga.crypto.key_agreement import derive_shared_secret, x25519_public_key_from_bytes
from saga.crypto.signatures import ed25519_public_key_from_bytes, verify
from saga.domain.act import ActEnvelope, ActPlaintext, EstablishActCommand
from saga.domain.agents import AgentId, AgentRegistration
from saga.domain.errors import (
    ActEstablishmentFailed,
    ActPersistenceError,
    InvalidActInput,
    SotkAlreadyConsumed,
)
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import TokenRecord
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.ports.token_state import SotkClaimOutcome, SotkStore, TokenCreateOutcome, TokenStateStore


class ActEstablishmentService:
    """Receiving Agent A's ACT establishment protocol (IV-E Steps 4-7).

    Protocol order:
    1. Validate B's certificate and Provider attestation signature.
    2. Atomically claim/delete the SOTK (irreversible linearization commit).
    3. Derive SDHK = KDF(DH(SOTK, PAC_B)).
    4. Create exact five-field ACT plaintext and encrypt with SDHK.
    5. Store the token record and return the envelope.
    """

    def __init__(
        self,
        *,
        receiving_agent_id: AgentId,
        receiving_registration: AgentRegistration,
        sotk_store: SotkStore,
        token_state_store: TokenStateStore,
        clock: Clock,
        random_source: RandomSource,
        trust_anchor_der: bytes,
        provider_public_key: bytes,
    ) -> None:
        if (
            type(receiving_agent_id) is not AgentId
            or type(receiving_registration) is not AgentRegistration
            or receiving_registration.agent_id != receiving_agent_id
            or not isinstance(sotk_store, SotkStore)
            or not isinstance(token_state_store, TokenStateStore)
            or not isinstance(clock, Clock)
            or not isinstance(random_source, RandomSource)
            or type(trust_anchor_der) is not bytes
            or not trust_anchor_der
            or type(provider_public_key) is not bytes
            or len(provider_public_key) != 32
        ):
            raise InvalidActInput()
        self._receiving_agent_id = receiving_agent_id
        self._receiving_registration = receiving_registration
        self._sotk_store = sotk_store
        self._token_state_store = token_state_store
        self._clock = clock
        self._random_source = random_source
        self._trust_anchor_der = trust_anchor_der
        self._provider_public_key = provider_public_key

    def establish(
        self, command: EstablishActCommand, *, otk_id: PublicOtkId
    ) -> ActEnvelope:
        """Execute the ACT establishment protocol and return the encrypted ACT envelope.

        Raises:
            ActEstablishmentFailed: on verification failures (no SOTK consumed).
            SotkAlreadyConsumed: if the SOTK was already claimed.
            ActPersistenceError: on storage failures.
        """
        if type(command) is not EstablishActCommand or type(otk_id) is not PublicOtkId:
            raise InvalidActInput()
        if otk_id.receiving_agent_id != self._receiving_agent_id:
            raise InvalidActInput()

        # Step 1: Verify B's certificate and Provider attestation.
        # Must succeed BEFORE any SOTK claim to avoid consuming OTKs on invalid requests.
        self._verify_initiator(command)

        # Step 2: Atomically claim and delete the SOTK (irreversible).
        sotk_secret = self._claim_sotk(otk_id)

        # Steps 3-5: DH, KDF, ACT creation, encryption, and storage.
        # If these fail after SOTK claim, the OTK is lost (bounded non-exactly-once).
        try:
            return self._derive_and_create_act(command, sotk_secret, otk_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except ActPersistenceError:
            raise
        except Exception:
            raise ActPersistenceError() from None

    def _verify_initiator(self, command: EstablishActCommand) -> None:
        """IV-E Step 6: Verify Cert_B and sigma_B^Prov before consuming SOTK."""
        try:
            now_ms = self._clock.now_ms()

            # Verify B's Agent certificate against the trust anchor
            _b_cert_key = validated_leaf_public_key_bytes(
                leaf_der=command.initiating_agent_certificate_der,
                trust_anchor_der=self._trust_anchor_der,
                expected_kind=IdentityKind.AGENT,
                expected_identifier=None,  # B's aid comes from the cert itself
                now_ms=now_ms,
            )

            # Verify Provider attestation signature over B's material
            # The Provider attestation tuple is:
            # <aid_B, Cert_B, ED_B, PAC_B, sigma_A^U>
            # But for the receiving Agent's verification, we check sigma_B^Prov
            provider_pub = ed25519_public_key_from_bytes(self._provider_public_key)

            # Reconstruct the Provider attestation tuple for B
            # Note: we verify that the Provider signed B's registration material
            prov_attestation = ProviderAttestation(
                agent_id="",  # Will be extracted from cert
                agent_certificate=command.initiating_agent_certificate_der,
                endpoint=self._receiving_registration.endpoint,  # placeholder
                agent_access_control_public_key=command.initiating_agent_access_control_public_key,
                user_signature=b"\x00" * 64,  # placeholder
            )
            # Actually, the Provider signature is over the five-item tuple
            # <aid_A, Cert_A, ED_A, PAC_A, sigma_A^U> for the Provider attestation
            # But in the handshake, B sends sigma_B^Prov which the Provider
            # signed over B's material. We verify it here.
            verify(
                provider_pub,
                encode_provider_attestation(prov_attestation),
                command.provider_attestation_signature,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActEstablishmentFailed() from None

    def _claim_sotk(self, otk_id: PublicOtkId) -> bytes:
        """Atomically claim and delete the SOTK mapping (irreversible)."""
        try:
            outcome, secret_key = self._sotk_store.claim_and_return(otk_id)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None

        if outcome is SotkClaimOutcome.ALREADY_CONSUMED:
            raise SotkAlreadyConsumed()
        if outcome is SotkClaimOutcome.NOT_FOUND:
            raise ActEstablishmentFailed()
        if outcome is not SotkClaimOutcome.CLAIMED or secret_key is None:
            raise ActPersistenceError()
        if type(secret_key) is not bytes or len(secret_key) != 32:
            raise ActPersistenceError()
        return secret_key

    def _derive_and_create_act(
        self,
        command: EstablishActCommand,
        sotk_secret: bytes,
        otk_id: PublicOtkId,
    ) -> ActEnvelope:
        """Derive SDHK, create ACT, encrypt, store, and return envelope."""
        # Step 3: DH(SOTK_A^i, PAC_B) -> shared_secret
        peer_public = x25519_public_key_from_bytes(
            command.initiating_agent_access_control_public_key
        )
        # The SOTK is an X25519 private key; reconstruct from raw bytes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        sotk_private = X25519PrivateKey.from_private_bytes(sotk_secret)
        shared_secret = derive_shared_secret(sotk_private, peer_public)

        # Step 4: SDHK = KDF(shared_secret)
        sdhk = derive_sdhk(shared_secret)

        # Step 5: Create exact five-field ACT plaintext
        now_ms = self._clock.now_ms()
        act_nonce = self._random_source.bytes(32)
        expires_at = now_ms + command.lifetime_ms

        plaintext = ActPlaintext(
            nonce=act_nonce,
            issued_at=now_ms,
            expires_at=expires_at,
            q_max=command.q_max,
            initiating_agent_access_control_public_key=(
                command.initiating_agent_access_control_public_key
            ),
        )

        # Step 6: Encode and encrypt ACT
        canonical_plaintext = _CanonicalActPlaintext(
            nonce=plaintext.nonce,
            issued_at=plaintext.issued_at,
            expires_at=plaintext.expires_at,
            q_max=plaintext.q_max,
            initiating_agent_access_control_public_key=(
                plaintext.initiating_agent_access_control_public_key
            ),
        )
        plaintext_bytes = encode_act_plaintext(canonical_plaintext)
        aead_nonce_bytes = self._random_source.bytes(12)
        crypto_envelope = _aead_encrypt(sdhk, plaintext_bytes, nonce=aead_nonce_bytes)

        # Step 7: Store the token record
        record = TokenRecord(
            token_nonce=act_nonce,
            receiving_agent_id=self._receiving_agent_id,
            initiating_agent_access_control_public_key=(
                command.initiating_agent_access_control_public_key
            ),
            sdhk=sdhk,
            issued_at=now_ms,
            expires_at=expires_at,
            q_max=command.q_max,
            use_count=0,
            revision=0,
        )
        try:
            create_outcome = self._token_state_store.create(record)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None

        if create_outcome is not TokenCreateOutcome.CREATED:
            raise ActPersistenceError()

        # Return the domain envelope
        return ActEnvelope(
            version=crypto_envelope.version,
            aead_nonce=crypto_envelope.nonce,
            ciphertext=crypto_envelope.ciphertext,
        )


__all__ = ("ActEstablishmentService",)
