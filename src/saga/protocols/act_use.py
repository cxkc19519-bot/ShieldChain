"""Paper IV-E Step 8: ACT use/validation at the receiving Agent.

The receiving Agent A decrypts the ACT envelope, validates PAC_B binding
(constant-time), checks time validity, and atomically increments use_count.
"""

from __future__ import annotations

from saga.crypto.aead import ActEnvelope as _CryptoEnvelope
from saga.crypto.aead import AeadError
from saga.crypto.aead import decrypt_act as _aead_decrypt
from saga.crypto.canonical import decode_act_plaintext
from saga.domain.act import (
    ActPlaintext,
    ActUseResult,
    UseActCommand,
    constant_time_bytes_equal,
)
from saga.domain.agents import AgentId
from saga.domain.errors import (
    ActBindingFailed,
    ActExpired,
    ActFutureIssued,
    ActPersistenceError,
    ActQuotaExhausted,
    ConcurrentActConflict,
    InvalidActInput,
)
from saga.domain.token_state import TokenRecord
from saga.ports.clock import Clock
from saga.ports.token_state import TokenStateStore, TokenUseOutcome

_MAX_USE_ATTEMPTS = 8


class ActUseService:
    """Receiving Agent A's ACT use/validation protocol (IV-E Step 8).

    Protocol order:
    1. Retrieve the token record by nonce.
    2. Decrypt the ACT envelope using stored SDHK.
    3. Constant-time verify PAC_B binding.
    4. Check time validity: [issued_at, expires_at) with future-issued rejection.
    5. Atomically increment use_count via CAS, checking use_count < q_max.
    """

    def __init__(
        self,
        *,
        receiving_agent_id: AgentId,
        token_state_store: TokenStateStore,
        clock: Clock,
    ) -> None:
        if (
            type(receiving_agent_id) is not AgentId
            or not isinstance(token_state_store, TokenStateStore)
            or not isinstance(clock, Clock)
        ):
            raise InvalidActInput()
        self._receiving_agent_id = receiving_agent_id
        self._token_state_store = token_state_store
        self._clock = clock

    def use(self, command: UseActCommand) -> ActUseResult:
        """Validate and use an ACT. Returns the result with updated use count.

        Raises:
            ActBindingFailed: if PAC_B does not match.
            ActExpired: if the token has expired.
            ActFutureIssued: if issued_at is in the future (engineering rule).
            ActQuotaExhausted: if use_count >= q_max.
            ConcurrentActConflict: if CAS retries exhausted.
            ActPersistenceError: on storage failures.
        """
        if type(command) is not UseActCommand:
            raise InvalidActInput()

        # Find the token record by trying to decrypt with each known SDHK
        # Actually, we need the token_nonce from the decrypted ACT to look up
        # the record. But we need the SDHK to decrypt. This is the chicken-and-egg.
        #
        # Resolution: The receiving Agent A has stored all token records with their
        # SDHKs. For use, B presents the envelope. A must try to decrypt it with
        # each stored SDHK, or B must also present some identifier.
        #
        # Per the paper, B presents the ACT ciphertext. A can:
        # 1. Iterate over stored tokens and try decryption (expensive)
        # 2. Derive SDHK from the same DH inputs (requires B's PAC)
        #
        # Since B's PAC_B is provided in the command, A can look up tokens by PAC_B.
        # Multiple tokens may exist for the same PAC_B. We use PAC_B + brute decrypt.
        #
        # For this implementation, we look up by initiating_agent PAC_B.
        record = self._find_token_record(command)
        plaintext = self._decrypt_and_validate(command, record)
        return self._atomic_use(record, plaintext)

    def _find_token_record(self, command: UseActCommand) -> TokenRecord:
        """Find the matching token record for this ACT use attempt.

        Since a receiving Agent may have multiple tokens, we need to try
        decrypting with each matching SDHK. For simplicity, we look up
        by (receiving_agent_id, initiating PAC_B) and try each.
        """
        try:
            records = self._token_state_store.find_by_initiator(
                receiving_agent_id=self._receiving_agent_id,
                initiating_agent_access_control_public_key=(
                    command.initiating_agent_access_control_public_key
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except AttributeError:
            # find_by_initiator might not exist; fall through to brute-force
            records = ()
        except Exception:
            raise ActPersistenceError() from None

        if not records:
            raise ActBindingFailed()

        # Try to decrypt with each candidate's SDHK
        for record in records:
            try:
                crypto_envelope = _CryptoEnvelope(
                    version=command.envelope.version,
                    nonce=command.envelope.aead_nonce,
                    ciphertext=command.envelope.ciphertext,
                )
                _aead_decrypt(record.sdhk, crypto_envelope)
                return record
            except (AeadError, Exception):
                continue

        raise ActBindingFailed()

    def _decrypt_and_validate(
        self, command: UseActCommand, record: TokenRecord
    ) -> ActPlaintext:
        """Decrypt ACT and validate binding, time, and quota."""
        # Decrypt
        try:
            crypto_envelope = _CryptoEnvelope(
                version=command.envelope.version,
                nonce=command.envelope.aead_nonce,
                ciphertext=command.envelope.ciphertext,
            )
            plaintext_bytes = _aead_decrypt(record.sdhk, crypto_envelope)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActBindingFailed() from None

        # Parse the canonical ACT plaintext
        try:
            canonical = decode_act_plaintext(plaintext_bytes)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActBindingFailed() from None

        plaintext = ActPlaintext(
            nonce=canonical.nonce,
            issued_at=canonical.issued_at,
            expires_at=canonical.expires_at,
            q_max=canonical.q_max,
            initiating_agent_access_control_public_key=(
                canonical.initiating_agent_access_control_public_key
            ),
        )

        # Constant-time PAC_B binding verification (IV-E Step 8)
        if not constant_time_bytes_equal(
            plaintext.initiating_agent_access_control_public_key,
            command.initiating_agent_access_control_public_key,
        ):
            raise ActBindingFailed()

        # Time validity: half-open interval [issued_at, expires_at)
        now_ms = self._clock.now_ms()

        # Future-issued rejection (engineering rule, not paper Step 8)
        if now_ms < plaintext.issued_at:
            raise ActFutureIssued()

        # Expiration check
        if now_ms >= plaintext.expires_at:
            raise ActExpired()

        # Quota pre-check against stored record
        if record.use_count >= record.q_max:
            raise ActQuotaExhausted()

        return plaintext

    def _atomic_use(self, record: TokenRecord, plaintext: ActPlaintext) -> ActUseResult:
        """Atomically increment use_count with bounded CAS retry."""
        for _ in range(_MAX_USE_ATTEMPTS):
            # Re-read for fresh revision
            try:
                current = self._token_state_store.get(
                    receiving_agent_id=self._receiving_agent_id,
                    token_nonce=record.token_nonce,
                )
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise ActPersistenceError() from None

            if current is None:
                raise ActPersistenceError()

            # Re-check quota against current state
            if current.use_count >= current.q_max:
                raise ActQuotaExhausted()

            # Try CAS increment
            try:
                outcome = self._token_state_store.try_increment_use(
                    receiving_agent_id=self._receiving_agent_id,
                    token_nonce=record.token_nonce,
                    expected_revision=current.revision,
                )
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise ActPersistenceError() from None

            if outcome is TokenUseOutcome.INCREMENTED:
                return ActUseResult(
                    plaintext=plaintext,
                    use_count=current.use_count + 1,
                )
            if outcome is TokenUseOutcome.NOT_FOUND:
                raise ActPersistenceError()
            # CONFLICT -> retry

        raise ConcurrentActConflict()

    def discard(self, *, token_nonce: bytes) -> bool:
        """Task-completion discard of a token record."""
        if type(token_nonce) is not bytes or len(token_nonce) != 32:
            raise InvalidActInput()
        try:
            return self._token_state_store.discard(
                receiving_agent_id=self._receiving_agent_id,
                token_nonce=token_nonce,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ActPersistenceError() from None


__all__ = ("ActUseService",)
