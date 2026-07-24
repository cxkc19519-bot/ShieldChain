"""Phase 4 unit tests: ACT domain value objects and token state."""

from __future__ import annotations

import pytest

from saga.domain.act import (
    ActEnvelope,
    ActPlaintext,
    ActUseResult,
    EstablishActCommand,
    UseActCommand,
    constant_time_bytes_equal,
)
from saga.domain.agents import AgentId
from saga.domain.errors import InvalidActInput
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping, TokenRecord
from saga.domain.users import UserId

# --- Fixtures ---

def _user_id() -> UserId:
    return UserId("alice@example.com")


def _agent_id() -> AgentId:
    return AgentId(owner=_user_id(), name="agent-a")


def _otk_id() -> PublicOtkId:
    return PublicOtkId(receiving_agent_id=_agent_id(), ordinal=0)


# --- ActPlaintext: exact five fields ---


class TestActPlaintext:
    def test_valid_construction(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        assert pt.nonce == b"\x01" * 32
        assert pt.issued_at == 1_000_000
        assert pt.expires_at == 2_000_000
        assert pt.q_max == 10
        assert pt.initiating_agent_access_control_public_key == b"\x02" * 32

    def test_repr_is_redacted(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        assert "redacted" in repr(pt).lower()
        assert b"\x01".hex() not in repr(pt)

    def test_nonce_wrong_length(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 16,
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_nonce_not_bytes(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce="not bytes",  # type: ignore[arg-type]
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_issued_at_negative(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=-1,
                expires_at=2_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_expires_at_before_issued_at(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=2_000_000,
                expires_at=1_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_expires_at_equals_issued_at(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=1_000_000,
                expires_at=1_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_q_max_zero(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=0,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_q_max_negative(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=-1,
                initiating_agent_access_control_public_key=b"\x02" * 32,
            )

    def test_pac_wrong_length(self) -> None:
        with pytest.raises(InvalidActInput):
            ActPlaintext(
                nonce=b"\x01" * 32,
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=10,
                initiating_agent_access_control_public_key=b"\x02" * 16,
            )

    def test_frozen(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        with pytest.raises(AttributeError):
            pt.q_max = 5  # type: ignore[misc]


# --- ActEnvelope ---


class TestActEnvelope:
    def test_valid_construction(self) -> None:
        envelope = ActEnvelope(
            version=1,
            aead_nonce=b"\x03" * 12,
            ciphertext=b"\x04" * 48,
        )
        assert envelope.version == 1
        assert envelope.aead_nonce == b"\x03" * 12
        assert envelope.ciphertext == b"\x04" * 48

    def test_wrong_version(self) -> None:
        with pytest.raises(InvalidActInput):
            ActEnvelope(
                version=2,
                aead_nonce=b"\x03" * 12,
                ciphertext=b"\x04" * 48,
            )

    def test_nonce_wrong_length(self) -> None:
        with pytest.raises(InvalidActInput):
            ActEnvelope(
                version=1,
                aead_nonce=b"\x03" * 8,
                ciphertext=b"\x04" * 48,
            )

    def test_ciphertext_too_short(self) -> None:
        with pytest.raises(InvalidActInput):
            ActEnvelope(
                version=1,
                aead_nonce=b"\x03" * 12,
                ciphertext=b"\x04" * 15,
            )

    def test_repr_redacted(self) -> None:
        envelope = ActEnvelope(
            version=1,
            aead_nonce=b"\x03" * 12,
            ciphertext=b"\x04" * 48,
        )
        assert "redacted" in repr(envelope).lower()


# --- ActUseResult ---


class TestActUseResult:
    def test_valid(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        result = ActUseResult(plaintext=pt, use_count=1)
        assert result.use_count == 1

    def test_use_count_exceeds_q_max(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=1,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        with pytest.raises(InvalidActInput):
            ActUseResult(plaintext=pt, use_count=2)

    def test_use_count_zero(self) -> None:
        pt = ActPlaintext(
            nonce=b"\x01" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            initiating_agent_access_control_public_key=b"\x02" * 32,
        )
        with pytest.raises(InvalidActInput):
            ActUseResult(plaintext=pt, use_count=0)


# --- EstablishActCommand ---


class TestEstablishActCommand:
    def test_valid(self) -> None:
        cmd = EstablishActCommand(
            initiating_agent_certificate_der=b"\x05" * 100,
            initiating_agent_access_control_public_key=b"\x06" * 32,
            provider_attestation_signature=b"\x07" * 64,
            allocated_otk_public_key=b"\x08" * 32,
            allocated_otk_user_signature=b"\x09" * 64,
            q_max=10,
            lifetime_ms=60_000,
        )
        assert cmd.q_max == 10
        assert cmd.lifetime_ms == 60_000

    def test_cert_too_large(self) -> None:
        with pytest.raises(InvalidActInput):
            EstablishActCommand(
                initiating_agent_certificate_der=b"\x05" * 20_000,
                initiating_agent_access_control_public_key=b"\x06" * 32,
                provider_attestation_signature=b"\x07" * 64,
                allocated_otk_public_key=b"\x08" * 32,
                allocated_otk_user_signature=b"\x09" * 64,
                q_max=10,
                lifetime_ms=60_000,
            )

    def test_q_max_zero(self) -> None:
        with pytest.raises(InvalidActInput):
            EstablishActCommand(
                initiating_agent_certificate_der=b"\x05" * 100,
                initiating_agent_access_control_public_key=b"\x06" * 32,
                provider_attestation_signature=b"\x07" * 64,
                allocated_otk_public_key=b"\x08" * 32,
                allocated_otk_user_signature=b"\x09" * 64,
                q_max=0,
                lifetime_ms=60_000,
            )

    def test_repr_redacted(self) -> None:
        cmd = EstablishActCommand(
            initiating_agent_certificate_der=b"\x05" * 100,
            initiating_agent_access_control_public_key=b"\x06" * 32,
            provider_attestation_signature=b"\x07" * 64,
            allocated_otk_public_key=b"\x08" * 32,
            allocated_otk_user_signature=b"\x09" * 64,
            q_max=10,
            lifetime_ms=60_000,
        )
        assert "redacted" in repr(cmd).lower()


# --- UseActCommand ---


class TestUseActCommand:
    def test_valid(self) -> None:
        envelope = ActEnvelope(version=1, aead_nonce=b"\x03" * 12, ciphertext=b"\x04" * 48)
        cmd = UseActCommand(
            envelope=envelope,
            initiating_agent_access_control_public_key=b"\x06" * 32,
        )
        assert cmd.envelope.version == 1

    def test_bad_envelope_type(self) -> None:
        with pytest.raises(InvalidActInput):
            UseActCommand(
                envelope="not an envelope",  # type: ignore[arg-type]
                initiating_agent_access_control_public_key=b"\x06" * 32,
            )


# --- constant_time_bytes_equal ---


class TestConstantTimeBytesEqual:
    def test_equal(self) -> None:
        assert constant_time_bytes_equal(b"\x01" * 32, b"\x01" * 32) is True

    def test_not_equal(self) -> None:
        assert constant_time_bytes_equal(b"\x01" * 32, b"\x02" * 32) is False

    def test_different_lengths(self) -> None:
        assert constant_time_bytes_equal(b"\x01" * 32, b"\x01" * 16) is False

    def test_non_bytes(self) -> None:
        assert constant_time_bytes_equal("a", b"b") is False  # type: ignore[arg-type]


# --- SotkMapping ---


class TestSotkMapping:
    def test_valid(self) -> None:
        mapping = SotkMapping(otk_id=_otk_id(), secret_key=b"\xaa" * 32)
        assert mapping.secret_key == b"\xaa" * 32

    def test_wrong_key_length(self) -> None:
        with pytest.raises(InvalidActInput):
            SotkMapping(otk_id=_otk_id(), secret_key=b"\xaa" * 16)

    def test_repr_redacted(self) -> None:
        mapping = SotkMapping(otk_id=_otk_id(), secret_key=b"\xaa" * 32)
        assert "redacted" in repr(mapping).lower()


# --- TokenRecord ---


class TestTokenRecord:
    def test_valid(self) -> None:
        record = TokenRecord(
            token_nonce=b"\x01" * 32,
            receiving_agent_id=_agent_id(),
            initiating_agent_access_control_public_key=b"\x02" * 32,
            sdhk=b"\x03" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            use_count=0,
            revision=0,
        )
        assert record.q_max == 10
        assert record.use_count == 0

    def test_use_count_exceeds_q_max(self) -> None:
        with pytest.raises(InvalidActInput):
            TokenRecord(
                token_nonce=b"\x01" * 32,
                receiving_agent_id=_agent_id(),
                initiating_agent_access_control_public_key=b"\x02" * 32,
                sdhk=b"\x03" * 32,
                issued_at=1_000_000,
                expires_at=2_000_000,
                q_max=5,
                use_count=6,
                revision=0,
            )

    def test_use_count_equals_q_max_is_valid(self) -> None:
        """At q_max, the token is exhausted but the record is still valid."""
        record = TokenRecord(
            token_nonce=b"\x01" * 32,
            receiving_agent_id=_agent_id(),
            initiating_agent_access_control_public_key=b"\x02" * 32,
            sdhk=b"\x03" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=5,
            use_count=5,
            revision=5,
        )
        assert record.use_count == record.q_max

    def test_repr_redacted(self) -> None:
        record = TokenRecord(
            token_nonce=b"\x01" * 32,
            receiving_agent_id=_agent_id(),
            initiating_agent_access_control_public_key=b"\x02" * 32,
            sdhk=b"\x03" * 32,
            issued_at=1_000_000,
            expires_at=2_000_000,
            q_max=10,
            use_count=3,
            revision=3,
        )
        assert "redacted" in repr(record).lower()
        assert "use_count=3" in repr(record)
