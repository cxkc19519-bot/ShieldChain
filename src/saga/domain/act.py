"""Immutable Phase 4 ACT domain value objects; no persistence or state transitions."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .errors import InvalidActInput


def _require_bytes(value: object, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise InvalidActInput()
    return value


def _require_positive_int(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise InvalidActInput()
    return value


def _require_non_negative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidActInput()
    return value


def _require_unix_ms(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidActInput()
    return value


@dataclass(frozen=True, slots=True, repr=False)
class ActPlaintext:
    """Paper-exact five-field ACT plaintext: <N, T_issued, T_expire, Q_max, PAC_B>.

    The outer AEAD nonce and envelope ``version`` are NOT ACT plaintext fields.
    """

    nonce: bytes
    issued_at: int
    expires_at: int
    q_max: int
    initiating_agent_access_control_public_key: bytes

    def __post_init__(self) -> None:
        _require_bytes(self.nonce, 32)
        _require_unix_ms(self.issued_at)
        _require_unix_ms(self.expires_at)
        if self.expires_at <= self.issued_at:
            raise InvalidActInput()
        _require_positive_int(self.q_max)
        _require_bytes(self.initiating_agent_access_control_public_key, 32)

    def __repr__(self) -> str:
        return "ActPlaintext(redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class ActEnvelope:
    """The AEAD-encrypted ACT ciphertext with outer envelope version and nonce."""

    version: int
    aead_nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise InvalidActInput()
        _require_bytes(self.aead_nonce, 12)
        if type(self.ciphertext) is not bytes or len(self.ciphertext) < 16:
            raise InvalidActInput()

    def __repr__(self) -> str:
        return "ActEnvelope(version=1, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class ActUseResult:
    """Successful ACT use: the validated plaintext and updated use count."""

    plaintext: ActPlaintext
    use_count: int

    def __post_init__(self) -> None:
        if type(self.plaintext) is not ActPlaintext:
            raise InvalidActInput()
        _require_positive_int(self.use_count)
        if self.use_count > self.plaintext.q_max:
            raise InvalidActInput()

    def __repr__(self) -> str:
        return f"ActUseResult(use_count={self.use_count}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class EstablishActCommand:
    """Input to the receiving Agent's ACT establishment protocol."""

    # Initiating Agent B's material (from ContactBundle + B's own key)
    initiating_agent_certificate_der: bytes
    initiating_agent_access_control_public_key: bytes
    provider_attestation_signature: bytes
    # The OTK that was allocated to B by the Provider
    allocated_otk_public_key: bytes
    allocated_otk_user_signature: bytes
    # Protocol parameters for ACT creation
    q_max: int
    lifetime_ms: int

    def __post_init__(self) -> None:
        if type(self.initiating_agent_certificate_der) is not bytes or not (
            1 <= len(self.initiating_agent_certificate_der) <= 16_384
        ):
            raise InvalidActInput()
        _require_bytes(self.initiating_agent_access_control_public_key, 32)
        _require_bytes(self.provider_attestation_signature, 64)
        _require_bytes(self.allocated_otk_public_key, 32)
        _require_bytes(self.allocated_otk_user_signature, 64)
        _require_positive_int(self.q_max)
        _require_positive_int(self.lifetime_ms)

    def __repr__(self) -> str:
        return "EstablishActCommand(redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class UseActCommand:
    """Input to the receiving Agent's ACT use/validation protocol."""

    envelope: ActEnvelope
    initiating_agent_access_control_public_key: bytes

    def __post_init__(self) -> None:
        if type(self.envelope) is not ActEnvelope:
            raise InvalidActInput()
        _require_bytes(self.initiating_agent_access_control_public_key, 32)

    def __repr__(self) -> str:
        return "UseActCommand(redacted=True)"


def constant_time_bytes_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison for PAC_B binding verification."""
    if type(a) is not bytes or type(b) is not bytes:
        return False
    return hmac.compare_digest(a, b)


__all__ = (
    "ActEnvelope",
    "ActPlaintext",
    "ActUseResult",
    "EstablishActCommand",
    "UseActCommand",
    "constant_time_bytes_equal",
)
