"""Deterministic, secret-safe substitutes for registration protocol tests."""

from dataclasses import dataclass, field

from saga.domain.encoding import require_unix_ms
from saga.domain.users import UserId


@dataclass(frozen=True, slots=True)
class FixedClock:
    _now_ms: int

    def __post_init__(self) -> None:
        if type(self._now_ms) is not int:
            raise ValueError("fixed clock value invalid")
        try:
            require_unix_ms(self._now_ms, "now_ms")
        except ValueError:
            raise ValueError("fixed clock value invalid") from None

    def now_ms(self) -> int:
        return self._now_ms


@dataclass(slots=True, repr=False)
class DeterministicRandomSource:
    _outputs: tuple[bytes, ...]
    _next_index: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if type(self._outputs) is not tuple or any(
            type(output) is not bytes for output in self._outputs
        ):
            raise ValueError("deterministic random results invalid")

    def bytes(self, length: int) -> bytes:
        if type(length) is not int or length <= 0:
            raise ValueError("random length invalid")
        if self._next_index >= len(self._outputs):
            raise ValueError("deterministic random source exhausted")
        output = self._outputs[self._next_index]
        if len(output) != length:
            raise ValueError("deterministic random result invalid")
        self._next_index += 1
        return output

    def __repr__(self) -> str:
        remaining = len(self._outputs) - self._next_index
        return f"DeterministicRandomSource(remaining={remaining}, redacted=True)"


@dataclass(frozen=True, slots=True)
class TrustedIdentityVerifier:
    """Explicit closed-set substitute for the paper's external identity assumption."""

    _trusted_user_ids: frozenset[UserId]

    def __post_init__(self) -> None:
        if type(self._trusted_user_ids) is not frozenset or any(
            type(user_id) is not UserId for user_id in self._trusted_user_ids
        ):
            raise ValueError("trusted identities invalid")

    def verify(self, user_id: UserId) -> bool:
        if type(user_id) is not UserId:
            raise ValueError("identity input invalid")
        return user_id in self._trusted_user_ids


@dataclass(slots=True, repr=False)
class FakeProviderSigner:
    """Observable signer substitute that never accepts or exposes a private key."""

    _public_key: bytes
    _signature: bytes
    _signed_messages: list[bytes] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if (
            type(self._public_key) is not bytes
            or len(self._public_key) != 32
            or type(self._signature) is not bytes
            or len(self._signature) != 64
        ):
            raise ValueError("provider signer material invalid")

    def public_key_bytes(self) -> bytes:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        if type(message) is not bytes:
            raise ValueError("signing message invalid")
        self._signed_messages.append(message)
        return self._signature

    @property
    def signed_messages(self) -> tuple[bytes, ...]:
        return tuple(self._signed_messages)

    def __repr__(self) -> str:
        return f"FakeProviderSigner(calls={len(self._signed_messages)}, redacted=True)"


__all__ = (
    "DeterministicRandomSource",
    "FakeProviderSigner",
    "FixedClock",
    "TrustedIdentityVerifier",
)
