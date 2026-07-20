"""Public one-time-key value objects. Allocation remains protocol-owned."""

from __future__ import annotations

from dataclasses import dataclass

from .agents import AgentId, RegisteredPublicOtk, _require_plain_bytes
from .errors import InvalidContactInput


def _non_negative(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidContactInput()
    return value


@dataclass(frozen=True, slots=True)
class PublicOtkId:
    receiving_agent_id: AgentId
    ordinal: int

    def __post_init__(self) -> None:
        if type(self.receiving_agent_id) is not AgentId:
            raise InvalidContactInput()
        _non_negative(self.ordinal)


@dataclass(frozen=True, slots=True, repr=False)
class AvailablePublicOtk:
    otk_id: PublicOtkId
    public_key: bytes
    user_signature: bytes

    def __post_init__(self) -> None:
        if type(self.otk_id) is not PublicOtkId:
            raise InvalidContactInput()
        try:
            _require_plain_bytes(self.public_key, 32)
            _require_plain_bytes(self.user_signature, 64)
        except Exception:
            raise InvalidContactInput() from None

    def __repr__(self) -> str:
        return f"AvailablePublicOtk(otk_id={self.otk_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class PairCounter:
    receiving_agent_id: AgentId
    initiating_agent_id: AgentId
    remaining: int
    revision: int

    def __post_init__(self) -> None:
        if (
            type(self.receiving_agent_id) is not AgentId
            or type(self.initiating_agent_id) is not AgentId
        ):
            raise InvalidContactInput()
        _non_negative(self.remaining)
        _non_negative(self.revision)


def validate_new_public_otks(value: object) -> tuple[RegisteredPublicOtk, ...]:
    """Validate a non-empty, duplicate-free append request without assigning ordinals."""
    if type(value) is not tuple or not 1 <= len(value) <= 1_024:
        raise InvalidContactInput()
    if any(type(entry) is not RegisteredPublicOtk for entry in value):
        raise InvalidContactInput()
    if len({entry.public_key for entry in value}) != len(value):
        raise InvalidContactInput()
    return value


__all__ = ("AvailablePublicOtk", "PairCounter", "PublicOtkId")
