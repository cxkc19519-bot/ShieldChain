"""Immutable Phase 4 token-state domain value objects for SOTK and ACT tracking."""

from __future__ import annotations

from dataclasses import dataclass

from .agents import AgentId
from .errors import InvalidActInput
from .otk import PublicOtkId


def _require_bytes(value: object, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise InvalidActInput()
    return value


def _require_non_negative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidActInput()
    return value


def _require_positive_int(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise InvalidActInput()
    return value


@dataclass(frozen=True, slots=True, repr=False)
class SotkMapping:
    """An OTK-to-SOTK mapping held locally by the receiving Agent."""

    otk_id: PublicOtkId
    secret_key: bytes

    def __post_init__(self) -> None:
        if type(self.otk_id) is not PublicOtkId:
            raise InvalidActInput()
        _require_bytes(self.secret_key, 32)

    def __repr__(self) -> str:
        return f"SotkMapping(otk_id={self.otk_id!r}, redacted=True)"


@dataclass(frozen=True, slots=True, repr=False)
class TokenRecord:
    """A stored ACT record at the receiving Agent, tracking use count."""

    token_nonce: bytes
    receiving_agent_id: AgentId
    initiating_agent_access_control_public_key: bytes
    sdhk: bytes
    issued_at: int
    expires_at: int
    q_max: int
    use_count: int
    revision: int

    def __post_init__(self) -> None:
        _require_bytes(self.token_nonce, 32)
        if type(self.receiving_agent_id) is not AgentId:
            raise InvalidActInput()
        _require_bytes(self.initiating_agent_access_control_public_key, 32)
        _require_bytes(self.sdhk, 32)
        _require_non_negative_int(self.issued_at)
        _require_non_negative_int(self.expires_at)
        _require_positive_int(self.q_max)
        _require_non_negative_int(self.use_count)
        if self.use_count > self.q_max:
            raise InvalidActInput()
        _require_non_negative_int(self.revision)

    def __repr__(self) -> str:
        return (
            f"TokenRecord(receiving_agent_id={self.receiving_agent_id!r}, "
            f"use_count={self.use_count}, q_max={self.q_max}, redacted=True)"
        )


__all__ = (
    "SotkMapping",
    "TokenRecord",
)
