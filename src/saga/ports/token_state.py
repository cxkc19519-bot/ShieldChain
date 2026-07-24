"""Versioned structural persistence contracts for Phase 4 SOTK and token state."""

from __future__ import annotations

from enum import StrEnum as _StrEnum
from typing import Protocol, runtime_checkable

from saga.domain.agents import AgentId
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping, TokenRecord


class SotkClaimOutcome(_StrEnum):
    """Result of an atomic SOTK claim-and-delete operation."""

    CLAIMED = "claimed"
    NOT_FOUND = "not_found"
    ALREADY_CONSUMED = "already_consumed"


class TokenCreateOutcome(_StrEnum):
    """Result of creating a new token record."""

    CREATED = "created"
    DUPLICATE = "duplicate"


class TokenUseOutcome(_StrEnum):
    """Result of an atomic token use-count increment."""

    INCREMENTED = "incremented"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"


@runtime_checkable
class SotkStore(Protocol):
    """Atomic claim/delete of SOTK mappings. Claim is irreversible."""

    def store(self, mapping: SotkMapping) -> None:
        """Store a new SOTK mapping for a receiving Agent's OTK."""
        ...

    def claim_and_delete(self, otk_id: PublicOtkId) -> SotkClaimOutcome:
        """Atomically claim and delete SOTK. Returns the secret key only on CLAIMED.

        Once claimed, the mapping is permanently destroyed and cannot be re-claimed.
        """
        ...

    def get_secret_key(self, otk_id: PublicOtkId) -> bytes | None:
        """Retrieve the secret key for a claimed SOTK, only available during claim.

        This is used internally: the claim_and_delete returns the outcome, and
        the actual secret key must be retrieved separately or returned alongside.
        """
        ...

    def claim_and_return(self, otk_id: PublicOtkId) -> tuple[SotkClaimOutcome, bytes | None]:
        """Atomically claim the SOTK and return (outcome, secret_key_or_none).

        On CLAIMED: returns (CLAIMED, secret_key_bytes).
        On NOT_FOUND or ALREADY_CONSUMED: returns (outcome, None).
        After this call with CLAIMED, the mapping is permanently destroyed.
        """
        ...


@runtime_checkable
class TokenStateStore(Protocol):
    """Versioned ACT token state with CAS semantics."""

    def create(self, record: TokenRecord) -> TokenCreateOutcome:
        """Store a new token record. Fails with DUPLICATE if nonce already exists."""
        ...

    def get(self, *, receiving_agent_id: AgentId, token_nonce: bytes) -> TokenRecord | None:
        """Retrieve a token record, or None if not found."""
        ...

    def try_increment_use(
        self, *, receiving_agent_id: AgentId, token_nonce: bytes, expected_revision: int
    ) -> TokenUseOutcome:
        """Atomically increment use_count if revision matches.

        Returns INCREMENTED on success, CONFLICT on version mismatch,
        NOT_FOUND if the record does not exist.
        """
        ...

    def discard(self, *, receiving_agent_id: AgentId, token_nonce: bytes) -> bool:
        """Remove a token record (task completion). Returns True if deleted."""
        ...


__all__ = (
    "SotkClaimOutcome",
    "SotkStore",
    "TokenCreateOutcome",
    "TokenStateStore",
    "TokenUseOutcome",
)
