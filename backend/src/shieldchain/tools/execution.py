"""Execution leases, usage counters, and deterministic recovery decisions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus
from shieldchain.tools.registry import BoundToolRequest

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


@dataclass(frozen=True, slots=True)
class ToolExecutionLease:
    id: UUID
    request_id: UUID
    holder_id: UUID
    attempt_number: int
    token_digest: str
    acquired_at: datetime
    expires_at: datetime
    released_at: datetime | None = None
    release_reason: str | None = None

    def __post_init__(self) -> None:
        if not all(isinstance(value, UUID) for value in (self.id, self.request_id, self.holder_id)):
            raise TypeError("lease identifiers must be UUID values")
        if not 1 <= self.attempt_number <= 4:
            raise ValueError("lease attempt_number must be between 1 and 4")
        if not re.fullmatch(r"[0-9a-f]{64}", self.token_digest):
            raise ValueError("token_digest must be lowercase SHA-256")
        for name in ("acquired_at", "expires_at"):
            value = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be an aware UTC datetime")
        if self.expires_at <= self.acquired_at:
            raise ValueError("execution lease must expire after acquisition")
        if (self.released_at is None) != (self.release_reason is None):
            raise ValueError("release time and reason must be set together")
        if self.released_at is not None:
            if self.released_at.tzinfo is None or self.released_at.utcoffset() != timedelta(0):
                raise ValueError("released_at must be an aware UTC datetime")
            if self.released_at < self.acquired_at:
                raise ValueError("released_at cannot predate acquisition")

    @property
    def active(self) -> bool:
        return self.released_at is None

    def matches(self, token: str) -> bool:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return False
        return hashlib.sha256(token.encode("ascii")).hexdigest() == self.token_digest


@dataclass(frozen=True, slots=True)
class ExecutionLeaseGrant:
    lease: ToolExecutionLease
    token: str

    def __post_init__(self) -> None:
        if not self.lease.matches(self.token):
            raise ValueError("lease grant token does not match its digest")


@dataclass(frozen=True, slots=True)
class ToolExecutionUsage:
    call_count: int
    attempt_count: int

    def __post_init__(self) -> None:
        if self.call_count < 0 or self.attempt_count < 0:
            raise ValueError("execution usage cannot be negative")


class RecoveryDisposition(StrEnum):
    RETRY_SAFE = "retry_safe"
    QUERY_STATUS = "query_status"
    VERIFY_RESULT = "verify_result"
    WAIT_FOR_APPROVAL = "wait_for_approval"
    MANUAL_REVIEW = "manual_review"


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    request_id: UUID
    disposition: RecoveryDisposition
    reason: str


class TrustedToolRecoveryService:
    """Plan recovery without replaying a state-changing action."""

    def decide(
        self,
        *,
        bound: BoundToolRequest,
        call: TrustedToolCall,
        lease: ToolExecutionLease | None,
        attempt_count: int,
        automation_enabled: bool,
        budget_remaining: int,
        now: datetime,
    ) -> RecoveryDecision:
        if call.status is TrustedToolCallStatus.AWAITING_APPROVAL:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.WAIT_FOR_APPROVAL,
                "approval_required",
            )
        if call.status is TrustedToolCallStatus.VERIFYING:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.VERIFY_RESULT,
                "verification_incomplete",
            )
        if (
            call.status is not TrustedToolCallStatus.EXECUTING
            or lease is None
            or not lease.active
            or lease.expires_at > now
        ):
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.MANUAL_REVIEW,
                "state_not_recoverable",
            )
        if not automation_enabled:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.MANUAL_REVIEW,
                "automation_disabled",
            )
        if budget_remaining <= 0:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.MANUAL_REVIEW,
                "budget_exhausted",
            )
        definition = bound.registration.definition
        if definition.mutates_state:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.QUERY_STATUS,
                "state_change_outcome_unknown",
            )
        if attempt_count <= definition.max_retries:
            return RecoveryDecision(
                call.request.id,
                RecoveryDisposition.RETRY_SAFE,
                "registered_safe_retry",
            )
        return RecoveryDecision(
            call.request.id,
            RecoveryDisposition.MANUAL_REVIEW,
            "retry_limit_exhausted",
        )
