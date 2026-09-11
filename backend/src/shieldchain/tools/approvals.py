"""Approval lifecycle with digest binding and separation of duties."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolRisk,
    TrustedToolCall,
    TrustedToolCallStatus,
)

AUTOMATIC_POLICY_SUBJECT = UUID("00000000-0000-4000-8000-000000000005")


class ApprovalError(RuntimeError):
    pass


class ApprovalAccessDenied(ApprovalError):
    pass


class ApprovalExpired(ApprovalError):
    pass


class ApprovalConflict(ApprovalError):
    pass


class ApprovalStateInvalid(ApprovalError):
    pass


class ApprovalStore(Protocol):
    def latest(self, *, tenant_id: UUID, request_id: UUID) -> ApprovalDecision | None: ...

    def append(self, *, tenant_id: UUID, decision: ApprovalDecision) -> None: ...


@dataclass(frozen=True, slots=True)
class ApprovalAuthority:
    tenant_id: UUID
    subject_id: UUID
    permissions: frozenset[str]
    now: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID) or not isinstance(self.subject_id, UUID):
            raise TypeError("tenant_id and subject_id must be UUID values")
        permissions = frozenset(self.permissions)
        if any(not isinstance(value, str) or not value for value in permissions):
            raise TypeError("permissions must contain non-empty strings")
        object.__setattr__(self, "permissions", permissions)
        if self.now.tzinfo is None or self.now.utcoffset() != timedelta(0):
            raise ValueError("now must be an aware UTC datetime")


class TrustedToolApprovalService:
    def decide(
        self,
        *,
        call: TrustedToolCall,
        policy: PolicyDecision,
        authority: ApprovalAuthority,
        requester_subject_id: UUID,
        outcome: ApprovalOutcome,
        reason_summary: str,
        store: ApprovalStore,
    ) -> ApprovalDecision:
        self._validate_common(call, policy, authority.now)
        if policy.outcome is not PolicyOutcome.APPROVAL_REQUIRED:
            raise ApprovalStateInvalid("policy does not require human approval")
        required = (
            "trusted_tools.approve_critical"
            if policy.assessed_risk is ToolRisk.CRITICAL
            else "trusted_tools.approve"
        )
        if required not in authority.permissions:
            raise ApprovalAccessDenied("approval permission is missing")
        if authority.subject_id == requester_subject_id:
            raise ApprovalAccessDenied("requester cannot approve the same high-risk call")
        existing = store.latest(tenant_id=authority.tenant_id, request_id=call.request.id)
        if existing is not None:
            if (
                existing.request_digest == call.request.request_digest
                and existing.outcome is outcome
            ):
                return existing
            raise ApprovalConflict("an approval decision already exists")
        decision = ApprovalDecision(
            uuid4(),
            call.request.id,
            call.request.request_digest,
            outcome,
            authority.subject_id,
            policy.policy_version,
            reason_summary,
            authority.now,
            min(policy.expires_at, authority.now + timedelta(minutes=10)),
        )
        store.append(tenant_id=authority.tenant_id, decision=decision)
        return decision

    def record_automatic(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        policy: PolicyDecision,
        store: ApprovalStore,
    ) -> ApprovalDecision:
        self._validate_common(call, policy, policy.created_at)
        if (
            policy.outcome is not PolicyOutcome.ALLOW
            or policy.reason is not PolicyReason.AUTOMATIC_SIMULATION_APPROVAL
        ):
            raise ApprovalStateInvalid("policy is not an automatic simulation approval")
        existing = store.latest(tenant_id=tenant_id, request_id=call.request.id)
        if existing is not None:
            if existing.request_digest == call.request.request_digest:
                return existing
            raise ApprovalConflict("automatic approval digest conflict")
        decision = ApprovalDecision(
            uuid4(),
            call.request.id,
            call.request.request_digest,
            ApprovalOutcome.APPROVED,
            AUTOMATIC_POLICY_SUBJECT,
            policy.policy_version,
            "Approved by deterministic simulation policy.",
            policy.created_at,
            policy.expires_at,
        )
        store.append(tenant_id=tenant_id, decision=decision)
        return decision

    @staticmethod
    def _validate_common(call: TrustedToolCall, policy: PolicyDecision, now: datetime) -> None:
        if call.status not in {
            TrustedToolCallStatus.POLICY_CHECKED,
            TrustedToolCallStatus.AWAITING_APPROVAL,
        }:
            raise ApprovalStateInvalid("tool call is not in an approvable state")
        if policy.request_id != call.request.id:
            raise ApprovalConflict("policy belongs to a different request")
        if policy.expires_at <= now:
            raise ApprovalExpired("policy decision has expired")
