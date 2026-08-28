"""Immutable contracts and allowlisted state machine for trusted tool calls."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar
from uuid import UUID

from shieldchain.agents.domain import AgentRole, Reference

type ToolScalar = str | int | float | bool
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_VERSION = re.compile(r"^[1-9][0-9]{0,5}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "tenant_id",
        "principal_id",
        "api_key",
        "password",
        "secret",
        "token",
        "credential",
        "prompt",
        "raw_prompt",
        "chain_of_thought",
        "shell",
        "command",
        "code",
        "script",
        "url",
        "uri",
    }
)


def _uuid(value: UUID, name: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _text(value: str, name: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise ValueError(f"{name} is invalid")
    return normalized


def _name(value: str, name: str) -> str:
    normalized = _text(value, name, maximum=64)
    if not _NAME.fullmatch(normalized):
        raise ValueError(f"{name} is invalid")
    return normalized


def _arguments(values: Mapping[str, ToolScalar]) -> Mapping[str, ToolScalar]:
    if not isinstance(values, Mapping):
        raise TypeError("arguments must be a mapping")
    result: dict[str, ToolScalar] = {}
    for key, value in values.items():
        normalized_key = _name(key, "argument key")
        if normalized_key in _FORBIDDEN_ARGUMENT_KEYS:
            raise ValueError(f"argument is forbidden: {normalized_key}")
        if not isinstance(value, (str, int, float, bool)) or value is None:
            raise TypeError("argument values must be JSON scalar values")
        if isinstance(value, str):
            value = _text(value, f"argument {normalized_key}", maximum=512)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("numeric arguments must be finite")
        result[normalized_key] = value
    if not result or len(result) > 32:
        raise ValueError("arguments must contain between 1 and 32 fields")
    return MappingProxyType(dict(sorted(result.items())))


class ToolRisk(StrEnum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolTargetType(StrEnum):
    IPV4 = "ipv4"
    ENDPOINT = "endpoint"
    ACCOUNT = "account"


class TrustedToolCallStatus(StrEnum):
    PROPOSED = "proposed"
    POLICY_CHECKED = "policy_checked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    PAUSED = "paused"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EMERGENCY_STOPPED = "emergency_stopped"


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class PolicyReason(StrEnum):
    POLICY_ALLOWED = "policy_allowed"
    AUTOMATIC_SIMULATION_APPROVAL = "automatic_simulation_approval"
    APPROVAL_REQUIRED = "approval_required"
    AUTOMATION_DISABLED = "automation_disabled"
    EMERGENCY_STOP_ACTIVE = "emergency_stop_active"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    CALLER_NOT_ALLOWED = "caller_not_allowed"
    CASE_BINDING_INVALID = "case_binding_invalid"
    EVIDENCE_REQUIRED = "evidence_required"
    EVIDENCE_INVALID = "evidence_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RATE_LIMITED = "rate_limited"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    VERIFICATION_FAILED = "verification_failed"


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class VerificationOutcome(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    version: str
    target_type: ToolTargetType
    risk: ToolRisk
    allowed_roles: frozenset[AgentRole]
    timeout_seconds: float
    max_retries: int
    mutates_state: bool
    verifier_name: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _name(self.name, "name"))
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("version must be a positive integer string")
        if not isinstance(self.target_type, ToolTargetType):
            raise TypeError("target_type must be a ToolTargetType")
        if not isinstance(self.risk, ToolRisk):
            raise TypeError("risk must be a ToolRisk")
        roles = frozenset(self.allowed_roles)
        if not roles or any(not isinstance(role, AgentRole) for role in roles):
            raise ValueError("allowed_roles must contain AgentRole values")
        object.__setattr__(self, "allowed_roles", roles)
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or not 0.05 <= self.timeout_seconds <= 30
        ):
            raise ValueError("timeout_seconds must be between 0.05 and 30")
        if (
            not isinstance(self.max_retries, int)
            or isinstance(self.max_retries, bool)
            or not 0 <= self.max_retries <= 3
        ):
            raise ValueError("max_retries must be between 0 and 3")
        if not isinstance(self.mutates_state, bool):
            raise TypeError("mutates_state must be a bool")
        if self.mutates_state and self.verifier_name is None:
            raise ValueError("state-changing tools require a verifier")
        if self.verifier_name is not None:
            object.__setattr__(self, "verifier_name", _name(self.verifier_name, "verifier_name"))
        if self.risk is ToolRisk.READ_ONLY and self.mutates_state:
            raise ValueError("read-only tools cannot mutate state")
        if self.risk in {ToolRisk.HIGH, ToolRisk.CRITICAL} and self.max_retries:
            raise ValueError("high-risk tools cannot be blindly retried")

    @property
    def identity(self) -> tuple[str, str]:
        return self.name, self.version


@dataclass(frozen=True, slots=True)
class TrustedToolRequest:
    id: UUID
    case_id: UUID
    run_id: UUID
    plan_id: UUID
    idempotency_key: str
    caller_role: AgentRole
    tool_name: str
    tool_version: str
    arguments: Mapping[str, ToolScalar]
    expected_state: Mapping[str, ToolScalar]
    rollback_strategy: str
    evidence: tuple[Reference, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "case_id", "run_id", "plan_id"):
            _uuid(getattr(self, name), name)
        if not isinstance(self.idempotency_key, str) or not _IDEMPOTENCY_KEY.fullmatch(
            self.idempotency_key
        ):
            raise ValueError("idempotency_key is invalid")
        if not isinstance(self.caller_role, AgentRole):
            raise TypeError("caller_role must be an AgentRole")
        object.__setattr__(self, "tool_name", _name(self.tool_name, "tool_name"))
        if not isinstance(self.tool_version, str) or not _VERSION.fullmatch(self.tool_version):
            raise ValueError("tool_version is invalid")
        object.__setattr__(self, "arguments", _arguments(self.arguments))
        object.__setattr__(self, "expected_state", _arguments(self.expected_state))
        object.__setattr__(
            self,
            "rollback_strategy",
            _text(self.rollback_strategy, "rollback_strategy", maximum=512),
        )
        references = tuple(self.evidence)
        if not references or any(not isinstance(item, Reference) for item in references):
            raise ValueError("evidence must contain trusted references")
        if any(item.case_id != self.case_id for item in references):
            raise ValueError("evidence must belong to the same case")
        object.__setattr__(self, "evidence", references)
        _utc(self.created_at, "created_at")

    @property
    def request_digest(self) -> str:
        payload = {
            "case_id": str(self.case_id),
            "run_id": str(self.run_id),
            "plan_id": str(self.plan_id),
            "caller_role": self.caller_role.value,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "arguments": dict(self.arguments),
            "expected_state": dict(self.expected_state),
            "rollback_strategy": self.rollback_strategy,
            "evidence": [item.to_dict() for item in self.evidence],
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    request_id: UUID
    outcome: PolicyOutcome
    reason: PolicyReason
    policy_version: str
    assessed_risk: ToolRisk
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.request_id, "request_id")
        if not isinstance(self.outcome, PolicyOutcome):
            raise TypeError("outcome must be a PolicyOutcome")
        if not isinstance(self.reason, PolicyReason):
            raise TypeError("reason must be a PolicyReason")
        object.__setattr__(
            self, "policy_version", _text(self.policy_version, "policy_version", maximum=64)
        )
        if not isinstance(self.assessed_risk, ToolRisk):
            raise TypeError("assessed_risk must be a ToolRisk")
        _utc(self.created_at, "created_at")
        _utc(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("policy decision must expire after creation")


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    id: UUID
    request_id: UUID
    request_digest: str
    outcome: ApprovalOutcome
    approver_subject_id: UUID
    policy_version: str
    reason_summary: str
    decided_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "request_id", "approver_subject_id"):
            _uuid(getattr(self, name), name)
        if not isinstance(self.request_digest, str) or not _SHA256.fullmatch(self.request_digest):
            raise ValueError("request_digest must be lowercase SHA-256")
        if not isinstance(self.outcome, ApprovalOutcome):
            raise TypeError("outcome must be an ApprovalOutcome")
        object.__setattr__(
            self, "policy_version", _text(self.policy_version, "policy_version", maximum=64)
        )
        object.__setattr__(
            self, "reason_summary", _text(self.reason_summary, "reason_summary", maximum=512)
        )
        _utc(self.decided_at, "decided_at")
        _utc(self.expires_at, "expires_at")
        if self.expires_at <= self.decided_at:
            raise ValueError("approval must expire after decision")


@dataclass(frozen=True, slots=True)
class ToolExecutionAttempt:
    id: UUID
    request_id: UUID
    attempt_number: int
    outcome: ExecutionOutcome
    result_summary: str
    error_category: str | None
    started_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _uuid(self.request_id, "request_id")
        if (
            not isinstance(self.attempt_number, int)
            or isinstance(self.attempt_number, bool)
            or not 1 <= self.attempt_number <= 4
        ):
            raise ValueError("attempt_number must be between 1 and 4")
        if not isinstance(self.outcome, ExecutionOutcome):
            raise TypeError("outcome must be an ExecutionOutcome")
        object.__setattr__(
            self, "result_summary", _text(self.result_summary, "result_summary", maximum=1024)
        )
        if self.error_category is not None:
            object.__setattr__(self, "error_category", _name(self.error_category, "error_category"))
        if self.outcome is ExecutionOutcome.SUCCEEDED and self.error_category is not None:
            raise ValueError("successful attempts cannot have an error category")
        _utc(self.started_at, "started_at")
        _utc(self.completed_at, "completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be before started_at")


@dataclass(frozen=True, slots=True)
class ToolVerification:
    id: UUID
    request_id: UUID
    outcome: VerificationOutcome
    observed_state: Mapping[str, ToolScalar]
    evidence: tuple[Reference, ...]
    reason: PolicyReason | None
    verified_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.id, "id")
        _uuid(self.request_id, "request_id")
        if not isinstance(self.outcome, VerificationOutcome):
            raise TypeError("outcome must be a VerificationOutcome")
        object.__setattr__(self, "observed_state", _arguments(self.observed_state))
        references = tuple(self.evidence)
        if any(not isinstance(item, Reference) for item in references):
            raise TypeError("evidence must contain trusted references")
        object.__setattr__(self, "evidence", references)
        if self.reason is not None and not isinstance(self.reason, PolicyReason):
            raise TypeError("reason must be a PolicyReason")
        if self.outcome is VerificationOutcome.VERIFIED and self.reason is not None:
            raise ValueError("verified results cannot have a failure reason")
        _utc(self.verified_at, "verified_at")


@dataclass(frozen=True, slots=True)
class TrustedToolCall:
    request: TrustedToolRequest
    status: TrustedToolCallStatus
    revision: int
    reason: PolicyReason | None
    updated_at: datetime

    _TRANSITIONS: ClassVar[Mapping[TrustedToolCallStatus, frozenset[TrustedToolCallStatus]]] = {
        TrustedToolCallStatus.PROPOSED: frozenset(
            {
                TrustedToolCallStatus.POLICY_CHECKED,
                TrustedToolCallStatus.PAUSED,
                TrustedToolCallStatus.REJECTED,
                TrustedToolCallStatus.CANCELLED,
                TrustedToolCallStatus.EMERGENCY_STOPPED,
            }
        ),
        TrustedToolCallStatus.POLICY_CHECKED: frozenset(
            {
                TrustedToolCallStatus.AWAITING_APPROVAL,
                TrustedToolCallStatus.APPROVED,
                TrustedToolCallStatus.PAUSED,
                TrustedToolCallStatus.REJECTED,
                TrustedToolCallStatus.CANCELLED,
                TrustedToolCallStatus.EMERGENCY_STOPPED,
            }
        ),
        TrustedToolCallStatus.AWAITING_APPROVAL: frozenset(
            {
                TrustedToolCallStatus.APPROVED,
                TrustedToolCallStatus.PAUSED,
                TrustedToolCallStatus.NEEDS_REVIEW,
                TrustedToolCallStatus.REJECTED,
                TrustedToolCallStatus.CANCELLED,
                TrustedToolCallStatus.EMERGENCY_STOPPED,
            }
        ),
        TrustedToolCallStatus.APPROVED: frozenset(
            {
                TrustedToolCallStatus.EXECUTING,
                TrustedToolCallStatus.PAUSED,
                TrustedToolCallStatus.CANCELLED,
                TrustedToolCallStatus.EMERGENCY_STOPPED,
            }
        ),
        TrustedToolCallStatus.PAUSED: frozenset(
            {
                TrustedToolCallStatus.PROPOSED,
                TrustedToolCallStatus.POLICY_CHECKED,
                TrustedToolCallStatus.AWAITING_APPROVAL,
                TrustedToolCallStatus.APPROVED,
                TrustedToolCallStatus.CANCELLED,
                TrustedToolCallStatus.EMERGENCY_STOPPED,
            }
        ),
        TrustedToolCallStatus.EXECUTING: frozenset(
            {
                TrustedToolCallStatus.VERIFYING,
                TrustedToolCallStatus.FAILED,
                TrustedToolCallStatus.NEEDS_REVIEW,
            }
        ),
        TrustedToolCallStatus.VERIFYING: frozenset(
            {
                TrustedToolCallStatus.SUCCEEDED,
                TrustedToolCallStatus.FAILED,
                TrustedToolCallStatus.NEEDS_REVIEW,
            }
        ),
    }

    def __post_init__(self) -> None:
        if not isinstance(self.request, TrustedToolRequest):
            raise TypeError("request must be a TrustedToolRequest")
        if not isinstance(self.status, TrustedToolCallStatus):
            raise TypeError("status must be a TrustedToolCallStatus")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")
        if self.reason is not None and not isinstance(self.reason, PolicyReason):
            raise TypeError("reason must be a PolicyReason")
        _utc(self.updated_at, "updated_at")

    def transition(
        self,
        target: TrustedToolCallStatus,
        *,
        now: datetime,
        reason: PolicyReason | None = None,
    ) -> TrustedToolCall:
        _utc(now, "now")
        if not isinstance(target, TrustedToolCallStatus):
            raise TypeError("target must be a TrustedToolCallStatus")
        if target not in self._TRANSITIONS.get(self.status, frozenset()):
            raise ValueError(f"transition is not allowed: {self.status.value} -> {target.value}")
        if now < self.updated_at:
            raise ValueError("transition time cannot move backwards")
        return replace(
            self,
            status=target,
            revision=self.revision + 1,
            reason=reason,
            updated_at=now,
        )
