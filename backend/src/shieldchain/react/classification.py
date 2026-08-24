"""Deterministic classification of trusted role and tool terminal states."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from shieldchain.agents.domain import TerminationReason
from shieldchain.agents.roles import RoleExecutionResult, RoleExecutionStatus
from shieldchain.react.domain import (
    FailureAssessment,
    FailureCategory,
    ReactDecision,
    ReactObservation,
)
from shieldchain.tools.domain import (
    ExecutionOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    VerificationOutcome,
)


@dataclass(frozen=True, slots=True)
class TrustedFailureInput:
    observation: ReactObservation
    call: TrustedToolCall | None = None
    attempt: ToolExecutionAttempt | None = None
    verification: ToolVerification | None = None
    role_result: RoleExecutionResult | None = None
    automation_enabled: bool = True
    emergency_stop_active: bool = False
    evidence_conflict: bool = False
    budget_exhausted: bool = False
    loop_detected: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.observation, ReactObservation):
            raise TypeError("observation must be a ReactObservation")
        if self.call is not None:
            if not isinstance(self.call, TrustedToolCall):
                raise TypeError("call must be a TrustedToolCall")
            if (
                self.call.request.case_id != self.observation.case_id
                or self.call.request.run_id != self.observation.run_id
                or self.observation.tool_call_id != self.call.request.id
            ):
                raise ValueError("tool call does not match the observation boundary")
        for name in ("attempt", "verification"):
            value = getattr(self, name)
            if value is not None and self.call is None:
                raise ValueError(f"{name} requires a bound tool call")
            if value is not None and value.request_id != self.call.request.id:
                raise ValueError(f"{name} belongs to another tool call")
        if self.verification is not None and self.observation.verification_id not in {
            None,
            self.verification.id,
        }:
            raise ValueError("verification does not match the observation")
        if self.role_result is not None:
            if not isinstance(self.role_result, RoleExecutionResult):
                raise TypeError("role_result must be a RoleExecutionResult")
            if (
                self.role_result.output is not None
                and self.role_result.output.case_id != self.observation.case_id
            ):
                raise ValueError("role result belongs to another case")
        for name in (
            "automation_enabled",
            "emergency_stop_active",
            "evidence_conflict",
            "budget_exhausted",
            "loop_detected",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")


_ALLOWED_DECISIONS: dict[FailureCategory, frozenset[ReactDecision]] = {
    FailureCategory.PLAN_ACCEPTED: frozenset({ReactDecision.MANUAL_REVIEW}),
    FailureCategory.COMPLETED: frozenset({ReactDecision.COMPLETE}),
    FailureCategory.VERIFICATION_FAILED: frozenset(
        {ReactDecision.REPLAN, ReactDecision.MANUAL_REVIEW}
    ),
    FailureCategory.VERIFICATION_INCONCLUSIVE: frozenset(
        {ReactDecision.QUERY_STATUS, ReactDecision.MANUAL_REVIEW}
    ),
    FailureCategory.EXECUTION_FAILED: frozenset(
        {ReactDecision.REPLAN, ReactDecision.MANUAL_REVIEW}
    ),
    FailureCategory.EXECUTION_OUTCOME_UNKNOWN: frozenset(
        {ReactDecision.QUERY_STATUS, ReactDecision.MANUAL_REVIEW}
    ),
    FailureCategory.DEPENDENCY_UNAVAILABLE: frozenset(
        {ReactDecision.RETRY_READ_ONLY, ReactDecision.REPLAN, ReactDecision.MANUAL_REVIEW}
    ),
    FailureCategory.EVIDENCE_INSUFFICIENT: frozenset(
        {ReactDecision.REPLAN, ReactDecision.MANUAL_REVIEW}
    ),
    **{
        category: frozenset({ReactDecision.MANUAL_REVIEW})
        for category in (
            FailureCategory.APPROVAL_REJECTED,
            FailureCategory.EMERGENCY_STOPPED,
            FailureCategory.AUTOMATION_DISABLED,
            FailureCategory.EVIDENCE_CONFLICT,
            FailureCategory.BUDGET_EXHAUSTED,
            FailureCategory.LOOP_DETECTED,
            FailureCategory.UNCLASSIFIED_FAILURE,
        )
    },
}

_RECOVERABLE = frozenset(
    {
        FailureCategory.VERIFICATION_FAILED,
        FailureCategory.VERIFICATION_INCONCLUSIVE,
        FailureCategory.EXECUTION_FAILED,
        FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
        FailureCategory.DEPENDENCY_UNAVAILABLE,
        FailureCategory.EVIDENCE_INSUFFICIENT,
    }
)


class DeterministicFailureClassifier:
    def classify(self, value: TrustedFailureInput, *, now: datetime) -> FailureAssessment:
        if not isinstance(value, TrustedFailureInput):
            raise TypeError("value must be a TrustedFailureInput")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("now must be an aware UTC datetime")
        category = self._category(value)
        reason = f"classified_{category.value}"
        return FailureAssessment(
            uuid5(NAMESPACE_URL, f"shieldchain:react:{value.observation.id}:{category.value}"),
            value.observation.id,
            category,
            category in _RECOVERABLE,
            0.5 if category is FailureCategory.UNCLASSIFIED_FAILURE else 1.0,
            reason,
            now,
        )

    @staticmethod
    def allowed_decisions(category: FailureCategory) -> frozenset[ReactDecision]:
        if not isinstance(category, FailureCategory):
            raise TypeError("category must be a FailureCategory")
        return _ALLOWED_DECISIONS[category]

    @staticmethod
    def _category(value: TrustedFailureInput) -> FailureCategory:
        if value.loop_detected:
            return FailureCategory.LOOP_DETECTED
        if value.budget_exhausted:
            return FailureCategory.BUDGET_EXHAUSTED
        if value.emergency_stop_active or (
            value.call is not None and value.call.status is TrustedToolCallStatus.EMERGENCY_STOPPED
        ):
            return FailureCategory.EMERGENCY_STOPPED
        if not value.automation_enabled:
            return FailureCategory.AUTOMATION_DISABLED
        if value.evidence_conflict:
            return FailureCategory.EVIDENCE_CONFLICT
        if value.verification is not None:
            if value.verification.outcome is VerificationOutcome.VERIFIED:
                return FailureCategory.COMPLETED
            if value.verification.outcome is VerificationOutcome.FAILED:
                return FailureCategory.VERIFICATION_FAILED
            if value.verification.outcome is VerificationOutcome.INCONCLUSIVE:
                return FailureCategory.VERIFICATION_INCONCLUSIVE
        if value.attempt is not None:
            if value.attempt.outcome is ExecutionOutcome.UNKNOWN:
                return FailureCategory.EXECUTION_OUTCOME_UNKNOWN
            if value.attempt.outcome is ExecutionOutcome.FAILED:
                return FailureCategory.EXECUTION_FAILED
        if value.call is not None:
            if (
                value.call.status is TrustedToolCallStatus.REJECTED
                and value.call.reason is PolicyReason.APPROVAL_REJECTED
            ):
                return FailureCategory.APPROVAL_REJECTED
            if value.call.reason is PolicyReason.EXECUTION_OUTCOME_UNKNOWN:
                return FailureCategory.EXECUTION_OUTCOME_UNKNOWN
            if value.call.reason is PolicyReason.EXECUTION_FAILED:
                return FailureCategory.EXECUTION_FAILED
            if value.call.reason is PolicyReason.VERIFICATION_FAILED:
                return FailureCategory.VERIFICATION_FAILED
            if value.call.reason is PolicyReason.BUDGET_EXHAUSTED:
                return FailureCategory.BUDGET_EXHAUSTED
        if value.role_result is not None:
            if value.role_result.status in {
                RoleExecutionStatus.DEPENDENCY_UNAVAILABLE,
                RoleExecutionStatus.TIMED_OUT,
            }:
                return FailureCategory.DEPENDENCY_UNAVAILABLE
            if value.role_result.status is RoleExecutionStatus.REFUSED or (
                value.role_result.output is not None
                and value.role_result.output.termination_reason is TerminationReason.NEEDS_REVIEW
            ):
                return FailureCategory.EVIDENCE_INSUFFICIENT
        return FailureCategory.UNCLASSIFIED_FAILURE
