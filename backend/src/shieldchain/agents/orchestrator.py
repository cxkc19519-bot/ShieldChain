"""Deterministic superagent state machine, supervisor and recoverable step commits."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    BudgetSnapshot,
    CasePhase,
    HandoffPacket,
    TerminationReason,
)
from shieldchain.agents.roles import (
    ProfessionalRoleRegistry,
    RoleExecutionRequest,
    RoleExecutionResult,
    RoleExecutionStatus,
)


class OrchestrationStatus(StrEnum):
    RUNNING = "running"
    AWAITING_TRUSTED_EXECUTION = "awaiting_trusted_execution"
    NEEDS_REVIEW = "needs_review"
    TERMINATED = "terminated"
    COMPLETED = "completed"


class SupervisorReason(StrEnum):
    STEP_BUDGET_EXHAUSTED = "step_budget_exhausted"
    TOKEN_BUDGET_EXHAUSTED = "token_budget_exhausted"
    ROLE_REFUSED = "role_refused"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    ROLE_TIMED_OUT = "role_timed_out"
    INVALID_ROLE_OUTPUT = "invalid_role_output"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    HIGH_RISK_ACTION = "high_risk_action"
    COMMIT_FAILED = "commit_failed"
    TRUSTED_EXECUTION_REQUIRED = "trusted_execution_required"


_ROLE_BY_PHASE = {
    CasePhase.TRIAGE: AgentRole.ALERT_TRIAGE,
    CasePhase.INVESTIGATION: AgentRole.THREAT_INVESTIGATION,
    CasePhase.RETRIEVAL: AgentRole.KNOWLEDGE_RETRIEVAL,
    CasePhase.RESPONSE_PLANNING: AgentRole.RESPONSE_PLANNING,
    CasePhase.VERIFICATION: AgentRole.VERIFICATION,
    CasePhase.REPORTING: AgentRole.REPORTING,
}
_NEXT_PHASE = {
    CasePhase.TRIAGE: CasePhase.INVESTIGATION,
    CasePhase.RETRIEVAL: CasePhase.RESPONSE_PLANNING,
    CasePhase.RESPONSE_PLANNING: CasePhase.AWAITING_EXECUTION,
    CasePhase.VERIFICATION: CasePhase.REPORTING,
    CasePhase.REPORTING: CasePhase.CLOSED,
}
_HIGH_RISK_ACTIONS = frozenset(
    {"block_ip", "isolate_endpoint", "disable_account", "quarantine_file"}
)


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


@dataclass(frozen=True, slots=True)
class OrchestrationState:
    case_id: UUID
    phase: CasePhase
    status: OrchestrationStatus
    budget: BudgetSnapshot
    revision: int
    retrieval_required: bool
    reason: SupervisorReason | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, UUID):
            raise TypeError("case_id must be a UUID")
        if not isinstance(self.phase, CasePhase):
            raise TypeError("phase must be a CasePhase")
        if not isinstance(self.status, OrchestrationStatus):
            raise TypeError("status must be an OrchestrationStatus")
        if not isinstance(self.budget, BudgetSnapshot):
            raise TypeError("budget must be a BudgetSnapshot")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 0
        ):
            raise ValueError("revision must be a non-negative integer")
        if not isinstance(self.retrieval_required, bool):
            raise TypeError("retrieval_required must be a bool")
        if self.reason is not None and not isinstance(self.reason, SupervisorReason):
            raise TypeError("reason must be a SupervisorReason")


@dataclass(frozen=True, slots=True)
class StepAudit:
    event_type: str
    from_phase: CasePhase
    to_phase: CasePhase
    role: AgentRole | None
    result_status: str
    reason: SupervisorReason | None


@dataclass(frozen=True, slots=True)
class AtomicStepBundle:
    id: UUID
    case_id: UUID
    expected_revision: int
    next_revision: int
    output: AgentOutput | None
    handoff: HandoffPacket | None
    audit: StepAudit
    budget: BudgetSnapshot
    created_at: datetime


class OrchestrationContextPort(Protocol):
    def build(self, *, state: OrchestrationState, role: AgentRole) -> RoleExecutionRequest: ...


class AtomicStepCommitPort(Protocol):
    def commit(self, bundle: AtomicStepBundle) -> None: ...


@dataclass(frozen=True, slots=True)
class AdvanceResult:
    state: OrchestrationState
    committed: bool
    retryable: bool
    bundle: AtomicStepBundle | None


class DeterministicSafetySupervisor:
    def projected_budget(
        self, budget: BudgetSnapshot, request: RoleExecutionRequest
    ) -> tuple[BudgetSnapshot | None, SupervisorReason | None]:
        if budget.steps_used >= budget.step_limit:
            return None, SupervisorReason.STEP_BUDGET_EXHAUSTED
        projected_tokens = budget.tokens_used + request.context.total_tokens
        if projected_tokens > budget.token_limit:
            return None, SupervisorReason.TOKEN_BUDGET_EXHAUSTED
        return (
            replace(
                budget,
                steps_used=budget.steps_used + 1,
                tokens_used=projected_tokens,
            ),
            None,
        )

    @staticmethod
    def failure_reason(result: RoleExecutionResult) -> SupervisorReason | None:
        if result.status is RoleExecutionStatus.COMPLETED:
            if result.output.termination_reason is TerminationReason.NEEDS_REVIEW:
                return SupervisorReason.EVIDENCE_INSUFFICIENT
            return None
        return {
            RoleExecutionStatus.REFUSED: SupervisorReason.ROLE_REFUSED,
            RoleExecutionStatus.DEPENDENCY_UNAVAILABLE: SupervisorReason.DEPENDENCY_UNAVAILABLE,
            RoleExecutionStatus.TIMED_OUT: SupervisorReason.ROLE_TIMED_OUT,
            RoleExecutionStatus.INVALID_OUTPUT: SupervisorReason.INVALID_ROLE_OUTPUT,
        }[result.status]

    @staticmethod
    def has_high_risk_action(output: AgentOutput) -> bool:
        return any(
            action.removeprefix("proposed:") in _HIGH_RISK_ACTIONS
            for action in output.recommended_actions
        )


class SuperagentOrchestrator:
    def __init__(
        self,
        *,
        roles: ProfessionalRoleRegistry,
        contexts: OrchestrationContextPort,
        commits: AtomicStepCommitPort,
        supervisor: DeterministicSafetySupervisor | None = None,
    ) -> None:
        self._roles = roles
        self._contexts = contexts
        self._commits = commits
        self._supervisor = supervisor or DeterministicSafetySupervisor()

    def advance(self, state: OrchestrationState) -> AdvanceResult:
        if state.status is not OrchestrationStatus.RUNNING:
            raise ValueError("only a running orchestration can advance")
        role = _ROLE_BY_PHASE.get(state.phase)
        if role is None:
            raise ValueError(f"phase cannot execute a role: {state.phase.value}")
        request = self._contexts.build(state=state, role=role)
        if request.role is not role or request.case_id != state.case_id:
            return self._terminal_without_role(
                state, SupervisorReason.INVALID_ROLE_OUTPUT, OrchestrationStatus.TERMINATED
            )
        budget, budget_reason = self._supervisor.projected_budget(state.budget, request)
        if budget_reason is not None:
            return self._terminal_without_role(state, budget_reason, OrchestrationStatus.TERMINATED)
        assert budget is not None
        result = self._roles.execute(request)
        failure = self._supervisor.failure_reason(result)
        if failure is not None:
            target_status = (
                OrchestrationStatus.TERMINATED
                if failure is SupervisorReason.INVALID_ROLE_OUTPUT
                else OrchestrationStatus.NEEDS_REVIEW
            )
            return self._commit_transition(
                state,
                budget,
                role,
                result,
                CasePhase.NEEDS_REVIEW,
                target_status,
                failure,
            )
        assert result.output is not None
        next_phase = self._next_phase(state)
        next_status = OrchestrationStatus.RUNNING
        reason = None
        if next_phase is CasePhase.AWAITING_EXECUTION:
            next_status = OrchestrationStatus.AWAITING_TRUSTED_EXECUTION
            reason = (
                SupervisorReason.HIGH_RISK_ACTION
                if self._supervisor.has_high_risk_action(result.output)
                else SupervisorReason.TRUSTED_EXECUTION_REQUIRED
            )
        elif next_phase is CasePhase.CLOSED:
            next_status = OrchestrationStatus.COMPLETED
        return self._commit_transition(
            state,
            budget,
            role,
            result,
            next_phase,
            next_status,
            reason,
        )

    def resume_after_execution(
        self, state: OrchestrationState, *, trusted_execution_verified: bool, now: datetime
    ) -> AdvanceResult:
        _utc(now, "now")
        if (
            state.phase is not CasePhase.AWAITING_EXECUTION
            or state.status is not OrchestrationStatus.AWAITING_TRUSTED_EXECUTION
        ):
            raise ValueError("orchestration is not awaiting trusted execution")
        if not trusted_execution_verified:
            target_phase = CasePhase.NEEDS_REVIEW
            target_status = OrchestrationStatus.NEEDS_REVIEW
            reason = SupervisorReason.TRUSTED_EXECUTION_REQUIRED
        else:
            target_phase = CasePhase.VERIFICATION
            target_status = OrchestrationStatus.RUNNING
            reason = None
        bundle = self._bundle(
            state,
            state.budget,
            None,
            None,
            target_phase,
            reason,
            "execution_boundary",
            now,
        )
        return self._commit_bundle(state, bundle, target_phase, target_status, reason)

    def _next_phase(self, state: OrchestrationState) -> CasePhase:
        if state.phase is CasePhase.INVESTIGATION:
            return CasePhase.RETRIEVAL if state.retrieval_required else CasePhase.RESPONSE_PLANNING
        target = _NEXT_PHASE.get(state.phase)
        if target is None:
            raise ValueError(f"no whitelisted transition from {state.phase.value}")
        return target

    def _commit_transition(
        self,
        state: OrchestrationState,
        budget: BudgetSnapshot,
        role: AgentRole,
        result: RoleExecutionResult,
        next_phase: CasePhase,
        next_status: OrchestrationStatus,
        reason: SupervisorReason | None,
    ) -> AdvanceResult:
        handoff = self._handoff(state, result.output, role, next_phase)
        bundle = self._bundle(
            state,
            budget,
            role,
            result.output,
            next_phase,
            reason,
            result.status.value,
            result.output.created_at if result.output else datetime.now(UTC),
            handoff,
        )
        return self._commit_bundle(state, bundle, next_phase, next_status, reason)

    def _terminal_without_role(
        self,
        state: OrchestrationState,
        reason: SupervisorReason,
        status: OrchestrationStatus,
    ) -> AdvanceResult:
        now = datetime.now(UTC)
        bundle = self._bundle(
            state,
            state.budget,
            None,
            None,
            CasePhase.NEEDS_REVIEW,
            reason,
            "supervisor_stop",
            now,
        )
        return self._commit_bundle(state, bundle, CasePhase.NEEDS_REVIEW, status, reason)

    def _commit_bundle(
        self,
        state: OrchestrationState,
        bundle: AtomicStepBundle,
        phase: CasePhase,
        status: OrchestrationStatus,
        reason: SupervisorReason | None,
    ) -> AdvanceResult:
        try:
            self._commits.commit(bundle)
        except Exception:
            return AdvanceResult(state, False, True, None)
        next_state = OrchestrationState(
            state.case_id,
            phase,
            status,
            bundle.budget,
            state.revision + 1,
            state.retrieval_required,
            reason,
        )
        return AdvanceResult(next_state, True, False, bundle)

    @staticmethod
    def _handoff(
        state: OrchestrationState,
        output: AgentOutput | None,
        role: AgentRole,
        next_phase: CasePhase,
    ) -> HandoffPacket | None:
        receiver = _ROLE_BY_PHASE.get(next_phase)
        if output is None or receiver is None or not output.references:
            return None
        return HandoffPacket(
            uuid5(
                NAMESPACE_URL,
                f"shieldchain:{state.case_id}:{state.revision}:{role.value}:{receiver.value}",
            ),
            state.case_id,
            role,
            receiver,
            output.summary,
            output.references,
            0.7,
            (),
            output.recommended_actions or ("Review prior role output",),
            output.created_at,
        )

    @staticmethod
    def _bundle(
        state: OrchestrationState,
        budget: BudgetSnapshot,
        role: AgentRole | None,
        output: AgentOutput | None,
        next_phase: CasePhase,
        reason: SupervisorReason | None,
        result_status: str,
        created_at: datetime,
        handoff: HandoffPacket | None = None,
    ) -> AtomicStepBundle:
        return AtomicStepBundle(
            uuid5(
                NAMESPACE_URL,
                f"shieldchain:{state.case_id}:{state.revision}:{state.phase.value}:{next_phase.value}",
            ),
            state.case_id,
            state.revision,
            state.revision + 1,
            output,
            handoff,
            StepAudit(
                "agent_step_committed",
                state.phase,
                next_phase,
                role,
                result_status,
                reason,
            ),
            budget,
            created_at,
        )
