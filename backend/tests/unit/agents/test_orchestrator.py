from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from shieldchain.agents.context import ContextAssemblyService
from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    BudgetSnapshot,
    CasePhase,
    EvidenceReference,
)
from shieldchain.agents.orchestrator import (
    AdvanceResult,
    OrchestrationState,
    OrchestrationStatus,
    SuperagentOrchestrator,
    SupervisorReason,
)
from shieldchain.agents.roles import (
    ProfessionalRoleRegistry,
    RoleExecutionRequest,
    RoleExecutionResult,
    RoleExecutionStatus,
)
from shieldchain.agents.security import ServerAccessContext
from shieldchain.rag.domain import SensitivityLevel
from shieldchain.tools.domain import (
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)

NOW = datetime(2026, 7, 23, 2, tzinfo=UTC)
CASE = UUID("10000000-0000-0000-0000-000000000001")


def budget(*, steps=0, step_limit=10, tokens=0, token_limit=10000):
    return BudgetSnapshot(step_limit, steps, 2, 0, 60, 0, token_limit, tokens, 1, 0, 5, 0)


def state(phase=CasePhase.TRIAGE, *, retrieval=True, value=None):
    return OrchestrationState(
        CASE,
        phase,
        OrchestrationStatus.RUNNING,
        value or budget(),
        0,
        retrieval,
    )


def trusted_execution(*, status=TrustedToolCallStatus.SUCCEEDED):
    request = TrustedToolRequest(
        UUID(int=1801),
        CASE,
        UUID(int=1802),
        UUID(int=1803),
        "phase5:orchestrator:1801",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Reverse rule.",
        (EvidenceReference(UUID(int=1804), CASE, "siem:orchestrator", NOW, "d" * 64),),
        NOW,
    )
    call = TrustedToolCall(request, status, 5, None, NOW)
    verification = ToolVerification(
        UUID(int=1805),
        request.id,
        VerificationOutcome.VERIFIED,
        {"firewall_status": "blocked"},
        request.evidence,
        None,
        NOW,
    )
    return call, verification


class Contexts:
    def build(self, *, state, role):
        context = ContextAssemblyService(now=NOW).assemble(
            access=ServerAccessContext(
                CASE, uuid4(), role, ("analyst",), (SensitivityLevel.INTERNAL,), ("soc",)
            ),
            system_rules=("system",),
            safety_boundaries=("safety",),
            current_task="task",
            allowed_actions=("block_ip",),
            case_tenant_id=CASE,
            case_sensitivity=SensitivityLevel.INTERNAL,
            case_permission_tags=("soc",),
            case_summary={"case_id": str(CASE), "confirmed_facts": []},
            candidates=(),
            output_schema={"summary": "string"},
            max_tokens=1000,
        )
        return RoleExecutionRequest(role, state.case_id, context, NOW)


class Role:
    def __init__(self, role, result=None):
        self.role = role
        self.result = result
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        if self.result:
            return self.result
        evidence = EvidenceReference(uuid4(), CASE, "siem:1", NOW, "a" * 64)
        output = AgentOutput(self.role, CASE, "summary", (evidence,), (), (), (), NOW)
        return RoleExecutionResult(RoleExecutionStatus.COMPLETED, output)


def registry(overrides=None):
    overrides = overrides or {}
    return ProfessionalRoleRegistry({role: overrides.get(role, Role(role)) for role in AgentRole})


class Commits:
    def __init__(self, fail=False):
        self.fail = fail
        self.items = []

    def commit(self, bundle):
        if self.fail:
            raise RuntimeError("database unavailable")
        self.items.append(bundle)


def orchestrator(*, roles=None, commits=None):
    return SuperagentOrchestrator(
        roles=roles or registry(), contexts=Contexts(), commits=commits or Commits()
    )


def test_whitelisted_step_commits_output_handoff_audit_and_budget_atomically() -> None:
    commits = Commits()
    result = orchestrator(commits=commits).advance(state())
    assert result.committed is True
    assert result.state.phase is CasePhase.INVESTIGATION
    assert commits.items[0].handoff is not None
    assert result.state.revision == 1
    assert result.state.budget.steps_used == 1
    assert len(commits.items) == 1
    assert commits.items[0].output is not None
    assert commits.items[0].audit.from_phase is CasePhase.TRIAGE


def test_investigation_uses_fixed_optional_retrieval_branch() -> None:
    with_retrieval = orchestrator().advance(state(CasePhase.INVESTIGATION, retrieval=True))
    without_retrieval = orchestrator().advance(state(CasePhase.INVESTIGATION, retrieval=False))
    assert with_retrieval.state.phase is CasePhase.RETRIEVAL
    assert without_retrieval.state.phase is CasePhase.RESPONSE_PLANNING


def test_role_failure_routes_to_review_and_invalid_output_terminates() -> None:
    refused = RoleExecutionResult(RoleExecutionStatus.REFUSED, None, "rag_refused")
    roles = registry({AgentRole.KNOWLEDGE_RETRIEVAL: Role(AgentRole.KNOWLEDGE_RETRIEVAL, refused)})
    result = orchestrator(roles=roles).advance(state(CasePhase.RETRIEVAL))
    assert result.state.status is OrchestrationStatus.NEEDS_REVIEW
    assert result.state.reason is SupervisorReason.ROLE_REFUSED

    invalid = RoleExecutionResult(RoleExecutionStatus.INVALID_OUTPUT, None, "bad_schema")
    roles = registry({AgentRole.ALERT_TRIAGE: Role(AgentRole.ALERT_TRIAGE, invalid)})
    result = orchestrator(roles=roles).advance(state())
    assert result.state.status is OrchestrationStatus.TERMINATED
    assert result.state.reason is SupervisorReason.INVALID_ROLE_OUTPUT


def test_budget_stops_before_role_execution() -> None:
    role = Role(AgentRole.ALERT_TRIAGE)
    roles = registry({AgentRole.ALERT_TRIAGE: role})
    result = orchestrator(roles=roles).advance(state(value=budget(steps=1, step_limit=1)))
    assert result.state.status is OrchestrationStatus.TERMINATED
    assert result.state.reason is SupervisorReason.STEP_BUDGET_EXHAUSTED
    assert role.calls == 0


def test_commit_failure_keeps_original_state_for_safe_retry() -> None:
    original = state()
    result = orchestrator(commits=Commits(fail=True)).advance(original)
    assert result == AdvanceResult(original, False, True, None)


def test_response_planning_waits_at_trusted_execution_boundary() -> None:
    output = AgentOutput(
        AgentRole.RESPONSE_PLANNING,
        CASE,
        "plan",
        (),
        (),
        (),
        ("proposed:block_ip",),
        NOW,
    )
    result_value = RoleExecutionResult(RoleExecutionStatus.COMPLETED, output)
    roles = registry({AgentRole.RESPONSE_PLANNING: Role(AgentRole.RESPONSE_PLANNING, result_value)})
    subject = orchestrator(roles=roles)
    waiting = subject.advance(state(CasePhase.RESPONSE_PLANNING))
    assert waiting.state.phase is CasePhase.AWAITING_EXECUTION
    assert waiting.state.status is OrchestrationStatus.AWAITING_TRUSTED_EXECUTION
    assert waiting.state.reason is SupervisorReason.HIGH_RISK_ACTION

    call, verification = trusted_execution()
    resumed = subject.resume_after_execution(
        waiting.state, call=call, verification=verification, now=NOW
    )
    assert resumed.state.phase is CasePhase.VERIFICATION
    assert resumed.state.status is OrchestrationStatus.RUNNING


def test_unverified_trusted_execution_terminal_goes_to_manual_review() -> None:
    subject = orchestrator()
    waiting = OrchestrationState(
        CASE,
        CasePhase.AWAITING_EXECUTION,
        OrchestrationStatus.AWAITING_TRUSTED_EXECUTION,
        budget(),
        1,
        False,
        SupervisorReason.TRUSTED_EXECUTION_REQUIRED,
    )
    call, _ = trusted_execution(status=TrustedToolCallStatus.NEEDS_REVIEW)
    resumed = subject.resume_after_execution(waiting, call=call, verification=None, now=NOW)
    assert resumed.state.phase is CasePhase.NEEDS_REVIEW
    assert resumed.state.status is OrchestrationStatus.NEEDS_REVIEW
    assert resumed.state.reason is SupervisorReason.TRUSTED_EXECUTION_NOT_VERIFIED
