from datetime import UTC, datetime
from uuid import UUID, uuid4

from shieldchain.agents.domain import AgentRole, BudgetSnapshot, EvidenceReference
from shieldchain.react.budget import ReactConsumption
from shieldchain.react.classification import TrustedFailureInput
from shieldchain.react.domain import (
    FailureCategory,
    ObservationSource,
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
)
from shieldchain.react.service import ControlledReactService
from shieldchain.tools.domain import (
    PolicyReason,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
)
from shieldchain.tools.registry import default_tool_registry

NOW = datetime(2026, 7, 23, 20, tzinfo=UTC)
TENANT, CASE, RUN, LOOP, CALL = (UUID(int=x) for x in range(6601, 6606))


def ref():
    return EvidenceReference(uuid4(), CASE, "siem:service", NOW, "e" * 64)


def budget(**c):
    return BudgetSnapshot(
        **(
            dict(
                step_limit=10,
                steps_used=1,
                loop_limit=4,
                loops_used=1,
                time_limit_seconds=60,
                time_used_seconds=1,
                token_limit=1000,
                tokens_used=10,
                cost_limit_usd=1,
                cost_used_usd=0,
                tool_call_limit=5,
                tool_calls_used=1,
            )
            | c
        )
    )


def action(name="block_ip", target="203.0.113.8"):
    return ProposedAction(uuid4(), f"proposed:{name}", target, {"state": "expected"}, (ref(),))


def loop(**c):
    return ReactLoop(
        **(
            dict(
                id=LOOP,
                case_id=CASE,
                run_id=RUN,
                status=ReactLoopStatus.RUNNING,
                revision=0,
                budget=budget(),
                observation_fingerprints=(),
                started_at=NOW,
                updated_at=NOW,
            )
            | c
        )
    )


def plan(a):
    return PlanRevision(
        uuid4(), LOOP, CASE, RUN, 0, None, (), (), (a,), FailureCategory.EXECUTION_FAILED, NOW
    )


def failure(reason=PolicyReason.EXECUTION_OUTCOME_UNKNOWN):
    request = TrustedToolRequest(
        CALL,
        CASE,
        RUN,
        uuid4(),
        "phase6:service",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "rollback",
        (ref(),),
        NOW,
    )
    call = TrustedToolCall(request, TrustedToolCallStatus.NEEDS_REVIEW, 4, reason, NOW)
    seen = ReactObservation(
        uuid4(),
        LOOP,
        CASE,
        RUN,
        1,
        ObservationSource.TOOL_CALL,
        "needs_review",
        reason.value,
        (ref(),),
        NOW,
        tool_call_id=CALL,
    )
    return TrustedFailureInput(seen, call=call)


class Store:
    def __init__(self):
        self.bundle = None

    def commit_step(self, *, tenant_id, bundle):
        self.bundle = bundle
        return bundle.changed


def test_unknown_execution_emits_query_instruction_and_atomic_bundle() -> None:
    failed = action()
    store = Store()
    result = ControlledReactService().step(
        tenant_id=TENANT,
        loop=loop(),
        current_plan=plan(failed),
        failure=failure(),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(),
        consumption=ReactConsumption(tool_calls=1),
        registry=default_tool_registry(),
        now=NOW,
        store=store,
    )
    assert result.decision.decision is ReactDecision.QUERY_STATUS
    assert result.query_tool_name == "query_firewall_state"
    assert result.loop.status is ReactLoopStatus.AWAITING_EXECUTION
    assert store.bundle.assessment.observation_id == store.bundle.observation.id
    assert store.bundle.decision.assessment_id == store.bundle.assessment.id


def test_budget_stop_commits_manual_review_without_consuming_budget() -> None:
    failed = action()
    store = Store()
    current = loop(budget=budget(loop_limit=1))
    result = ControlledReactService().step(
        tenant_id=TENANT,
        loop=current,
        current_plan=plan(failed),
        failure=failure(PolicyReason.EXECUTION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(action("isolate_endpoint", "endpoint-42"),),
        consumption=ReactConsumption(),
        registry=default_tool_registry(),
        now=NOW,
        store=store,
    )
    assert result.decision.decision is ReactDecision.MANUAL_REVIEW
    assert result.loop.status is ReactLoopStatus.AWAITING_HUMAN
    assert result.loop.budget == current.budget and result.plan is None
