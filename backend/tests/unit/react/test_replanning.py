from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import BudgetSnapshot, EvidenceReference
from shieldchain.react.domain import (
    FailureAssessment,
    FailureCategory,
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
)
from shieldchain.react.replanning import DeterministicReplanner
from shieldchain.tools.registry import default_tool_registry

NOW = datetime(2026, 7, 23, 18, tzinfo=UTC)
CASE, RUN, LOOP = (UUID(int=value) for value in range(6401, 6404))


def reference():
    return EvidenceReference(uuid4(), CASE, "siem:replan", NOW, "c" * 64)


def action(name="block_ip", target="203.0.113.8"):
    expected = (
        {"firewall_status": "blocked"}
        if name == "block_ip"
        else {"endpoint_status": "isolated"}
        if name == "isolate_endpoint"
        else {"account_status": "disabled"}
    )
    return ProposedAction(uuid4(), f"proposed:{name}", target, expected, (reference(),))


def budget():
    return BudgetSnapshot(10, 1, 4, 1, 60, 1, 1000, 10, 1, 0, 5, 1)


def loop():
    return ReactLoop(LOOP, CASE, RUN, ReactLoopStatus.RUNNING, 0, budget(), (), NOW, NOW)


def plan(item):
    return PlanRevision(
        uuid4(),
        LOOP,
        CASE,
        RUN,
        0,
        None,
        (),
        (),
        (item,),
        FailureCategory.EVIDENCE_INSUFFICIENT,
        NOW,
    )


def assessment(category):
    return FailureAssessment(
        uuid4(), uuid4(), category, True, 1, f"classified_{category.value}", NOW
    )


def test_unknown_mutation_only_generates_registered_status_query() -> None:
    failed = action()
    result = DeterministicReplanner().decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.EXECUTION_OUTCOME_UNKNOWN),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(action("isolate_endpoint", "endpoint-42"),),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert result.decision is ReactDecision.QUERY_STATUS
    assert result.query_tool_name == "query_firewall_state" and result.query_target == failed.target
    assert result.plan_revision is None


def test_read_only_dependency_can_only_retry_same_registered_query() -> None:
    failed = action()
    result = DeterministicReplanner().decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.DEPENDENCY_UNAVAILABLE),
        failed_action=failed,
        failed_tool_name="query_firewall_state",
        candidates=(),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert result.decision is ReactDecision.RETRY_READ_ONLY
    assert result.query_tool_name == "query_firewall_state"


def test_safe_candidate_creates_linear_deterministic_revision() -> None:
    failed, candidate = action(), action("isolate_endpoint", "endpoint-42")
    subject = DeterministicReplanner()
    first = subject.decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.VERIFICATION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(candidate,),
        registry=default_tool_registry(),
        now=NOW,
    )
    second = subject.decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.VERIFICATION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(candidate,),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert first.decision is ReactDecision.REPLAN and first.plan_revision.revision == 1
    assert first.plan_revision.removed_action_ids == (failed.id,)
    assert first.plan_revision.added_actions == (candidate,)
    assert first.plan_revision.id == second.plan_revision.id


@pytest.mark.parametrize(
    "category",
    [
        FailureCategory.APPROVAL_REJECTED,
        FailureCategory.EMERGENCY_STOPPED,
        FailureCategory.AUTOMATION_DISABLED,
        FailureCategory.EVIDENCE_CONFLICT,
        FailureCategory.BUDGET_EXHAUSTED,
        FailureCategory.LOOP_DETECTED,
        FailureCategory.UNCLASSIFIED_FAILURE,
    ],
)
def test_stop_categories_never_create_plan(category) -> None:
    failed = action()
    result = DeterministicReplanner().decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(category),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(action("isolate_endpoint", "endpoint-42"),),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert result.decision is ReactDecision.MANUAL_REVIEW and result.plan_revision is None


def test_same_action_and_target_is_not_a_safe_alternative() -> None:
    failed = action()
    duplicate = action("block_ip", failed.target)
    result = DeterministicReplanner().decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.EXECUTION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(duplicate,),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert result.decision is ReactDecision.MANUAL_REVIEW


def test_candidate_selection_is_order_independent() -> None:
    failed = action()
    endpoint, account = (
        action("isolate_endpoint", "endpoint-42"),
        action("disable_account", "user-42"),
    )
    subject = DeterministicReplanner()
    left = subject.decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.EXECUTION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(endpoint, account),
        registry=default_tool_registry(),
        now=NOW,
    )
    right = subject.decide(
        loop=loop(),
        current=plan(failed),
        assessment=assessment(FailureCategory.EXECUTION_FAILED),
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=(account, endpoint),
        registry=default_tool_registry(),
        now=NOW,
    )
    assert left.plan_revision.added_actions == right.plan_revision.added_actions == (account,)


def test_cross_loop_plan_is_rejected() -> None:
    failed = action()
    with pytest.raises(ValueError, match="loop"):
        DeterministicReplanner().decide(
            loop=loop(),
            current=PlanRevision(
                uuid4(),
                uuid4(),
                CASE,
                RUN,
                0,
                None,
                (),
                (),
                (failed,),
                FailureCategory.EXECUTION_FAILED,
                NOW,
            ),
            assessment=assessment(FailureCategory.EXECUTION_FAILED),
            failed_action=failed,
            failed_tool_name="block_ip",
            candidates=(),
            registry=default_tool_registry(),
            now=NOW,
        )
