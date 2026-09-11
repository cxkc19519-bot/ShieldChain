from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import BudgetSnapshot, EvidenceReference
from shieldchain.react.budget import ReactBudgetSupervisor, ReactConsumption
from shieldchain.react.domain import (
    FailureCategory,
    ObservationSource,
    PlanRevision,
    ProposedAction,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
)

NOW = datetime(2026, 7, 23, 17, tzinfo=UTC)
CASE, RUN, LOOP = (UUID(int=value) for value in range(6301, 6304))


def budget(**changes):
    values = dict(
        step_limit=10,
        steps_used=1,
        loop_limit=4,
        loops_used=1,
        time_limit_seconds=60,
        time_used_seconds=2,
        token_limit=1000,
        tokens_used=100,
        cost_limit_usd=2.0,
        cost_used_usd=0.1,
        tool_call_limit=5,
        tool_calls_used=1,
    )
    return BudgetSnapshot(**(values | changes))


def loop(**changes):
    values = dict(
        id=LOOP,
        case_id=CASE,
        run_id=RUN,
        status=ReactLoopStatus.RUNNING,
        revision=1,
        budget=budget(),
        observation_fingerprints=(),
        started_at=NOW,
        updated_at=NOW,
    )
    return ReactLoop(**(values | changes))


def reference():
    return EvidenceReference(uuid4(), CASE, "siem:budget", NOW, "b" * 64)


def observation(**changes):
    values = dict(
        id=uuid4(),
        loop_id=LOOP,
        case_id=CASE,
        run_id=RUN,
        iteration=1,
        source=ObservationSource.EVIDENCE,
        status="insufficient",
        reason_code="evidence_insufficient",
        references=(reference(),),
        observed_at=NOW,
    )
    return ReactObservation(**(values | changes))


def plan(**changes):
    item = ProposedAction(
        uuid4(), "proposed:block_ip", "203.0.113.8", {"firewall_status": "blocked"}, (reference(),)
    )
    values = dict(
        id=uuid4(),
        loop_id=LOOP,
        case_id=CASE,
        run_id=RUN,
        revision=0,
        parent_revision=None,
        retained_action_ids=(),
        removed_action_ids=(),
        added_actions=(item,),
        reason=FailureCategory.EVIDENCE_INSUFFICIENT,
        created_at=NOW,
    )
    return PlanRevision(**(values | changes))


def test_projection_counts_every_server_budget_dimension() -> None:
    result = ReactBudgetSupervisor().project(
        loop=loop(),
        observation=observation(),
        plan=plan(),
        consumption=ReactConsumption(tokens=50, cost_usd=0.2, tool_calls=1),
        now=NOW + timedelta(seconds=5),
    )
    assert result.allowed is True
    assert result.budget.steps_used == 2 and result.budget.loops_used == 2
    assert result.budget.time_used_seconds == 5
    assert result.budget.tokens_used == 150 and result.budget.cost_used_usd == pytest.approx(0.3)
    assert result.budget.tool_calls_used == 2


@pytest.mark.parametrize(
    ("budget_changes", "consumption", "seconds"),
    [
        ({"step_limit": 1}, ReactConsumption(), 0),
        ({"loop_limit": 1}, ReactConsumption(), 0),
        ({"time_limit_seconds": 3}, ReactConsumption(), 4),
        ({"token_limit": 110}, ReactConsumption(tokens=11), 0),
        ({"cost_limit_usd": 0.15}, ReactConsumption(cost_usd=0.06), 0),
        ({"tool_call_limit": 1}, ReactConsumption(), 0),
    ],
)
def test_current_or_projected_limit_stops_before_consumption(
    budget_changes, consumption, seconds
) -> None:
    result = ReactBudgetSupervisor().project(
        loop=loop(budget=budget(**budget_changes)),
        observation=observation(),
        plan=None,
        consumption=consumption,
        now=NOW + timedelta(seconds=seconds),
    )
    assert result.allowed is False
    assert result.stop_category is FailureCategory.BUDGET_EXHAUSTED
    assert result.budget == budget(**budget_changes)


def test_repeated_normalized_observation_and_plan_detects_loop() -> None:
    seen, current_plan = observation(), plan()
    fingerprint = ReactBudgetSupervisor.fingerprint(observation=seen, plan=current_plan)
    repeated = observation(
        id=uuid4(), references=seen.references, observed_at=NOW + timedelta(seconds=1)
    )
    result = ReactBudgetSupervisor().project(
        loop=loop(observation_fingerprints=(fingerprint,)),
        observation=repeated,
        plan=current_plan,
        consumption=ReactConsumption(),
        now=NOW + timedelta(seconds=1),
    )
    assert result.allowed is False and result.stop_category is FailureCategory.LOOP_DETECTED


def test_fingerprint_is_canonical_for_reference_order_but_plan_sensitive() -> None:
    first, second = reference(), reference()
    left = observation(references=(first, second))
    right = observation(id=uuid4(), references=(second, first))
    assert ReactBudgetSupervisor.fingerprint(
        observation=left, plan=None
    ) == ReactBudgetSupervisor.fingerprint(observation=right, plan=None)
    assert ReactBudgetSupervisor.fingerprint(
        observation=left, plan=plan()
    ) != ReactBudgetSupervisor.fingerprint(observation=left, plan=None)


def test_cross_loop_observation_and_plan_are_rejected() -> None:
    supervisor = ReactBudgetSupervisor()
    with pytest.raises(ValueError, match="observation"):
        supervisor.project(
            loop=loop(),
            observation=observation(loop_id=uuid4()),
            plan=None,
            consumption=ReactConsumption(),
            now=NOW,
        )
    with pytest.raises(ValueError, match="plan"):
        supervisor.project(
            loop=loop(),
            observation=observation(),
            plan=plan(run_id=uuid4()),
            consumption=ReactConsumption(),
            now=NOW,
        )


@pytest.mark.parametrize(
    "values",
    [
        {"tokens": True},
        {"tokens": -1},
        {"tool_calls": 101},
        {"cost_usd": float("nan")},
        {"cost_usd": -0.1},
    ],
)
def test_consumption_is_bounded_and_finite(values) -> None:
    with pytest.raises(ValueError):
        ReactConsumption(**values)


def test_wall_clock_cannot_move_backwards() -> None:
    with pytest.raises(ValueError, match="predate"):
        ReactBudgetSupervisor().project(
            loop=loop(),
            observation=observation(),
            plan=None,
            consumption=ReactConsumption(),
            now=NOW - timedelta(seconds=1),
        )
