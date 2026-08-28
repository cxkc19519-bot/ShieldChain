from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from shieldchain.response_planning.domain import ResponsePlan, ResponsePlanStatus

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


def test_response_plan_state_machine_only_allows_forward_transitions() -> None:
    plan = ResponsePlan(uuid4(), uuid4(), uuid4(), uuid4(), ResponsePlanStatus.DRAFT, 0, NOW, NOW)
    proposed = plan.transition(ResponsePlanStatus.PROPOSED, now=NOW + timedelta(seconds=1))
    awaiting = proposed.transition(
        ResponsePlanStatus.AWAITING_EXECUTION, now=NOW + timedelta(seconds=2)
    )
    assert awaiting.status is ResponsePlanStatus.AWAITING_EXECUTION

    with pytest.raises(ValueError, match="invalid response plan transition"):
        awaiting.transition(ResponsePlanStatus.PROPOSED, now=NOW + timedelta(seconds=3))


def test_terminal_and_legacy_plans_cannot_transition() -> None:
    for status in (
        ResponsePlanStatus.COMPLETED,
        ResponsePlanStatus.REJECTED,
        ResponsePlanStatus.CANCELLED,
        ResponsePlanStatus.LEGACY_IMPORTED,
    ):
        plan = ResponsePlan(uuid4(), uuid4(), uuid4(), None, status, 0, NOW, NOW)
        with pytest.raises(ValueError):
            plan.transition(ResponsePlanStatus.PROPOSED, now=NOW)
