from datetime import UTC, datetime
from uuid import UUID

from shieldchain.agents.domain import BudgetSnapshot
from shieldchain.react.domain import ReactLoop, ReactLoopStatus
from shieldchain.react.recovery import ReactRecoveryDisposition, ReactRecoveryService
from shieldchain.tools.execution import RecoveryDecision, RecoveryDisposition

NOW = datetime(2026, 7, 23, 21, tzinfo=UTC)
LOOP, CASE, RUN, CALL = (UUID(int=x) for x in range(6701, 6705))


def loop(status=ReactLoopStatus.RUNNING):
    budget = BudgetSnapshot(10, 1, 4, 1, 60, 1, 1000, 10, 1, 0, 5, 1)
    return ReactLoop(LOOP, CASE, RUN, status, 1, budget, (), NOW, NOW)


def test_stale_step_without_tool_work_can_resume() -> None:
    result = ReactRecoveryService().decide(loop=loop(), tool=None)
    assert result.disposition is ReactRecoveryDisposition.RESUME_STEP


def test_stage5_recovery_decisions_are_preserved_without_mutation_replay() -> None:
    subject = ReactRecoveryService()
    query = subject.decide(
        loop=loop(),
        tool=RecoveryDecision(
            CALL, RecoveryDisposition.QUERY_STATUS, "state_change_outcome_unknown"
        ),
    )
    retry = subject.decide(
        loop=loop(),
        tool=RecoveryDecision(CALL, RecoveryDisposition.RETRY_SAFE, "registered_safe_retry"),
    )
    assert query.disposition is ReactRecoveryDisposition.QUERY_TOOL_STATUS
    assert retry.disposition is ReactRecoveryDisposition.RETRY_READ_ONLY
    assert query.disposition is not ReactRecoveryDisposition.RESUME_STEP


def test_non_running_loop_always_requires_manual_review() -> None:
    result = ReactRecoveryService().decide(loop=loop(ReactLoopStatus.AWAITING_EXECUTION), tool=None)
    assert result.disposition is ReactRecoveryDisposition.MANUAL_REVIEW
