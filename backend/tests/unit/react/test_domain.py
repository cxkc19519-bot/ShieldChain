import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import BudgetSnapshot, EvidenceReference
from shieldchain.react.domain import (
    FailureAssessment,
    FailureCategory,
    ObservationSource,
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
    ReactStepDecision,
)

NOW = datetime(2026, 7, 23, 15, tzinfo=UTC)
CASE, RUN, LOOP = (UUID(int=value) for value in range(6101, 6104))


def reference(case_id: UUID = CASE):
    return EvidenceReference(uuid4(), case_id, "siem:phase6", NOW, "f" * 64)


def budget(**changes):
    values = dict(
        step_limit=20,
        steps_used=2,
        loop_limit=4,
        loops_used=1,
        time_limit_seconds=600,
        time_used_seconds=12,
        token_limit=20_000,
        tokens_used=500,
        cost_limit_usd=5.0,
        cost_used_usd=0.2,
        tool_call_limit=10,
        tool_calls_used=1,
    )
    return BudgetSnapshot(**(values | changes))


def observation(**changes):
    values = dict(
        id=uuid4(),
        loop_id=LOOP,
        case_id=CASE,
        run_id=RUN,
        iteration=1,
        source=ObservationSource.TOOL_VERIFICATION,
        status="failed",
        reason_code="verification_failed",
        references=(reference(),),
        observed_at=NOW,
        tool_call_id=uuid4(),
        verification_id=uuid4(),
    )
    return ReactObservation(**(values | changes))


def assessment(observation_id=None, **changes):
    values = dict(
        id=uuid4(),
        observation_id=observation_id or uuid4(),
        category=FailureCategory.VERIFICATION_FAILED,
        recoverable=True,
        confidence=1.0,
        reason_code="verified_state_mismatch",
        assessed_at=NOW,
    )
    return FailureAssessment(**(values | changes))


def action(**changes):
    values = dict(
        id=uuid4(),
        action="proposed:block_ip",
        target="203.0.113.8",
        expected_state={"firewall_status": "blocked"},
        references=(reference(),),
    )
    return ProposedAction(**(values | changes))


def test_enums_are_closed_and_explicit() -> None:
    assert ReactDecision.QUERY_STATUS.value == "query_status"
    assert FailureCategory.COMPLETED.value == "completed"
    assert FailureCategory.UNCLASSIFIED_FAILURE.value == "unclassified_failure"
    assert "execute_arbitrary" not in ReactDecision._value2member_map_


def test_tool_observations_bind_real_call_and_verification_ids() -> None:
    with pytest.raises(ValueError, match="tool_call_id"):
        observation(tool_call_id=None)
    with pytest.raises(ValueError, match="verification_id"):
        observation(verification_id=None)
    role = observation(source=ObservationSource.ROLE, tool_call_id=None, verification_id=None)
    assert role.source is ObservationSource.ROLE


def test_observation_requires_same_case_trusted_references() -> None:
    with pytest.raises(ValueError, match="same case"):
        observation(references=(reference(uuid4()),))
    with pytest.raises(TypeError, match="trusted references"):
        observation(references=("untrusted",))


@pytest.mark.parametrize(
    "value", [datetime(2026, 7, 23), datetime(2026, 7, 23, tzinfo=timezone(timedelta(hours=8)))]
)
def test_all_timestamps_require_aware_utc(value) -> None:
    with pytest.raises(ValueError, match="aware UTC"):
        observation(observed_at=value)


@pytest.mark.parametrize("value", [-0.1, 1.1, True, float("nan"), float("inf")])
def test_assessment_confidence_is_finite_and_bounded(value) -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        assessment(confidence=value)


def test_proposed_action_is_allowlisted_cited_and_defensively_frozen() -> None:
    state = {"firewall_status": "blocked"}
    item = action(expected_state=state)
    state["firewall_status"] = "mutated"
    assert item.expected_state == {"firewall_status": "blocked"}
    assert isinstance(item.expected_state, MappingProxyType)
    with pytest.raises(ValueError, match="allowed"):
        action(action="proposed:run_shell")
    with pytest.raises(ValueError, match="reference"):
        action(references=())


def test_plan_revision_has_linear_parent_and_disjoint_action_changes() -> None:
    kept, removed = uuid4(), uuid4()
    item = PlanRevision(
        uuid4(),
        LOOP,
        CASE,
        RUN,
        1,
        0,
        (kept,),
        (removed,),
        (action(),),
        FailureCategory.EXECUTION_FAILED,
        NOW,
    )
    assert item.parent_revision == 0
    with pytest.raises(ValueError, match="previous"):
        PlanRevision(
            uuid4(), LOOP, CASE, RUN, 2, 0, (), (), (), FailureCategory.EXECUTION_FAILED, NOW
        )
    with pytest.raises(ValueError, match="disjoint"):
        PlanRevision(
            uuid4(),
            LOOP,
            CASE,
            RUN,
            1,
            0,
            (kept,),
            (kept,),
            (),
            FailureCategory.EXECUTION_FAILED,
            NOW,
        )


def test_added_action_references_must_match_revision_case() -> None:
    with pytest.raises(ValueError, match="same case"):
        PlanRevision(
            uuid4(),
            LOOP,
            uuid4(),
            RUN,
            0,
            None,
            (),
            (),
            (action(),),
            FailureCategory.EXECUTION_FAILED,
            NOW,
        )


def test_loop_freezes_fingerprints_and_validates_time_order() -> None:
    values = ["a" * 64]
    loop = ReactLoop(LOOP, CASE, RUN, ReactLoopStatus.RUNNING, 0, budget(), values, NOW, NOW)
    values.append("b" * 64)
    assert loop.observation_fingerprints == ("a" * 64,)
    with pytest.raises(ValueError, match="predate"):
        ReactLoop(
            LOOP,
            CASE,
            RUN,
            ReactLoopStatus.RUNNING,
            0,
            budget(),
            (),
            NOW,
            NOW - timedelta(seconds=1),
        )


def test_replan_decision_must_bind_exactly_one_revision() -> None:
    seen = observation()
    classified = assessment(seen.id)
    with pytest.raises(ValueError, match="revision"):
        ReactStepDecision(
            uuid4(),
            LOOP,
            seen.id,
            classified.id,
            ReactDecision.REPLAN,
            "safe_replan",
            budget(),
            NOW,
        )
    with pytest.raises(ValueError, match="revision"):
        ReactStepDecision(
            uuid4(),
            LOOP,
            seen.id,
            classified.id,
            ReactDecision.MANUAL_REVIEW,
            "operator_required",
            budget(),
            NOW,
            uuid4(),
        )


def test_public_serialization_is_json_safe_and_has_no_private_fields() -> None:
    seen = observation()
    classified = assessment(seen.id)
    revision = PlanRevision(
        uuid4(), LOOP, CASE, RUN, 0, None, (), (), (action(),), classified.category, NOW
    )
    decision = ReactStepDecision(
        uuid4(),
        LOOP,
        seen.id,
        classified.id,
        ReactDecision.REPLAN,
        "safe_replan",
        budget(),
        NOW,
        revision.id,
    )
    payload = json.dumps(
        {
            "observation": seen.to_dict(),
            "assessment": classified.to_dict(),
            "revision": revision.to_dict(),
            "decision": decision.to_dict(),
        },
        allow_nan=False,
    )
    for forbidden in (
        "tenant",
        "principal",
        "raw_prompt",
        "chain_of_thought",
        "result_summary",
        "token_digest",
        "secret",
    ):
        assert forbidden not in payload.lower()


def test_domain_objects_are_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        observation().status = "changed"
