from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.agents.roles import RoleExecutionResult, RoleExecutionStatus
from shieldchain.react.classification import DeterministicFailureClassifier, TrustedFailureInput
from shieldchain.react.domain import (
    FailureCategory,
    ObservationSource,
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
    TrustedToolRequest,
    VerificationOutcome,
)

NOW = datetime(2026, 7, 23, 16, tzinfo=UTC)
CASE, RUN, LOOP, CALL = (UUID(int=value) for value in range(6201, 6205))


def reference(case_id=CASE):
    return EvidenceReference(uuid4(), case_id, "siem:classification", NOW, "a" * 64)


def call(status=TrustedToolCallStatus.FAILED, reason=PolicyReason.EXECUTION_FAILED):
    request = TrustedToolRequest(
        CALL,
        CASE,
        RUN,
        uuid4(),
        "phase6:classification",
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Remove exact rule.",
        (reference(),),
        NOW,
    )
    return TrustedToolCall(request, status, 3, reason, NOW)


def observation(**changes):
    values = dict(
        id=uuid4(),
        loop_id=LOOP,
        case_id=CASE,
        run_id=RUN,
        iteration=1,
        source=ObservationSource.TOOL_CALL,
        status="failed",
        reason_code="execution_failed",
        references=(reference(),),
        observed_at=NOW,
        tool_call_id=CALL,
    )
    return ReactObservation(**(values | changes))


def attempt(outcome):
    return ToolExecutionAttempt(
        uuid4(),
        CALL,
        1,
        outcome,
        "Safe summary",
        None if outcome is ExecutionOutcome.SUCCEEDED else "tool_failure",
        NOW,
        NOW,
    )


def verification(outcome):
    return ToolVerification(
        uuid4(),
        CALL,
        outcome,
        {"firewall_status": "not_blocked"},
        (reference(),),
        None if outcome is VerificationOutcome.VERIFIED else PolicyReason.VERIFICATION_FAILED,
        NOW,
    )


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"loop_detected": True}, FailureCategory.LOOP_DETECTED),
        ({"budget_exhausted": True}, FailureCategory.BUDGET_EXHAUSTED),
        ({"emergency_stop_active": True}, FailureCategory.EMERGENCY_STOPPED),
        ({"automation_enabled": False}, FailureCategory.AUTOMATION_DISABLED),
        ({"evidence_conflict": True}, FailureCategory.EVIDENCE_CONFLICT),
    ],
)
def test_supervisor_conditions_have_fail_closed_precedence(values, expected) -> None:
    result = DeterministicFailureClassifier().classify(
        TrustedFailureInput(observation(), **values), now=NOW
    )
    assert result.category is expected and result.recoverable is False


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (VerificationOutcome.FAILED, FailureCategory.VERIFICATION_FAILED),
        (VerificationOutcome.INCONCLUSIVE, FailureCategory.VERIFICATION_INCONCLUSIVE),
    ],
)
def test_verification_outcomes_are_classified_without_observed_payload(outcome, expected) -> None:
    checked = verification(outcome)
    seen = observation(source=ObservationSource.TOOL_VERIFICATION, verification_id=checked.id)
    result = DeterministicFailureClassifier().classify(
        TrustedFailureInput(seen, call=call(), verification=checked), now=NOW
    )
    assert result.category is expected


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (ExecutionOutcome.FAILED, FailureCategory.EXECUTION_FAILED),
        (ExecutionOutcome.UNKNOWN, FailureCategory.EXECUTION_OUTCOME_UNKNOWN),
    ],
)
def test_attempt_outcomes_use_enums_not_error_text(outcome, expected) -> None:
    result = DeterministicFailureClassifier().classify(
        TrustedFailureInput(observation(), call=call(), attempt=attempt(outcome)), now=NOW
    )
    assert result.category is expected


def test_rejected_emergency_and_reason_bound_calls_are_fixed() -> None:
    classifier = DeterministicFailureClassifier()
    rejected = classifier.classify(
        TrustedFailureInput(
            observation(), call=call(TrustedToolCallStatus.REJECTED, PolicyReason.APPROVAL_REJECTED)
        ),
        now=NOW,
    )
    stopped = classifier.classify(
        TrustedFailureInput(
            observation(), call=call(TrustedToolCallStatus.EMERGENCY_STOPPED, None)
        ),
        now=NOW,
    )
    assert rejected.category is FailureCategory.APPROVAL_REJECTED
    assert stopped.category is FailureCategory.EMERGENCY_STOPPED


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (RoleExecutionStatus.DEPENDENCY_UNAVAILABLE, FailureCategory.DEPENDENCY_UNAVAILABLE),
        (RoleExecutionStatus.TIMED_OUT, FailureCategory.DEPENDENCY_UNAVAILABLE),
        (RoleExecutionStatus.REFUSED, FailureCategory.EVIDENCE_INSUFFICIENT),
        (RoleExecutionStatus.INVALID_OUTPUT, FailureCategory.UNCLASSIFIED_FAILURE),
    ],
)
def test_role_terminal_states_have_closed_mapping(status, expected) -> None:
    role = RoleExecutionResult(status, None, "ignored_free_text")
    result = DeterministicFailureClassifier().classify(
        TrustedFailureInput(
            observation(source=ObservationSource.ROLE, tool_call_id=None), role_result=role
        ),
        now=NOW,
    )
    assert result.category is expected


def test_unknown_combinations_default_to_manual_review() -> None:
    classifier = DeterministicFailureClassifier()
    result = classifier.classify(TrustedFailureInput(observation()), now=NOW)
    assert result.category is FailureCategory.UNCLASSIFIED_FAILURE
    assert result.confidence == 0.5
    assert classifier.allowed_decisions(result.category) == frozenset({ReactDecision.MANUAL_REVIEW})


def test_unknown_mutating_outcome_only_allows_status_query_or_human() -> None:
    allowed = DeterministicFailureClassifier.allowed_decisions(
        FailureCategory.EXECUTION_OUTCOME_UNKNOWN
    )
    assert allowed == frozenset({ReactDecision.QUERY_STATUS, ReactDecision.MANUAL_REVIEW})
    assert ReactDecision.REPLAN not in allowed and ReactDecision.RETRY_READ_ONLY not in allowed


def test_all_categories_have_an_explicit_nonempty_decision_set() -> None:
    classifier = DeterministicFailureClassifier()
    assert all(classifier.allowed_decisions(category) for category in FailureCategory)


def test_cross_boundary_objects_are_rejected() -> None:
    with pytest.raises(ValueError, match="boundary"):
        TrustedFailureInput(observation(run_id=uuid4()), call=call())
    with pytest.raises(ValueError, match="another tool call"):
        TrustedFailureInput(
            observation(),
            call=call(),
            attempt=ToolExecutionAttempt(
                uuid4(), uuid4(), 1, ExecutionOutcome.FAILED, "safe", "failure", NOW, NOW
            ),
        )


def test_classification_id_is_deterministic_and_no_raw_text_is_copied() -> None:
    value = TrustedFailureInput(
        observation(), call=call(), attempt=attempt(ExecutionOutcome.FAILED)
    )
    first = DeterministicFailureClassifier().classify(value, now=NOW)
    second = DeterministicFailureClassifier().classify(value, now=NOW)
    assert first == second
    assert first.reason_code == "classified_execution_failed"
    assert "Safe summary" not in str(first.to_dict())
