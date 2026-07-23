from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolDefinition,
    ToolExecutionAttempt,
    ToolRisk,
    ToolTargetType,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)

NOW = datetime(2026, 7, 23, 5, tzinfo=UTC)
CASE = UUID(int=901)
RUN = UUID(int=902)
PLAN = UUID(int=903)
EVIDENCE = EvidenceReference(UUID(int=904), CASE, "siem:1", NOW, "a" * 64)


def request(**changes: object) -> TrustedToolRequest:
    values = dict(
        id=UUID(int=905),
        case_id=CASE,
        run_id=RUN,
        plan_id=PLAN,
        idempotency_key="phase5:block:0001",
        caller_role=AgentRole.RESPONSE_PLANNING,
        tool_name="block_ip",
        tool_version="1",
        arguments={"target_ip": "203.0.113.8"},
        expected_state={"firewall_status": "blocked"},
        rollback_strategy="Remove the exact scoped rule after review.",
        evidence=(EVIDENCE,),
        created_at=NOW,
    )
    values.update(changes)
    return TrustedToolRequest(**values)


def definition(**changes: object) -> ToolDefinition:
    values = dict(
        name="block_ip",
        version="1",
        target_type=ToolTargetType.IPV4,
        risk=ToolRisk.HIGH,
        allowed_roles=frozenset({AgentRole.RESPONSE_PLANNING}),
        timeout_seconds=2.0,
        max_retries=0,
        mutates_state=True,
        verifier_name="query_firewall_state",
    )
    values.update(changes)
    return ToolDefinition(**values)


def test_definition_is_frozen_and_defensively_freezes_roles() -> None:
    roles = {AgentRole.RESPONSE_PLANNING}
    value = definition(allowed_roles=roles)
    roles.add(AgentRole.SUPERAGENT)
    assert value.allowed_roles == frozenset({AgentRole.RESPONSE_PLANNING})
    with pytest.raises(FrozenInstanceError):
        value.name = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"name": "Block IP"}, "name"),
        ({"version": "latest"}, "version"),
        ({"timeout_seconds": 31}, "timeout"),
        ({"max_retries": 4}, "retries"),
        ({"verifier_name": None}, "verifier"),
        ({"risk": ToolRisk.HIGH, "max_retries": 1}, "blindly"),
        ({"risk": ToolRisk.READ_ONLY, "mutates_state": True}, "read-only"),
    ],
)
def test_definition_rejects_unsafe_metadata(changes, message) -> None:
    with pytest.raises(ValueError, match=message):
        definition(**changes)


def test_request_freezes_structured_arguments_and_has_stable_digest() -> None:
    arguments = {"target_ip": "203.0.113.8", "rule_ttl": 60}
    first = request(arguments=arguments)
    arguments["target_ip"] = "198.51.100.4"
    second = request(arguments={"rule_ttl": 60, "target_ip": "203.0.113.8"})
    assert isinstance(first.arguments, MappingProxyType)
    assert first.arguments["target_ip"] == "203.0.113.8"
    assert first.request_digest == second.request_digest
    assert len(first.request_digest) == 64


@pytest.mark.parametrize(
    "key",
    (
        "tenant_id",
        "principal_id",
        "api_key",
        "password",
        "raw_prompt",
        "chain_of_thought",
        "shell",
        "command",
        "code",
        "url",
    ),
)
def test_request_rejects_authority_secret_prompt_and_execution_fields(key: str) -> None:
    with pytest.raises(ValueError, match="forbidden"):
        request(arguments={key: "hidden"})


def test_request_rejects_cross_case_or_missing_evidence_and_non_utc() -> None:
    other = EvidenceReference(uuid4(), uuid4(), "siem:2", NOW, "b" * 64)
    with pytest.raises(ValueError, match="same case"):
        request(evidence=(other,))
    with pytest.raises(ValueError, match="evidence"):
        request(evidence=())
    with pytest.raises(ValueError, match="UTC"):
        request(created_at=NOW.replace(tzinfo=None))


def test_request_digest_changes_with_bound_plan_tool_arguments_or_evidence() -> None:
    baseline = request().request_digest
    assert request(plan_id=uuid4()).request_digest != baseline
    assert request(tool_name="isolate_endpoint").request_digest != baseline
    assert request(arguments={"target_ip": "203.0.113.9"}).request_digest != baseline
    other = EvidenceReference(uuid4(), CASE, "siem:2", NOW, "b" * 64)
    assert request(evidence=(other,)).request_digest != baseline


def test_policy_and_approval_require_expiry_and_digest_binding() -> None:
    policy = PolicyDecision(
        request().id,
        PolicyOutcome.APPROVAL_REQUIRED,
        PolicyReason.APPROVAL_REQUIRED,
        "policy-v1",
        ToolRisk.HIGH,
        NOW,
        NOW + timedelta(minutes=5),
    )
    approval = ApprovalDecision(
        uuid4(),
        policy.request_id,
        request().request_digest,
        ApprovalOutcome.APPROVED,
        uuid4(),
        policy.policy_version,
        "Approved for the fixed simulation target.",
        NOW,
        NOW + timedelta(minutes=2),
    )
    assert approval.request_digest == request().request_digest
    with pytest.raises(ValueError, match="expire"):
        PolicyDecision(
            request().id,
            PolicyOutcome.DENY,
            PolicyReason.TOOL_NOT_ALLOWED,
            "policy-v1",
            ToolRisk.HIGH,
            NOW,
            NOW,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        ApprovalDecision(
            uuid4(),
            request().id,
            "bad",
            ApprovalOutcome.REJECTED,
            uuid4(),
            "policy-v1",
            "Denied",
            NOW,
            NOW + timedelta(minutes=1),
        )


def test_execution_attempt_cannot_claim_success_with_error() -> None:
    with pytest.raises(ValueError, match="successful"):
        ToolExecutionAttempt(
            uuid4(), request().id, 1, ExecutionOutcome.SUCCEEDED, "blocked", "timeout", NOW, NOW
        )
    unknown = ToolExecutionAttempt(
        uuid4(),
        request().id,
        1,
        ExecutionOutcome.UNKNOWN,
        "Adapter timed out; outcome is unknown.",
        "timeout",
        NOW,
        NOW,
    )
    assert unknown.outcome is ExecutionOutcome.UNKNOWN


def test_verification_keeps_observed_state_and_trusted_references_separate() -> None:
    value = ToolVerification(
        uuid4(),
        request().id,
        VerificationOutcome.VERIFIED,
        {"firewall_status": "blocked"},
        (EVIDENCE,),
        None,
        NOW,
    )
    assert value.observed_state["firewall_status"] == "blocked"
    assert value.evidence == (EVIDENCE,)
    with pytest.raises(ValueError, match="failure reason"):
        ToolVerification(
            uuid4(),
            request().id,
            VerificationOutcome.VERIFIED,
            {"firewall_status": "blocked"},
            (),
            PolicyReason.VERIFICATION_FAILED,
            NOW,
        )


def test_state_machine_allows_only_whitelisted_forward_transitions() -> None:
    value = TrustedToolCall(request(), TrustedToolCallStatus.PROPOSED, 0, None, NOW)
    checked = value.transition(TrustedToolCallStatus.POLICY_CHECKED, now=NOW)
    waiting = checked.transition(
        TrustedToolCallStatus.AWAITING_APPROVAL,
        now=NOW,
        reason=PolicyReason.APPROVAL_REQUIRED,
    )
    approved = waiting.transition(TrustedToolCallStatus.APPROVED, now=NOW)
    executing = approved.transition(TrustedToolCallStatus.EXECUTING, now=NOW)
    verifying = executing.transition(TrustedToolCallStatus.VERIFYING, now=NOW)
    succeeded = verifying.transition(TrustedToolCallStatus.SUCCEEDED, now=NOW)
    assert succeeded.revision == 6
    with pytest.raises(ValueError, match="not allowed"):
        value.transition(TrustedToolCallStatus.EXECUTING, now=NOW)
    with pytest.raises(ValueError, match="not allowed"):
        succeeded.transition(TrustedToolCallStatus.PROPOSED, now=NOW)


def test_executing_call_cannot_pretend_emergency_stop_retracted_issued_action() -> None:
    value = TrustedToolCall(request(), TrustedToolCallStatus.EXECUTING, 4, None, NOW)
    with pytest.raises(ValueError, match="not allowed"):
        value.transition(TrustedToolCallStatus.EMERGENCY_STOPPED, now=NOW)
    review = value.transition(
        TrustedToolCallStatus.NEEDS_REVIEW,
        now=NOW,
        reason=PolicyReason.EXECUTION_OUTCOME_UNKNOWN,
    )
    assert review.status is TrustedToolCallStatus.NEEDS_REVIEW
