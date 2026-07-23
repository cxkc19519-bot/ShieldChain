from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyOutcome,
    PolicyReason,
    ToolTargetType,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.gateway import AdapterExecution, TrustedToolGateway
from shieldchain.tools.policy import ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import BoundToolRequest, default_tool_registry

NOW = datetime(2026, 7, 23, 10, tzinfo=UTC)
TENANT, PRINCIPAL, APPROVER, CASE, RUN, PLAN, CALL, EVIDENCE = (
    UUID(int=value) for value in range(1401, 1409)
)
REF = EvidenceReference(EVIDENCE, CASE, "siem:gateway", NOW, "f" * 64)


def bound(tool: str = "block_ip") -> BoundToolRequest:
    query = tool == "query_firewall_state"
    return default_tool_registry().bind(
        TrustedToolRequest(
            CALL,
            CASE,
            RUN,
            PLAN,
            "phase5:gateway:1401",
            AgentRole.RESPONSE_PLANNING,
            tool,
            "1",
            {"target_ip": "203.0.113.8"}
            if query
            else {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
            {"firewall_status": "blocked"},
            "Reverse exact scoped rule.",
            (REF,),
            NOW,
        )
    )


def context(**changes: object) -> ToolPolicyContext:
    values = {
        "tenant_id": TENANT,
        "principal_id": PRINCIPAL,
        "case_id": CASE,
        "run_id": RUN,
        "role": AgentRole.RESPONSE_PLANNING,
        "mode": ToolExecutionMode.SIMULATION,
        "automation_enabled": True,
        "emergency_stop_active": False,
        "allowed_tools": frozenset(
            item.definition.identity for item in default_tool_registry().registrations
        ),
        "allowed_targets": {ToolTargetType.IPV4: frozenset({"203.0.113.8"})},
        "confirmed_evidence_ids": frozenset({EVIDENCE}),
        "tool_calls_used": 0,
        "tool_call_limit": 5,
        "calls_in_window": 0,
        "rate_limit": 3,
        "simulation_auto_approve_critical": False,
        "now": NOW,
    }
    values.update(changes)
    return ToolPolicyContext(**values)  # type: ignore[arg-type]


class Store:
    def __init__(self) -> None:
        self.call: TrustedToolCall | None = None
        self.approval: ApprovalDecision | None = None
        self.policies = []
        self.attempts = []
        self.verifications = []
        self.atomic_sections = 0

    @contextmanager
    def atomic(self):
        self.atomic_sections += 1
        yield

    def create_or_get(self, *, tenant_id, bound, request_id):
        if self.call is not None:
            return self.call, False
        self.call = TrustedToolCall(bound.request, TrustedToolCallStatus.PROPOSED, 0, None, NOW)
        return self.call, True

    def append_policy(self, *, tenant_id, decision):
        self.policies.append(decision)

    def transition(self, *, tenant_id, current, target, now, request_id, reason=None):
        self.call = current.transition(target, now=now, reason=reason)
        return self.call

    def append_attempt(self, *, tenant_id, attempt):
        self.attempts.append(attempt)

    def append_verification(self, *, tenant_id, verification):
        self.verifications.append(verification)

    def latest(self, *, tenant_id, request_id):
        return self.approval

    def append(self, *, tenant_id, decision):
        self.approval = decision


class Adapter:
    def __init__(
        self,
        execution: AdapterExecution | Exception | object | None = None,
        verification: VerificationOutcome | Exception = VerificationOutcome.VERIFIED,
    ) -> None:
        self.execution = execution or AdapterExecution(ExecutionOutcome.SUCCEEDED, "Rule applied.")
        self.verification = verification
        self.executed: list[BoundToolRequest] = []
        self.verified = 0

    def execute(self, request):
        self.executed.append(request)
        if isinstance(self.execution, Exception):
            raise self.execution
        return self.execution

    def verify(self, request, execution, *, now):
        self.verified += 1
        if isinstance(self.verification, Exception):
            raise self.verification
        return ToolVerification(
            uuid4(),
            request.request.id,
            self.verification,
            {"firewall_status": "blocked"},
            request.request.evidence,
            None
            if self.verification is VerificationOutcome.VERIFIED
            else PolicyReason.VERIFICATION_FAILED,
            now,
        )


def submit(store: Store, adapter: Adapter, *, tool="block_ip", **context_changes):
    return TrustedToolGateway().submit(
        bound=bound(tool),
        context=context(**context_changes),
        store=store,
        adapter=adapter,
        request_id="req-gateway-1401",
    )


def test_fixed_pipeline_auto_approves_executes_and_verifies() -> None:
    store, adapter = Store(), Adapter()
    result = submit(store, adapter)
    assert result.call.status is TrustedToolCallStatus.SUCCEEDED
    assert result.approval is store.approval
    assert result.approval is not None
    assert result.policy and result.policy.reason is PolicyReason.AUTOMATIC_SIMULATION_APPROVAL
    assert adapter.executed == [bound()]
    assert len(store.attempts) == len(store.verifications) == 1
    assert store.atomic_sections == 4


def test_denied_and_approval_required_calls_do_not_reach_adapter() -> None:
    denied_store, denied_adapter = Store(), Adapter()
    denied = submit(denied_store, denied_adapter, automation_enabled=False)
    assert denied.call.status is TrustedToolCallStatus.REJECTED
    assert denied_adapter.executed == []

    waiting_store, waiting_adapter = Store(), Adapter()
    waiting = submit(waiting_store, waiting_adapter, mode=ToolExecutionMode.REAL)
    assert waiting.call.status is TrustedToolCallStatus.AWAITING_APPROVAL
    assert waiting.policy and waiting.policy.outcome is PolicyOutcome.APPROVAL_REQUIRED
    assert waiting_adapter.executed == []


def test_valid_human_approval_resumes_exact_bound_request() -> None:
    store, adapter = Store(), Adapter()
    waiting = submit(store, adapter, mode=ToolExecutionMode.REAL)
    policy = waiting.policy
    assert policy is not None
    approval = ApprovalDecision(
        uuid4(),
        CALL,
        bound().request_digest,
        ApprovalOutcome.APPROVED,
        APPROVER,
        policy.policy_version,
        "Approved exact request.",
        NOW,
        NOW + timedelta(minutes=4),
    )
    store.approval = approval
    resumed = TrustedToolGateway().execute_after_approval(
        bound=bound(),
        call=waiting.call,
        policy=policy,
        approval=approval,
        context=context(mode=ToolExecutionMode.REAL),
        store=store,
        adapter=adapter,
        request_id="req-gateway-resume",
    )
    assert resumed.call.status is TrustedToolCallStatus.SUCCEEDED
    assert adapter.executed == [bound()]


@pytest.mark.parametrize(
    ("execution", "status", "category"),
    [
        (TimeoutError("private timeout detail"), TrustedToolCallStatus.NEEDS_REVIEW, "timeout"),
        (RuntimeError("private token=secret"), TrustedToolCallStatus.FAILED, "adapter_failure"),
        (
            AdapterExecution(ExecutionOutcome.FAILED, "bad\x00\nsummary", "INVALID VALUE"),
            TrustedToolCallStatus.FAILED,
            "tool_failure",
        ),
    ],
)
def test_adapter_failures_are_sanitized_and_never_claim_success(
    execution, status, category
) -> None:
    store = Store()
    result = submit(store, Adapter(execution))
    assert result.call.status is status
    assert result.attempt and result.attempt.error_category == category
    assert "secret" not in result.attempt.result_summary
    assert "\x00" not in result.attempt.result_summary
    assert result.verification is None


@pytest.mark.parametrize(
    ("verification", "status"),
    [
        (VerificationOutcome.FAILED, TrustedToolCallStatus.FAILED),
        (VerificationOutcome.INCONCLUSIVE, TrustedToolCallStatus.NEEDS_REVIEW),
        (RuntimeError("private verifier failure"), TrustedToolCallStatus.NEEDS_REVIEW),
    ],
)
def test_verification_must_confirm_success(verification, status) -> None:
    result = submit(Store(), Adapter(verification=verification))
    assert result.call.status is status
    assert result.verification is not None


def test_duplicate_submission_returns_existing_call_without_policy_or_execution() -> None:
    store, adapter = Store(), Adapter()
    first = submit(store, adapter, tool="query_firewall_state")
    duplicate = submit(store, adapter, tool="query_firewall_state")
    assert first.call.status is TrustedToolCallStatus.SUCCEEDED
    assert duplicate.created is False
    assert duplicate.call.status is TrustedToolCallStatus.SUCCEEDED
    assert len(adapter.executed) == 1
    assert len(store.policies) == 1


def test_invalid_or_expired_approval_cannot_resume_execution() -> None:
    store, adapter = Store(), Adapter()
    waiting = submit(store, adapter, mode=ToolExecutionMode.REAL)
    assert waiting.policy is not None
    invalid = ApprovalDecision(
        uuid4(),
        CALL,
        "0" * 64,
        ApprovalOutcome.APPROVED,
        APPROVER,
        waiting.policy.policy_version,
        "Wrong digest.",
        NOW,
        NOW + timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="invalid or expired"):
        TrustedToolGateway().execute_after_approval(
            bound=bound(),
            call=waiting.call,
            policy=waiting.policy,
            approval=invalid,
            context=context(mode=ToolExecutionMode.REAL),
            store=store,
            adapter=adapter,
            request_id="req-invalid-approval",
        )
    assert adapter.executed == []
