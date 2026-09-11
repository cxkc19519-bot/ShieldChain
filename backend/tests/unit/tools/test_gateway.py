from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event
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
from shieldchain.tools.execution import ExecutionLeaseGrant, ToolExecutionLease
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


def bound_with_timeout(tool: str, timeout_seconds: float) -> BoundToolRequest:
    current = bound(tool)
    return replace(
        current,
        registration=replace(
            current.registration,
            definition=replace(
                current.registration.definition,
                timeout_seconds=timeout_seconds,
            ),
        ),
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
        self.commits = 0
        self.released_leases = []

    @contextmanager
    def atomic(self):
        self.atomic_sections += 1
        yield

    def commit(self):
        self.commits += 1

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

    def acquire_lease(self, *, tenant_id, call, holder_id, now, duration, request_id):
        token = "l" * 43
        lease = ToolExecutionLease(
            uuid4(),
            call.request.id,
            holder_id,
            len(self.attempts) + 1,
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            now,
            now + duration,
        )
        return ExecutionLeaseGrant(lease, token)

    def release_lease(self, *, tenant_id, call, grant, now, reason, request_id):
        released = ToolExecutionLease(
            grant.lease.id,
            grant.lease.request_id,
            grant.lease.holder_id,
            grant.lease.attempt_number,
            grant.lease.token_digest,
            grant.lease.acquired_at,
            grant.lease.expires_at,
            now,
            reason,
        )
        self.released_leases.append(released)
        return released

    def next_attempt_number(self, *, tenant_id, request_id):
        return len(self.attempts) + 1

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
        execution: AdapterExecution | Exception | object | list[object] | None = None,
        verification: VerificationOutcome | Exception = VerificationOutcome.VERIFIED,
    ) -> None:
        self.execution = execution or AdapterExecution(ExecutionOutcome.SUCCEEDED, "Rule applied.")
        self.verification = verification
        self.executed: list[BoundToolRequest] = []
        self.verified = 0

    def execute(self, request):
        self.executed.append(request)
        result = self.execution.pop(0) if isinstance(self.execution, list) else self.execution
        if isinstance(result, Exception):
            raise result
        return result

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


class BlockingExecutionAdapter(Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.release = Event()
        self.completed = Event()

    def execute(self, request):
        self.executed.append(request)
        self.release.wait(timeout=1)
        self.completed.set()
        return self.execution


class BlockingVerificationAdapter(Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.release = Event()
        self.completed = Event()

    def verify(self, request, execution, *, now):
        self.release.wait(timeout=1)
        self.completed.set()
        return super().verify(request, execution, now=now)


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
    assert store.commits == 3


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


def test_read_only_failure_retries_only_to_registered_limit() -> None:
    transient = Adapter(
        [
            AdapterExecution(ExecutionOutcome.FAILED, "Temporary failure", "temporary"),
            AdapterExecution(ExecutionOutcome.SUCCEEDED, "Query completed"),
        ]
    )
    store = Store()
    result = submit(store, transient, tool="query_firewall_state")
    assert result.call.status is TrustedToolCallStatus.SUCCEEDED
    assert len(store.attempts) == len(transient.executed) == 2
    assert [item.attempt_number for item in store.attempts] == [1, 2]
    assert len(store.released_leases) == 1

    exhausted_store, exhausted = Store(), Adapter(RuntimeError("offline"))
    failed = submit(exhausted_store, exhausted, tool="query_firewall_state")
    assert failed.call.status is TrustedToolCallStatus.FAILED
    assert len(exhausted_store.attempts) == len(exhausted.executed) == 3


def test_timeout_is_unknown_and_is_never_retried_even_for_read_only_tool() -> None:
    store, adapter = Store(), Adapter(TimeoutError("unknown outcome"))
    result = submit(store, adapter, tool="query_firewall_state")
    assert result.call.status is TrustedToolCallStatus.NEEDS_REVIEW
    assert len(adapter.executed) == len(store.attempts) == 1
    assert store.released_leases[0].release_reason == "outcome_unknown"


def test_gateway_enforces_adapter_execution_deadline_without_replay() -> None:
    store = Store()
    adapter = BlockingExecutionAdapter()

    result = TrustedToolGateway().submit(
        bound=bound_with_timeout("block_ip", 0.05),
        context=context(),
        store=store,
        adapter=adapter,
        request_id="req-gateway-deadline",
    )

    assert result.call.status is TrustedToolCallStatus.NEEDS_REVIEW
    assert result.attempt is not None
    assert result.attempt.outcome is ExecutionOutcome.UNKNOWN
    assert result.attempt.error_category == "timeout"
    assert adapter.completed.is_set() is False
    assert len(adapter.executed) == 1
    adapter.release.set()


def test_gateway_enforces_verification_deadline_as_inconclusive() -> None:
    store = Store()
    adapter = BlockingVerificationAdapter()

    result = TrustedToolGateway().submit(
        bound=bound_with_timeout("block_ip", 0.05),
        context=context(),
        store=store,
        adapter=adapter,
        request_id="req-verification-deadline",
    )

    assert result.call.status is TrustedToolCallStatus.NEEDS_REVIEW
    assert result.verification is not None
    assert result.verification.outcome is VerificationOutcome.INCONCLUSIVE
    assert adapter.completed.is_set() is False
    adapter.release.set()


def test_state_changing_failure_is_never_blindly_retried() -> None:
    store, adapter = Store(), Adapter(RuntimeError("device unavailable"))
    result = submit(store, adapter, tool="block_ip")
    assert result.call.status is TrustedToolCallStatus.FAILED
    assert len(adapter.executed) == len(store.attempts) == 1
