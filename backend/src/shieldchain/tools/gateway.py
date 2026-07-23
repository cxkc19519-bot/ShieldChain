"""Fixed trusted-tool gateway pipeline; adapters never receive model context."""

from __future__ import annotations

import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

from shieldchain.tools.approvals import TrustedToolApprovalService
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    VerificationOutcome,
)
from shieldchain.tools.policy import DeterministicToolPolicy, ToolPolicyContext
from shieldchain.tools.registry import BoundToolRequest

_ERROR_CATEGORY = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


@dataclass(frozen=True, slots=True)
class AdapterExecution:
    outcome: ExecutionOutcome
    result_summary: str
    error_category: str | None = None


class TrustedToolAdapter(Protocol):
    def execute(self, request: BoundToolRequest) -> AdapterExecution: ...

    def verify(
        self, request: BoundToolRequest, execution: AdapterExecution, *, now: datetime
    ) -> ToolVerification: ...


class GatewayStore(Protocol):
    def atomic(self) -> AbstractContextManager[None]: ...

    def create_or_get(
        self, *, tenant_id: UUID, bound: BoundToolRequest, request_id: str
    ) -> tuple[TrustedToolCall, bool]: ...

    def append_policy(self, *, tenant_id: UUID, decision: PolicyDecision) -> None: ...

    def transition(
        self,
        *,
        tenant_id: UUID,
        current: TrustedToolCall,
        target: TrustedToolCallStatus,
        now: datetime,
        request_id: str,
        reason: PolicyReason | None = None,
    ) -> TrustedToolCall: ...

    def append_attempt(self, *, tenant_id: UUID, attempt: ToolExecutionAttempt) -> None: ...

    def append_verification(self, *, tenant_id: UUID, verification: ToolVerification) -> None: ...

    def latest(self, *, tenant_id: UUID, request_id: UUID) -> ApprovalDecision | None: ...

    def append(self, *, tenant_id: UUID, decision: ApprovalDecision) -> None: ...


@dataclass(frozen=True, slots=True)
class GatewayResult:
    call: TrustedToolCall
    created: bool
    policy: PolicyDecision | None = None
    approval: ApprovalDecision | None = None
    attempt: ToolExecutionAttempt | None = None
    verification: ToolVerification | None = None


class TrustedToolGateway:
    def __init__(
        self,
        *,
        policy: DeterministicToolPolicy | None = None,
        approvals: TrustedToolApprovalService | None = None,
    ) -> None:
        self._policy = policy or DeterministicToolPolicy()
        self._approvals = approvals or TrustedToolApprovalService()

    def submit(
        self,
        *,
        bound: BoundToolRequest,
        context: ToolPolicyContext,
        store: GatewayStore,
        adapter: TrustedToolAdapter,
        request_id: str,
    ) -> GatewayResult:
        call, created = store.create_or_get(
            tenant_id=context.tenant_id, bound=bound, request_id=request_id
        )
        if not created:
            return GatewayResult(call, False)
        policy = self._policy.evaluate(bound, context)
        approval = None
        with store.atomic():
            store.append_policy(tenant_id=context.tenant_id, decision=policy)
            call = store.transition(
                tenant_id=context.tenant_id,
                current=call,
                target=TrustedToolCallStatus.POLICY_CHECKED,
                now=context.now,
                request_id=request_id,
                reason=policy.reason,
            )
            if policy.outcome is PolicyOutcome.DENY:
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.REJECTED,
                    now=context.now,
                    request_id=request_id,
                    reason=policy.reason,
                )
            elif policy.outcome is PolicyOutcome.APPROVAL_REQUIRED:
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.AWAITING_APPROVAL,
                    now=context.now,
                    request_id=request_id,
                    reason=policy.reason,
                )
            else:
                if policy.reason is PolicyReason.AUTOMATIC_SIMULATION_APPROVAL:
                    approval = self._approvals.record_automatic(
                        tenant_id=context.tenant_id,
                        call=call,
                        policy=policy,
                        store=store,
                    )
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.APPROVED,
                    now=context.now,
                    request_id=request_id,
                    reason=policy.reason,
                )
        if policy.outcome in {PolicyOutcome.DENY, PolicyOutcome.APPROVAL_REQUIRED}:
            return GatewayResult(call, True, policy)
        return self._execute(
            bound=bound,
            call=call,
            created=True,
            policy=policy,
            approval=approval,
            context=context,
            store=store,
            adapter=adapter,
            request_id=request_id,
        )

    def execute_after_approval(
        self,
        *,
        bound: BoundToolRequest,
        call: TrustedToolCall,
        policy: PolicyDecision,
        approval: ApprovalDecision,
        context: ToolPolicyContext,
        store: GatewayStore,
        adapter: TrustedToolAdapter,
        request_id: str,
    ) -> GatewayResult:
        if call.status is not TrustedToolCallStatus.AWAITING_APPROVAL:
            raise ValueError("tool call is not awaiting approval")
        latest = store.latest(tenant_id=context.tenant_id, request_id=call.request.id)
        if (
            bound.request.id != call.request.id
            or bound.request_digest != call.request.request_digest
            or context.case_id != call.request.case_id
            or context.run_id != call.request.run_id
            or policy.request_id != call.request.id
            or policy.outcome is not PolicyOutcome.APPROVAL_REQUIRED
            or approval.request_id != call.request.id
            or approval.request_digest != call.request.request_digest
            or approval.outcome is not ApprovalOutcome.APPROVED
            or approval.policy_version != policy.policy_version
            or latest != approval
            or approval.expires_at <= context.now
            or policy.expires_at <= context.now
        ):
            raise ValueError("approval is invalid or expired")
        with store.atomic():
            call = store.transition(
                tenant_id=context.tenant_id,
                current=call,
                target=TrustedToolCallStatus.APPROVED,
                now=context.now,
                request_id=request_id,
            )
        return self._execute(
            bound=bound,
            call=call,
            created=False,
            policy=policy,
            approval=approval,
            context=context,
            store=store,
            adapter=adapter,
            request_id=request_id,
        )

    def _execute(
        self,
        *,
        bound: BoundToolRequest,
        call: TrustedToolCall,
        created: bool,
        policy: PolicyDecision,
        approval: ApprovalDecision | None,
        context: ToolPolicyContext,
        store: GatewayStore,
        adapter: TrustedToolAdapter,
        request_id: str,
    ) -> GatewayResult:
        with store.atomic():
            call = store.transition(
                tenant_id=context.tenant_id,
                current=call,
                target=TrustedToolCallStatus.EXECUTING,
                now=context.now,
                request_id=request_id,
            )
        try:
            raw_execution = adapter.execute(bound)
            if not isinstance(raw_execution, AdapterExecution):
                raise TypeError("adapter returned an invalid execution result")
            execution = _sanitize_execution(raw_execution)
        except TimeoutError:
            execution = AdapterExecution(
                ExecutionOutcome.UNKNOWN,
                "Adapter timed out; execution outcome is unknown.",
                "timeout",
            )
        except Exception:
            execution = AdapterExecution(
                ExecutionOutcome.FAILED,
                "Adapter failed without a trusted result.",
                "adapter_failure",
            )
        attempt = ToolExecutionAttempt(
            uuid4(),
            call.request.id,
            1,
            execution.outcome,
            execution.result_summary,
            execution.error_category,
            context.now,
            context.now,
        )
        with store.atomic():
            store.append_attempt(tenant_id=context.tenant_id, attempt=attempt)
            if execution.outcome is ExecutionOutcome.UNKNOWN:
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.NEEDS_REVIEW,
                    now=context.now,
                    request_id=request_id,
                    reason=PolicyReason.EXECUTION_OUTCOME_UNKNOWN,
                )
            elif execution.outcome is ExecutionOutcome.FAILED:
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.FAILED,
                    now=context.now,
                    request_id=request_id,
                    reason=PolicyReason.EXECUTION_FAILED,
                )
            else:
                call = store.transition(
                    tenant_id=context.tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.VERIFYING,
                    now=context.now,
                    request_id=request_id,
                )
        if execution.outcome in {ExecutionOutcome.UNKNOWN, ExecutionOutcome.FAILED}:
            return GatewayResult(call, created, policy, approval, attempt)
        verification = self._verify(bound, call, execution, context, adapter)
        target = {
            VerificationOutcome.VERIFIED: TrustedToolCallStatus.SUCCEEDED,
            VerificationOutcome.FAILED: TrustedToolCallStatus.FAILED,
            VerificationOutcome.INCONCLUSIVE: TrustedToolCallStatus.NEEDS_REVIEW,
        }[verification.outcome]
        reason = (
            None if target is TrustedToolCallStatus.SUCCEEDED else PolicyReason.VERIFICATION_FAILED
        )
        with store.atomic():
            store.append_verification(tenant_id=context.tenant_id, verification=verification)
            call = store.transition(
                tenant_id=context.tenant_id,
                current=call,
                target=target,
                now=context.now,
                request_id=request_id,
                reason=reason,
            )
        return GatewayResult(call, created, policy, approval, attempt, verification)

    @staticmethod
    def _verify(
        bound: BoundToolRequest,
        call: TrustedToolCall,
        execution: AdapterExecution,
        context: ToolPolicyContext,
        adapter: TrustedToolAdapter,
    ) -> ToolVerification:
        try:
            verification = adapter.verify(bound, execution, now=context.now)
            if not isinstance(verification, ToolVerification):
                raise TypeError("adapter returned an invalid verification result")
            if verification.request_id != call.request.id:
                raise ValueError("verification belongs to another request")
            return verification
        except Exception:
            return ToolVerification(
                uuid4(),
                call.request.id,
                VerificationOutcome.INCONCLUSIVE,
                {"verification_status": "unavailable"},
                call.request.evidence,
                PolicyReason.VERIFICATION_FAILED,
                context.now,
            )


def _sanitize_execution(value: AdapterExecution) -> AdapterExecution:
    if not isinstance(value.outcome, ExecutionOutcome):
        raise TypeError("execution outcome is invalid")
    summary = _safe_summary(value.result_summary)
    if value.outcome is ExecutionOutcome.SUCCEEDED:
        category = None
    elif isinstance(value.error_category, str) and _ERROR_CATEGORY.fullmatch(value.error_category):
        category = value.error_category
    else:
        category = "tool_failure"
    return AdapterExecution(value.outcome, summary, category)


def _safe_summary(value: object) -> str:
    if not isinstance(value, str):
        return "Adapter returned no trusted summary."
    cleaned = " ".join(
        "".join(character if ord(character) >= 32 else " " for character in value).split()
    )
    return cleaned[:1024] or "Adapter returned no trusted summary."
