"""Tenant-bound application service for trusted-tool HTTP endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.tools.approval_store import SqlAlchemyApprovalStore
from shieldchain.tools.approvals import ApprovalAuthority, TrustedToolApprovalService
from shieldchain.tools.control import TrustedToolControlService
from shieldchain.tools.control_store import SqlAlchemyToolControlStore
from shieldchain.tools.domain import (
    ApprovalOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolRisk,
    TrustedToolCallStatus,
)
from shieldchain.tools.persistence import (
    ToolApprovalRow,
    ToolExecutionAttemptRow,
    ToolPolicyDecisionRow,
    ToolVerificationRow,
    TrustedToolCallRow,
)
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository, _call
from shieldchain.tools.schemas import ToolMutationView, ToolTraceItem, ToolTraceView

REQUESTER_SERVICE_SUBJECT = UUID("00000000-0000-4000-8000-000000000006")


class ToolApiNotFound(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class TrustedToolApiService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def trace(self, *, tenant_id: UUID, run_id: UUID) -> ToolTraceView:
        with self._sessions() as session:
            rows = session.execute(
                select(TrustedToolCallRow)
                .where(
                    TrustedToolCallRow.tenant_id == str(tenant_id),
                    TrustedToolCallRow.run_id == str(run_id),
                )
                .order_by(TrustedToolCallRow.created_at, TrustedToolCallRow.id)
            ).scalars()
            items = [self._trace_item(session, row) for row in rows]
        if not items:
            raise ToolApiNotFound("trusted tool trace not found")
        return ToolTraceView(run_id=run_id, calls=items)

    def decide(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        call_id: UUID,
        outcome: ApprovalOutcome,
        reason: str,
        now: datetime,
    ) -> ToolMutationView:
        with self._sessions.begin() as session:
            repo = SqlAlchemyTrustedToolRepository()
            call = repo.get(session, tenant_id=tenant_id, tool_call_id=call_id)
            policy = self._latest_policy(session, tenant_id, call_id)
            if call is None or policy is None:
                raise ToolApiNotFound("trusted tool call not found")
            TrustedToolApprovalService().decide(
                call=call,
                policy=policy,
                authority=ApprovalAuthority(
                    tenant_id,
                    actor_id,
                    frozenset({"trusted_tools.approve", "trusted_tools.approve_critical"}),
                    now,
                ),
                requester_subject_id=REQUESTER_SERVICE_SUBJECT,
                outcome=outcome,
                reason_summary=reason,
                store=SqlAlchemyApprovalStore(session, repo),
            )
            if outcome is ApprovalOutcome.REJECTED:
                call = repo.transition(
                    session,
                    tenant_id=tenant_id,
                    current=call,
                    target=TrustedToolCallStatus.REJECTED,
                    now=now,
                    request_id=f"api-approval:{call_id}",
                    reason=PolicyReason.APPROVAL_REJECTED,
                )
            return ToolMutationView(
                call_id=call_id, status=call.status.value, revision=call.revision
            )

    def control_call(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        call_id: UUID,
        action: str,
        reason: str,
        now: datetime,
    ) -> ToolMutationView:
        with self._sessions.begin() as session:
            repo = SqlAlchemyTrustedToolRepository()
            call = repo.get(session, tenant_id=tenant_id, tool_call_id=call_id)
            if call is None:
                raise ToolApiNotFound("trusted tool call not found")
            service = TrustedToolControlService()
            store = SqlAlchemyToolControlStore(session, repo)
            changed = getattr(service, action)(
                tenant_id=tenant_id,
                call=call,
                actor_subject_id=actor_id,
                reason=reason,
                now=now,
                request_id=f"api-{action}:{call_id}",
                store=store,
            )
            return ToolMutationView(
                call_id=call_id, status=changed.status.value, revision=changed.revision
            )

    def emergency(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        active: bool,
        reason: str,
        now: datetime,
    ) -> ToolMutationView:
        with self._sessions.begin() as session:
            control = TrustedToolControlService().set_global(
                tenant_id=tenant_id,
                actor_subject_id=actor_id,
                automation_enabled=not active,
                emergency_stop_active=active,
                reason=reason,
                now=now,
                store=SqlAlchemyToolControlStore(session),
            )
            return ToolMutationView(
                status=("emergency_stopped" if active else "automation_enabled"),
                revision=control.revision,
            )

    @staticmethod
    def _latest_policy(session: Session, tenant_id: UUID, call_id: UUID) -> PolicyDecision | None:
        row = session.execute(
            select(ToolPolicyDecisionRow)
            .where(
                ToolPolicyDecisionRow.tenant_id == str(tenant_id),
                ToolPolicyDecisionRow.tool_call_id == str(call_id),
            )
            .order_by(ToolPolicyDecisionRow.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return (
            PolicyDecision(
                call_id,
                PolicyOutcome(row.outcome),
                PolicyReason(row.reason),
                row.policy_version,
                ToolRisk(row.assessed_risk),
                _utc(row.created_at),
                _utc(row.expires_at),
            )
            if row
            else None
        )

    @staticmethod
    def _trace_item(session: Session, row: TrustedToolCallRow) -> ToolTraceItem:
        call = _call(row)
        policy = session.execute(
            select(ToolPolicyDecisionRow)
            .where(
                ToolPolicyDecisionRow.tenant_id == row.tenant_id,
                ToolPolicyDecisionRow.tool_call_id == row.id,
            )
            .order_by(ToolPolicyDecisionRow.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        approval = session.execute(
            select(ToolApprovalRow)
            .where(
                ToolApprovalRow.tenant_id == row.tenant_id,
                ToolApprovalRow.tool_call_id == row.id,
            )
            .order_by(ToolApprovalRow.decided_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        attempts = session.execute(
            select(ToolExecutionAttemptRow)
            .where(
                ToolExecutionAttemptRow.tenant_id == row.tenant_id,
                ToolExecutionAttemptRow.tool_call_id == row.id,
            )
            .order_by(ToolExecutionAttemptRow.attempt_number)
        ).scalars()
        verification = session.execute(
            select(ToolVerificationRow)
            .where(
                ToolVerificationRow.tenant_id == row.tenant_id,
                ToolVerificationRow.tool_call_id == row.id,
            )
            .order_by(ToolVerificationRow.verified_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        target = next(
            str(call.request.arguments[key])
            for key in ("target_ip", "endpoint_id", "account_id")
            if key in call.request.arguments
        )
        return ToolTraceItem(
            id=call.request.id,
            tool_name=call.request.tool_name,
            tool_version=call.request.tool_version,
            status=call.status.value,
            reason=call.reason.value if call.reason else None,
            target=target,
            policy_outcome=policy.outcome if policy else None,
            risk=policy.assessed_risk if policy else None,
            approval_outcome=approval.outcome if approval else None,
            attempt_outcomes=[item.outcome for item in attempts],
            verification_outcome=verification.outcome if verification else None,
            evidence_ids=[item.id for item in call.request.evidence],
            created_at=call.request.created_at,
            updated_at=call.updated_at,
        )
