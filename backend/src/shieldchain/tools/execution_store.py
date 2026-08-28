"""Tenant-scoped SQLAlchemy execution lease and usage store."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from shieldchain.incidents.repositories import append_incident_audit
from shieldchain.response_planning.persistence import ResponsePlanActionRow
from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus
from shieldchain.tools.execution import (
    ExecutionLeaseGrant,
    ToolExecutionLease,
    ToolExecutionUsage,
)
from shieldchain.tools.persistence import (
    ToolAutomationControlRow,
    ToolExecutionAttemptRow,
    ToolExecutionLeaseRow,
    ToolVerificationRow,
    TrustedToolCallRow,
)
from shieldchain.tools.repositories import TrustedToolCallNotFound


class ExecutionLeaseConflict(RuntimeError):
    pass


class ExecutionLeaseNotFound(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _lease(row: ToolExecutionLeaseRow) -> ToolExecutionLease:
    return ToolExecutionLease(
        UUID(row.id),
        UUID(row.tool_call_id),
        UUID(row.holder_id),
        row.attempt_number,
        row.token_digest,
        _utc(row.acquired_at),
        _utc(row.expires_at),
        _utc(row.released_at) if row.released_at else None,
        row.release_reason,
    )


class SqlAlchemyExecutionStore:
    def __init__(self, session: Session) -> None:
        self._session = session

    def acquire_lease(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        holder_id: UUID,
        now: datetime,
        duration: timedelta,
        request_id: str,
    ) -> ExecutionLeaseGrant:
        if call.status is not TrustedToolCallStatus.APPROVED:
            raise ExecutionLeaseConflict("tool call is not approved for execution")
        if duration <= timedelta(0) or duration > timedelta(minutes=2):
            raise ValueError("lease duration must be between zero and two minutes")
        control = self._session.get(ToolAutomationControlRow, str(tenant_id))
        if control is not None and (
            not control.automation_enabled or control.emergency_stop_active
        ):
            raise ExecutionLeaseConflict("server automation control blocks new execution leases")

        row = self._session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.id == str(call.request.id),
                TrustedToolCallRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.revision == call.revision,
                TrustedToolCallRow.status == TrustedToolCallStatus.APPROVED.value,
            )
        ).scalar_one_or_none()
        if row is None:
            raise ExecutionLeaseConflict("tool call revision is stale or cross-tenant")
        self._require_verified_dependencies(row)
        active = self._session.execute(
            select(ToolExecutionLeaseRow.id).where(
                ToolExecutionLeaseRow.tool_call_id == str(call.request.id),
                ToolExecutionLeaseRow.tenant_id == str(tenant_id),
                ToolExecutionLeaseRow.released_at.is_(None),
            )
        ).scalar_one_or_none()
        if active is not None:
            raise ExecutionLeaseConflict("an execution lease is already active")
        attempt_number = self.next_attempt_number(tenant_id=tenant_id, request_id=call.request.id)
        token = secrets.token_urlsafe(32)
        lease = ToolExecutionLease(
            uuid4(),
            call.request.id,
            holder_id,
            attempt_number,
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            now,
            now + duration,
        )
        self._session.add(
            ToolExecutionLeaseRow(
                id=str(lease.id),
                tool_call_id=str(lease.request_id),
                tenant_id=str(tenant_id),
                holder_id=str(holder_id),
                attempt_number=attempt_number,
                token_digest=lease.token_digest,
                acquired_at=lease.acquired_at,
                expires_at=lease.expires_at,
                released_at=None,
                release_reason=None,
            )
        )
        append_incident_audit(
            self._session,
            incident_id=call.request.case_id,
            run_id=call.request.run_id,
            event_type="trusted_tool_execution_lease_acquired",
            request_id=request_id,
            occurred_at=now,
            payload={
                "tool_call_id": str(call.request.id),
                "lease_id": str(lease.id),
                "attempt_number": attempt_number,
            },
        )
        self._session.flush()
        return ExecutionLeaseGrant(lease, token)

    def _require_verified_dependencies(self, call: TrustedToolCallRow) -> None:
        if call.plan_action_id is None:
            return
        action = self._session.execute(
            select(ResponsePlanActionRow).where(
                ResponsePlanActionRow.id == call.plan_action_id,
                ResponsePlanActionRow.tenant_id == call.tenant_id,
            )
        ).scalar_one_or_none()
        if action is None or action.plan_revision_id != call.plan_revision_id:
            raise ExecutionLeaseConflict("plan action binding is invalid")
        for dependency_id in action.depends_on_json:
            dependency = self._session.execute(
                select(TrustedToolCallRow).where(
                    TrustedToolCallRow.tenant_id == call.tenant_id,
                    TrustedToolCallRow.plan_revision_id == action.plan_revision_id,
                    TrustedToolCallRow.plan_action_id == str(dependency_id),
                )
            ).scalar_one_or_none()
            if dependency is None or dependency.status != TrustedToolCallStatus.SUCCEEDED.value:
                raise ExecutionLeaseConflict("plan action dependencies are not verified")
            verified = self._session.execute(
                select(ToolVerificationRow.id).where(
                    ToolVerificationRow.tenant_id == call.tenant_id,
                    ToolVerificationRow.tool_call_id == dependency.id,
                    ToolVerificationRow.outcome == "verified",
                )
            ).scalar_one_or_none()
            if verified is None:
                raise ExecutionLeaseConflict("plan action dependencies are not verified")

    def release_lease(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        grant: ExecutionLeaseGrant,
        now: datetime,
        reason: str,
        request_id: str,
    ) -> ToolExecutionLease:
        if grant.lease.request_id != call.request.id or not grant.lease.matches(grant.token):
            raise ExecutionLeaseConflict("lease does not authorize this tool call")
        result = self._session.execute(
            update(ToolExecutionLeaseRow)
            .where(
                ToolExecutionLeaseRow.id == str(grant.lease.id),
                ToolExecutionLeaseRow.tool_call_id == str(call.request.id),
                ToolExecutionLeaseRow.tenant_id == str(tenant_id),
                ToolExecutionLeaseRow.token_digest == grant.lease.token_digest,
                ToolExecutionLeaseRow.released_at.is_(None),
            )
            .values(released_at=now, release_reason=reason)
        )
        if result.rowcount != 1:
            raise ExecutionLeaseNotFound("active execution lease not found")
        append_incident_audit(
            self._session,
            incident_id=call.request.case_id,
            run_id=call.request.run_id,
            event_type="trusted_tool_execution_lease_released",
            request_id=request_id,
            occurred_at=now,
            payload={
                "tool_call_id": str(call.request.id),
                "lease_id": str(grant.lease.id),
                "reason": reason,
            },
        )
        return ToolExecutionLease(
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

    def next_attempt_number(self, *, tenant_id: UUID, request_id: UUID) -> int:
        count = self._session.scalar(
            select(func.count())
            .select_from(ToolExecutionAttemptRow)
            .where(
                ToolExecutionAttemptRow.tenant_id == str(tenant_id),
                ToolExecutionAttemptRow.tool_call_id == str(request_id),
            )
        )
        result = int(count or 0) + 1
        if result > 4:
            raise ExecutionLeaseConflict("execution attempt limit is exhausted")
        return result

    def usage(self, *, tenant_id: UUID, run_id: UUID) -> ToolExecutionUsage:
        call_count = self._session.scalar(
            select(func.count())
            .select_from(TrustedToolCallRow)
            .where(
                TrustedToolCallRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.run_id == str(run_id),
            )
        )
        attempt_count = self._session.scalar(
            select(func.count())
            .select_from(ToolExecutionAttemptRow)
            .join(
                TrustedToolCallRow,
                ToolExecutionAttemptRow.tool_call_id == TrustedToolCallRow.id,
            )
            .where(
                ToolExecutionAttemptRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.run_id == str(run_id),
            )
        )
        return ToolExecutionUsage(int(call_count or 0), int(attempt_count or 0))

    def expired_leases(
        self, *, tenant_id: UUID, now: datetime, limit: int = 100
    ) -> tuple[ToolExecutionLease, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        rows = self._session.execute(
            select(ToolExecutionLeaseRow)
            .where(
                ToolExecutionLeaseRow.tenant_id == str(tenant_id),
                ToolExecutionLeaseRow.released_at.is_(None),
                ToolExecutionLeaseRow.expires_at <= now,
            )
            .order_by(ToolExecutionLeaseRow.expires_at, ToolExecutionLeaseRow.id)
            .limit(limit)
        ).scalars()
        return tuple(_lease(row) for row in rows)

    def expire_active_lease(
        self,
        *,
        tenant_id: UUID,
        call: TrustedToolCall,
        now: datetime,
        request_id: str,
    ) -> ToolExecutionLease:
        row = self._session.execute(
            select(ToolExecutionLeaseRow).where(
                ToolExecutionLeaseRow.tool_call_id == str(call.request.id),
                ToolExecutionLeaseRow.tenant_id == str(tenant_id),
                ToolExecutionLeaseRow.released_at.is_(None),
                ToolExecutionLeaseRow.expires_at <= now,
            )
        ).scalar_one_or_none()
        if row is None:
            raise ExecutionLeaseNotFound("expired execution lease not found")
        result = self._session.execute(
            update(ToolExecutionLeaseRow)
            .where(
                ToolExecutionLeaseRow.id == row.id,
                ToolExecutionLeaseRow.released_at.is_(None),
                ToolExecutionLeaseRow.expires_at <= now,
            )
            .values(released_at=now, release_reason="recovery_expired")
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise ExecutionLeaseNotFound("expired execution lease is stale")
        append_incident_audit(
            self._session,
            incident_id=call.request.case_id,
            run_id=call.request.run_id,
            event_type="trusted_tool_execution_lease_released",
            request_id=request_id,
            occurred_at=now,
            payload={
                "tool_call_id": str(call.request.id),
                "lease_id": row.id,
                "reason": "recovery_expired",
            },
        )
        return ToolExecutionLease(
            UUID(row.id),
            UUID(row.tool_call_id),
            UUID(row.holder_id),
            row.attempt_number,
            row.token_digest,
            _utc(row.acquired_at),
            _utc(row.expires_at),
            now,
            "recovery_expired",
        )

    def require_call(self, *, tenant_id: UUID, request_id: UUID) -> TrustedToolCallRow:
        row = self._session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.id == str(request_id),
                TrustedToolCallRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if row is None:
            raise TrustedToolCallNotFound("trusted tool call not found in tenant")
        return row
