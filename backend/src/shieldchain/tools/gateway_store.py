"""SQLAlchemy transaction adapter for the trusted-tool gateway."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from shieldchain.tools.approval_store import SqlAlchemyApprovalStore
from shieldchain.tools.domain import (
    ApprovalDecision,
    PolicyDecision,
    PolicyReason,
    ToolExecutionAttempt,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
)
from shieldchain.tools.execution import ExecutionLeaseGrant, ToolExecutionLease
from shieldchain.tools.execution_store import SqlAlchemyExecutionStore
from shieldchain.tools.registry import BoundToolRequest
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository


class SqlAlchemyGatewayStore:
    """Bind repository operations to one session and explicit savepoints."""

    def __init__(
        self,
        session: Session,
        repository: SqlAlchemyTrustedToolRepository | None = None,
    ) -> None:
        self._session = session
        self._repository = repository or SqlAlchemyTrustedToolRepository()
        self._approvals = SqlAlchemyApprovalStore(session, self._repository)
        self._execution = SqlAlchemyExecutionStore(session)

    @contextmanager
    def atomic(self) -> Iterator[None]:
        with self._session.begin_nested():
            yield

    def commit(self) -> None:
        """Make completed gateway phases visible to recovery workers."""

        self._session.commit()

    def create_or_get(
        self, *, tenant_id: UUID, bound: BoundToolRequest, request_id: str
    ) -> tuple[TrustedToolCall, bool]:
        with self.atomic():
            return self._repository.create_or_get(
                self._session,
                tenant_id=tenant_id,
                bound=bound,
                request_id=request_id,
            )

    def append_policy(self, *, tenant_id: UUID, decision: PolicyDecision) -> None:
        self._repository.append_policy(self._session, tenant_id=tenant_id, decision=decision)

    def transition(
        self,
        *,
        tenant_id: UUID,
        current: TrustedToolCall,
        target: TrustedToolCallStatus,
        now: datetime,
        request_id: str,
        reason: PolicyReason | None = None,
    ) -> TrustedToolCall:
        return self._repository.transition(
            self._session,
            tenant_id=tenant_id,
            current=current,
            target=target,
            now=now,
            request_id=request_id,
            reason=reason,
        )

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
        return self._execution.acquire_lease(
            tenant_id=tenant_id,
            call=call,
            holder_id=holder_id,
            now=now,
            duration=duration,
            request_id=request_id,
        )

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
        return self._execution.release_lease(
            tenant_id=tenant_id,
            call=call,
            grant=grant,
            now=now,
            reason=reason,
            request_id=request_id,
        )

    def next_attempt_number(self, *, tenant_id: UUID, request_id: UUID) -> int:
        return self._execution.next_attempt_number(tenant_id=tenant_id, request_id=request_id)

    def append_attempt(self, *, tenant_id: UUID, attempt: ToolExecutionAttempt) -> None:
        self._repository.append_attempt(self._session, tenant_id=tenant_id, attempt=attempt)

    def append_verification(self, *, tenant_id: UUID, verification: ToolVerification) -> None:
        self._repository.append_verification(
            self._session, tenant_id=tenant_id, verification=verification
        )

    def latest(self, *, tenant_id: UUID, request_id: UUID) -> ApprovalDecision | None:
        return self._approvals.latest(tenant_id=tenant_id, request_id=request_id)

    def append(self, *, tenant_id: UUID, decision: ApprovalDecision) -> None:
        self._approvals.append(tenant_id=tenant_id, decision=decision)
