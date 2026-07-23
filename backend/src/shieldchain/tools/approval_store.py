"""SQLAlchemy adapter for the approval service port."""

from datetime import UTC
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from shieldchain.tools.domain import ApprovalDecision, ApprovalOutcome
from shieldchain.tools.persistence import ToolApprovalRow
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository


class SqlAlchemyApprovalStore:
    def __init__(
        self,
        session: Session,
        repository: SqlAlchemyTrustedToolRepository | None = None,
    ) -> None:
        self._session = session
        self._repository = repository or SqlAlchemyTrustedToolRepository()

    def latest(
        self, *, tenant_id: UUID, request_id: UUID
    ) -> ApprovalDecision | None:
        row = self._session.execute(
            select(ToolApprovalRow)
            .where(
                ToolApprovalRow.tenant_id == str(tenant_id),
                ToolApprovalRow.tool_call_id == str(request_id),
            )
            .order_by(ToolApprovalRow.decided_at.desc(), ToolApprovalRow.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            return None
        decided_at = (
            row.decided_at.replace(tzinfo=UTC)
            if row.decided_at.tzinfo is None
            else row.decided_at.astimezone(UTC)
        )
        expires_at = (
            row.expires_at.replace(tzinfo=UTC)
            if row.expires_at.tzinfo is None
            else row.expires_at.astimezone(UTC)
        )
        return ApprovalDecision(
            UUID(row.id),
            UUID(row.tool_call_id),
            row.request_digest,
            ApprovalOutcome(row.outcome),
            UUID(row.approver_subject_id),
            row.policy_version,
            row.reason_summary,
            decided_at,
            expires_at,
        )

    def append(self, *, tenant_id: UUID, decision: ApprovalDecision) -> None:
        self._repository.append_approval(
            self._session, tenant_id=tenant_id, decision=decision
        )
