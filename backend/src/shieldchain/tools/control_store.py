"""SQLAlchemy storage adapter for trusted-tool controls."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from shieldchain.tools.control import (
    AutomationControl,
    ToolControlAction,
    ToolControlEvent,
    TrustedToolControlService,
)
from shieldchain.tools.domain import TrustedToolCall, TrustedToolCallStatus
from shieldchain.tools.persistence import (
    ToolAutomationControlRow,
    ToolControlEventRow,
    TrustedToolCallRow,
)
from shieldchain.tools.repositories import (
    SqlAlchemyTrustedToolRepository,
    _call,
)


class StaleAutomationControl(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class SqlAlchemyToolControlStore:
    def __init__(
        self,
        session: Session,
        repository: SqlAlchemyTrustedToolRepository | None = None,
    ) -> None:
        self._session = session
        self._repository = repository or SqlAlchemyTrustedToolRepository()

    def transition_controlled_call(
        self,
        *,
        tenant_id: UUID,
        current: TrustedToolCall,
        target: TrustedToolCallStatus,
        now: datetime,
        request_id: str,
    ) -> TrustedToolCall:
        return self._repository.transition(
            self._session,
            tenant_id=tenant_id,
            current=current,
            target=target,
            now=now,
            request_id=request_id,
        )

    def append_control_event(self, event: ToolControlEvent) -> None:
        self._session.add(
            ToolControlEventRow(
                id=str(event.id),
                tenant_id=str(event.tenant_id),
                tool_call_id=str(event.request_id) if event.request_id else None,
                action=event.action.value,
                actor_subject_id=str(event.actor_subject_id),
                reason=event.reason,
                previous_status=(event.previous_status.value if event.previous_status else None),
                new_status=event.new_status.value if event.new_status else None,
                revision=event.revision,
                occurred_at=event.occurred_at,
            )
        )

    def latest_call_event(self, *, tenant_id: UUID, request_id: UUID) -> ToolControlEvent | None:
        row = self._session.execute(
            select(ToolControlEventRow)
            .where(
                ToolControlEventRow.tenant_id == str(tenant_id),
                ToolControlEventRow.tool_call_id == str(request_id),
            )
            .order_by(ToolControlEventRow.occurred_at.desc(), ToolControlEventRow.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            return None
        return ToolControlEvent(
            UUID(row.id),
            UUID(row.tenant_id),
            UUID(row.tool_call_id) if row.tool_call_id else None,
            ToolControlAction(row.action),
            UUID(row.actor_subject_id),
            row.reason,
            TrustedToolCallStatus(row.previous_status) if row.previous_status else None,
            TrustedToolCallStatus(row.new_status) if row.new_status else None,
            row.revision,
            _utc(row.occurred_at),
        )

    def get_control(self, *, tenant_id: UUID) -> AutomationControl | None:
        row = self._session.get(ToolAutomationControlRow, str(tenant_id))
        if row is None:
            return None
        return AutomationControl(
            UUID(row.tenant_id),
            row.automation_enabled,
            row.emergency_stop_active,
            row.revision,
            UUID(row.actor_subject_id),
            row.reason,
            _utc(row.updated_at),
        )

    def set_control(
        self, *, current: AutomationControl | None, changed: AutomationControl
    ) -> AutomationControl:
        if current is None:
            if self._session.get(ToolAutomationControlRow, str(changed.tenant_id)) is not None:
                raise StaleAutomationControl("automation control was concurrently created")
            self._session.add(
                ToolAutomationControlRow(
                    tenant_id=str(changed.tenant_id),
                    automation_enabled=changed.automation_enabled,
                    emergency_stop_active=changed.emergency_stop_active,
                    revision=changed.revision,
                    actor_subject_id=str(changed.actor_subject_id),
                    reason=changed.reason,
                    updated_at=changed.updated_at,
                )
            )
            self._session.flush()
            return changed
        result = self._session.execute(
            update(ToolAutomationControlRow)
            .where(
                ToolAutomationControlRow.tenant_id == str(changed.tenant_id),
                ToolAutomationControlRow.revision == current.revision,
            )
            .values(
                automation_enabled=changed.automation_enabled,
                emergency_stop_active=changed.emergency_stop_active,
                revision=changed.revision,
                actor_subject_id=str(changed.actor_subject_id),
                reason=changed.reason,
                updated_at=changed.updated_at,
            )
        )
        if result.rowcount != 1:
            raise StaleAutomationControl("automation control revision is stale")
        return changed

    def pending_calls(self, *, tenant_id: UUID) -> tuple[TrustedToolCall, ...]:
        rows = self._session.execute(
            select(TrustedToolCallRow).where(
                TrustedToolCallRow.tenant_id == str(tenant_id),
                TrustedToolCallRow.status.in_(
                    status.value for status in TrustedToolControlService._CONTROLLABLE
                ),
            )
        ).scalars()
        return tuple(_call(row) for row in rows)
