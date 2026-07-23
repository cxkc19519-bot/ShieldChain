"""Tenant-scoped projection for the public multi-agent collaboration trajectory."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import AgentRole
from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    CaseContextRow,
    ConfirmedCaseFactRow,
)
from shieldchain.agents.schemas import (
    BudgetView,
    CollaborationTrajectoryView,
    HandoffView,
    RoleStatusView,
    TrajectoryReferenceView,
)
from shieldchain.incidents.persistence import InvestigationRunRow


class CollaborationTrajectoryNotFound(Exception):
    """The run is absent from the trusted tenant boundary or has no agent context."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _reference(value: dict[str, Any]) -> TrajectoryReferenceView:
    return TrajectoryReferenceView(
        id=UUID(str(value["id"])),
        kind=value["kind"],
        source_id=str(value["source_id"]),
        observed_at=datetime.fromisoformat(str(value["observed_at"])),
        integrity_sha256=str(value["integrity_sha256"]),
    )


def _references(values: list[dict[str, Any]]) -> list[TrajectoryReferenceView]:
    return [_reference(value) for value in values]


class CollaborationTrajectoryQuery:
    """Build an allowlisted read model; private-context rows are never queried."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def get(self, *, tenant_id: UUID, run_id: UUID) -> CollaborationTrajectoryView:
        with self._session_factory() as session:
            run = session.execute(
                select(InvestigationRunRow).where(
                    InvestigationRunRow.id == str(run_id),
                    InvestigationRunRow.tenant_id == str(tenant_id),
                )
            ).scalar_one_or_none()
            context = session.execute(
                select(CaseContextRow).where(
                    CaseContextRow.run_id == str(run_id),
                    CaseContextRow.tenant_id == str(tenant_id),
                )
            ).scalar_one_or_none()
            if run is None or context is None:
                raise CollaborationTrajectoryNotFound
            facts = list(
                session.execute(
                    select(ConfirmedCaseFactRow)
                    .where(
                        ConfirmedCaseFactRow.case_context_id == context.id,
                        ConfirmedCaseFactRow.tenant_id == str(tenant_id),
                    )
                    .order_by(ConfirmedCaseFactRow.created_at, ConfirmedCaseFactRow.id)
                ).scalars()
            )
            executions = list(
                session.execute(
                    select(AgentExecutionRow)
                    .where(
                        AgentExecutionRow.run_id == str(run_id),
                        AgentExecutionRow.tenant_id == str(tenant_id),
                    )
                    .order_by(AgentExecutionRow.created_at, AgentExecutionRow.id)
                ).scalars()
            )
            handoffs = list(
                session.execute(
                    select(AgentHandoffRow)
                    .where(
                        AgentHandoffRow.run_id == str(run_id),
                        AgentHandoffRow.tenant_id == str(tenant_id),
                    )
                    .order_by(AgentHandoffRow.created_at, AgentHandoffRow.id)
                ).scalars()
            )

        latest = {row.role: row for row in executions}
        role_statuses = []
        for role in AgentRole:
            row = latest.get(role.value)
            role_statuses.append(
                RoleStatusView(
                    role=role.value,
                    status=row.termination_reason
                    if row
                    else context.step_status_json.get(role.value, "not_started"),
                    summary=row.summary if row else None,
                    reason_code=(
                        row.termination_reason
                        if row and row.termination_reason != "completed"
                        else None
                    ),
                    citations=_references(row.references_json) if row else [],
                    updated_at=_utc(row.created_at) if row else None,
                )
            )
        handoff_views = [
            HandoffView(
                id=UUID(row.id),
                sender=row.sender_role,
                receiver=row.receiver_role,
                conclusion=row.conclusion,
                confidence=row.confidence,
                open_questions=list(row.open_questions_json),
                recommended_actions=list(row.recommended_actions_json),
                citations=_references(row.references_json),
                created_at=_utc(row.created_at),
            )
            for row in handoffs
        ]
        citations: dict[UUID, TrajectoryReferenceView] = {}
        for fact in facts:
            for reference in _references(fact.references_json):
                citations[reference.id] = reference
        for role in role_statuses:
            for reference in role.citations:
                citations[reference.id] = reference
        for handoff in handoff_views:
            for reference in handoff.citations:
                citations[reference.id] = reference
        reasons = sorted(
            {row.termination_reason for row in executions if row.termination_reason != "completed"}
        )
        return CollaborationTrajectoryView(
            run_id=run_id,
            case_id=UUID(run.incident_id),
            phase=context.phase,
            revision=context.revision,
            shared_summary=context.disposition_status,
            confirmed_facts=[fact.statement for fact in facts],
            role_statuses=role_statuses,
            handoffs=handoff_views,
            citations=sorted(citations.values(), key=lambda item: (item.observed_at, str(item.id))),
            budget=BudgetView.model_validate(context.budget_json),
            reason_codes=reasons,
            updated_at=_utc(context.updated_at),
        )
