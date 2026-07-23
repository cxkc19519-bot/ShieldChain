"""Tenant-bound application service for public ReAct traces and controls."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.schemas import BudgetView, TrajectoryReferenceView
from shieldchain.react.persistence import (
    ReactAssessmentRow,
    ReactControlEventRow,
    ReactDecisionRow,
    ReactLoopRow,
    ReactObservationRow,
    ReactPlanRevisionRow,
)
from shieldchain.react.repositories import (
    ReactLoopNotFound,
    SqlAlchemyReactRepository,
    StaleReactLoop,
)
from shieldchain.react.schemas import (
    ReactActionView,
    ReactAssessmentView,
    ReactControlEventView,
    ReactDecisionView,
    ReactMutationView,
    ReactObservationView,
    ReactPlanRevisionView,
    ReactTrajectoryView,
)


class ReactApiNotFound(RuntimeError):
    pass


class ReactControlConflict(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


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


def _action(value: dict[str, Any]) -> ReactActionView:
    expected = {
        key: item
        for key, item in dict(value["expected_state"]).items()
        if key in {"firewall_status", "isolation_status", "account_status"}
    }
    return ReactActionView(
        id=UUID(str(value["id"])),
        action=str(value["action"]),
        target=str(value["target"]),
        expected_state=expected,
        citations=_references(value["references"]),
    )


class ReactApiService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def trajectory(self, *, tenant_id: UUID, run_id: UUID) -> ReactTrajectoryView:
        with self._sessions() as session:
            loop = session.execute(
                select(ReactLoopRow).where(
                    ReactLoopRow.tenant_id == str(tenant_id),
                    ReactLoopRow.run_id == str(run_id),
                )
            ).scalar_one_or_none()
            if loop is None:
                raise ReactApiNotFound("react trajectory not found")
            observations = list(
                session.execute(
                    select(ReactObservationRow)
                    .where(
                        ReactObservationRow.tenant_id == str(tenant_id),
                        ReactObservationRow.loop_id == loop.id,
                    )
                    .order_by(ReactObservationRow.iteration, ReactObservationRow.observed_at)
                ).scalars()
            )
            observation_ids = [row.id for row in observations]
            assessments = (
                list(
                    session.execute(
                        select(ReactAssessmentRow)
                        .where(
                            ReactAssessmentRow.tenant_id == str(tenant_id),
                            ReactAssessmentRow.observation_id.in_(observation_ids),
                        )
                        .order_by(ReactAssessmentRow.assessed_at, ReactAssessmentRow.id)
                    ).scalars()
                )
                if observation_ids
                else []
            )
            plans = list(
                session.execute(
                    select(ReactPlanRevisionRow)
                    .where(
                        ReactPlanRevisionRow.tenant_id == str(tenant_id),
                        ReactPlanRevisionRow.loop_id == loop.id,
                    )
                    .order_by(ReactPlanRevisionRow.revision)
                ).scalars()
            )
            decisions = list(
                session.execute(
                    select(ReactDecisionRow)
                    .where(
                        ReactDecisionRow.tenant_id == str(tenant_id),
                        ReactDecisionRow.loop_id == loop.id,
                    )
                    .order_by(ReactDecisionRow.decided_at, ReactDecisionRow.id)
                ).scalars()
            )
            controls = list(
                session.execute(
                    select(ReactControlEventRow)
                    .where(
                        ReactControlEventRow.tenant_id == str(tenant_id),
                        ReactControlEventRow.loop_id == loop.id,
                    )
                    .order_by(ReactControlEventRow.created_at, ReactControlEventRow.id)
                ).scalars()
            )
        return ReactTrajectoryView(
            loop_id=UUID(loop.id),
            run_id=run_id,
            case_id=UUID(loop.case_id),
            status=loop.status,
            revision=loop.revision,
            budget=BudgetView.model_validate(loop.budget_json),
            observations=[
                ReactObservationView(
                    id=UUID(row.id),
                    iteration=row.iteration,
                    source=row.source,
                    status=row.status,
                    reason_code=row.reason_code,
                    citations=_references(row.references_json),
                    tool_call_id=UUID(row.tool_call_id) if row.tool_call_id else None,
                    verification_id=UUID(row.verification_id) if row.verification_id else None,
                    observed_at=_utc(row.observed_at),
                )
                for row in observations
            ],
            assessments=[
                ReactAssessmentView(
                    id=UUID(row.id),
                    observation_id=UUID(row.observation_id),
                    category=row.category,
                    recoverable=row.recoverable,
                    confidence=row.confidence,
                    reason_code=row.reason_code,
                    assessed_at=_utc(row.assessed_at),
                )
                for row in assessments
            ],
            plan_revisions=[
                ReactPlanRevisionView(
                    id=UUID(row.id),
                    revision=row.revision,
                    parent_revision=row.parent_revision,
                    retained_action_ids=[UUID(value) for value in row.retained_action_ids_json],
                    removed_action_ids=[UUID(value) for value in row.removed_action_ids_json],
                    added_actions=[_action(value) for value in row.added_actions_json],
                    reason=row.reason,
                    created_at=_utc(row.created_at),
                )
                for row in plans
            ],
            decisions=[
                ReactDecisionView(
                    id=UUID(row.id),
                    observation_id=UUID(row.observation_id),
                    assessment_id=UUID(row.assessment_id),
                    decision=row.decision,
                    reason_code=row.reason_code,
                    budget=BudgetView.model_validate(row.budget_json),
                    plan_revision_id=(UUID(row.plan_revision_id) if row.plan_revision_id else None),
                    decided_at=_utc(row.decided_at),
                )
                for row in decisions
            ],
            controls=[
                ReactControlEventView(
                    id=UUID(row.id),
                    action=row.action,
                    from_status=row.from_status,
                    to_status=row.to_status,
                    reason_code=row.reason_code,
                    revision=row.revision,
                    created_at=_utc(row.created_at),
                )
                for row in controls
            ],
            updated_at=_utc(loop.updated_at),
        )

    def control(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        loop_id: UUID,
        action: str,
        reason: str,
        request_id: str,
        now: datetime,
    ) -> ReactMutationView:
        try:
            with self._sessions.begin() as session:
                changed = SqlAlchemyReactRepository().control(
                    session,
                    tenant_id=tenant_id,
                    loop_id=loop_id,
                    actor_subject_id=actor_id,
                    action=action,
                    reason_summary=reason,
                    request_id=request_id,
                    now=now,
                )
        except ReactLoopNotFound:
            raise ReactApiNotFound("react loop not found") from None
        except (IntegrityError, StaleReactLoop, ValueError):
            raise ReactControlConflict("react control is not allowed") from None
        return ReactMutationView(
            loop_id=changed.id,
            status=changed.status.value,
            revision=changed.revision,
        )
