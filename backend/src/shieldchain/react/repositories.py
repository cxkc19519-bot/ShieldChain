"""Tenant-scoped CAS repository and atomic ReAct step persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from shieldchain.agents.domain import BudgetSnapshot, EvidenceReference, KnowledgeReference
from shieldchain.incidents.persistence import InvestigationRunRow
from shieldchain.react.domain import (
    FailureAssessment,
    PlanRevision,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
    ReactStepDecision,
)
from shieldchain.react.persistence import (
    ReactAssessmentRow,
    ReactDecisionRow,
    ReactLoopRow,
    ReactObservationRow,
    ReactPlanRevisionRow,
)


class ReactLoopNotFound(RuntimeError):
    pass


class StaleReactLoop(RuntimeError):
    pass


class ReactBoundaryViolation(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _budget(value):
    return BudgetSnapshot(**value)


def _reference(value):
    cls = (
        EvidenceReference
        if value["kind"] == "evidence"
        else KnowledgeReference
        if value["kind"] == "knowledge"
        else None
    )
    if cls is None:
        raise ReactBoundaryViolation("stored reference kind is invalid")
    return cls(
        UUID(value["id"]),
        UUID(value["case_id"]),
        value["source_id"],
        datetime.fromisoformat(value["observed_at"]),
        value["integrity_sha256"],
    )


def _loop(row):
    return ReactLoop(
        UUID(row.id),
        UUID(row.case_id),
        UUID(row.run_id),
        ReactLoopStatus(row.status),
        row.revision,
        _budget(row.budget_json),
        tuple(row.observation_fingerprints_json),
        _utc(row.started_at),
        _utc(row.updated_at),
    )


@dataclass(frozen=True, slots=True)
class ReactStepBundle:
    current: ReactLoop
    changed: ReactLoop
    observation: ReactObservation
    assessment: FailureAssessment
    decision: ReactStepDecision
    plan: PlanRevision | None = None


class SqlAlchemyReactRepository:
    def create(self, session: Session, *, tenant_id: UUID, loop: ReactLoop) -> ReactLoop:
        run = session.execute(
            select(InvestigationRunRow).where(
                InvestigationRunRow.id == str(loop.run_id),
                InvestigationRunRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if run is None or run.incident_id != str(loop.case_id):
            raise ReactLoopNotFound("run not found in tenant")
        session.add(
            ReactLoopRow(
                id=str(loop.id),
                tenant_id=str(tenant_id),
                case_id=str(loop.case_id),
                run_id=str(loop.run_id),
                status=loop.status.value,
                revision=loop.revision,
                budget_json=loop.budget.to_dict(),
                observation_fingerprints_json=list(loop.observation_fingerprints),
                started_at=loop.started_at,
                updated_at=loop.updated_at,
            )
        )
        session.flush()
        return loop

    def get(self, session: Session, *, tenant_id: UUID, loop_id: UUID) -> ReactLoop | None:
        row = session.execute(
            select(ReactLoopRow).where(
                ReactLoopRow.id == str(loop_id), ReactLoopRow.tenant_id == str(tenant_id)
            )
        ).scalar_one_or_none()
        return _loop(row) if row else None

    def commit_step(
        self, session: Session, *, tenant_id: UUID, bundle: ReactStepBundle
    ) -> ReactLoop:
        self._validate(bundle)
        result = session.execute(
            update(ReactLoopRow)
            .where(
                ReactLoopRow.id == str(bundle.current.id),
                ReactLoopRow.tenant_id == str(tenant_id),
                ReactLoopRow.revision == bundle.current.revision,
            )
            .values(
                status=bundle.changed.status.value,
                revision=bundle.changed.revision,
                budget_json=bundle.changed.budget.to_dict(),
                observation_fingerprints_json=list(bundle.changed.observation_fingerprints),
                updated_at=bundle.changed.updated_at,
            )
        )
        if result.rowcount != 1:
            raise StaleReactLoop("react loop revision is stale")
        session.add(
            ReactObservationRow(
                id=str(bundle.observation.id),
                loop_id=str(bundle.observation.loop_id),
                tenant_id=str(tenant_id),
                case_id=str(bundle.observation.case_id),
                run_id=str(bundle.observation.run_id),
                iteration=bundle.observation.iteration,
                source=bundle.observation.source.value,
                status=bundle.observation.status,
                reason_code=bundle.observation.reason_code,
                references_json=[x.to_dict() for x in bundle.observation.references],
                tool_call_id=str(bundle.observation.tool_call_id)
                if bundle.observation.tool_call_id
                else None,
                verification_id=str(bundle.observation.verification_id)
                if bundle.observation.verification_id
                else None,
                observed_at=bundle.observation.observed_at,
            )
        )
        session.add(
            ReactAssessmentRow(
                id=str(bundle.assessment.id),
                observation_id=str(bundle.assessment.observation_id),
                tenant_id=str(tenant_id),
                category=bundle.assessment.category.value,
                recoverable=bundle.assessment.recoverable,
                confidence=bundle.assessment.confidence,
                reason_code=bundle.assessment.reason_code,
                assessed_at=bundle.assessment.assessed_at,
            )
        )
        if bundle.plan:
            session.add(
                ReactPlanRevisionRow(
                    id=str(bundle.plan.id),
                    loop_id=str(bundle.plan.loop_id),
                    tenant_id=str(tenant_id),
                    case_id=str(bundle.plan.case_id),
                    run_id=str(bundle.plan.run_id),
                    revision=bundle.plan.revision,
                    parent_revision=bundle.plan.parent_revision,
                    retained_action_ids_json=[str(x) for x in bundle.plan.retained_action_ids],
                    removed_action_ids_json=[str(x) for x in bundle.plan.removed_action_ids],
                    added_actions_json=[x.to_dict() for x in bundle.plan.added_actions],
                    reason=bundle.plan.reason.value,
                    created_at=bundle.plan.created_at,
                )
            )
        session.add(
            ReactDecisionRow(
                id=str(bundle.decision.id),
                loop_id=str(bundle.decision.loop_id),
                tenant_id=str(tenant_id),
                observation_id=str(bundle.decision.observation_id),
                assessment_id=str(bundle.decision.assessment_id),
                decision=bundle.decision.decision.value,
                reason_code=bundle.decision.reason_code,
                budget_json=bundle.decision.budget.to_dict(),
                plan_revision_id=str(bundle.decision.plan_revision_id)
                if bundle.decision.plan_revision_id
                else None,
                decided_at=bundle.decision.decided_at,
            )
        )
        session.flush()
        return bundle.changed

    @staticmethod
    def _validate(bundle: ReactStepBundle) -> None:
        if (
            bundle.changed.id != bundle.current.id
            or bundle.changed.revision != bundle.current.revision + 1
        ):
            raise ReactBoundaryViolation("loop revision is not consecutive")
        boundary = (bundle.current.id, bundle.current.case_id, bundle.current.run_id)
        if (
            bundle.observation.loop_id,
            bundle.observation.case_id,
            bundle.observation.run_id,
        ) != boundary:
            raise ReactBoundaryViolation("observation crosses loop boundary")
        if (
            bundle.assessment.observation_id != bundle.observation.id
            or bundle.decision.observation_id != bundle.observation.id
            or bundle.decision.assessment_id != bundle.assessment.id
            or bundle.decision.loop_id != bundle.current.id
        ):
            raise ReactBoundaryViolation("step records are not bound")
        if (bundle.plan is None) != (bundle.decision.plan_revision_id is None):
            raise ReactBoundaryViolation("plan binding is inconsistent")
        if bundle.plan and (
            bundle.plan.id != bundle.decision.plan_revision_id
            or (bundle.plan.loop_id, bundle.plan.case_id, bundle.plan.run_id) != boundary
        ):
            raise ReactBoundaryViolation("plan crosses loop boundary")
