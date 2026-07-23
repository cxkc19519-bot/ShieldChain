"""One-step bounded ReAct service; it never receives a tool adapter."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy.orm import Session

from shieldchain.react.budget import ReactBudgetSupervisor, ReactConsumption
from shieldchain.react.classification import DeterministicFailureClassifier, TrustedFailureInput
from shieldchain.react.domain import (
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
    ReactStepDecision,
)
from shieldchain.react.replanning import DeterministicReplanner
from shieldchain.react.repositories import ReactStepBundle, SqlAlchemyReactRepository
from shieldchain.tools.registry import TrustedToolRegistry


class ReactStepStore(Protocol):
    def commit_step(self, *, tenant_id: UUID, bundle: ReactStepBundle) -> ReactLoop: ...


@dataclass(frozen=True, slots=True)
class ReactStepResult:
    loop: ReactLoop
    decision: ReactStepDecision
    plan: PlanRevision | None
    query_tool_name: str | None
    query_target: str | None


class SqlAlchemyReactStepStore:
    def __init__(
        self, session: Session, repository: SqlAlchemyReactRepository | None = None
    ) -> None:
        self._session = session
        self._repository = repository or SqlAlchemyReactRepository()

    def commit_step(self, *, tenant_id: UUID, bundle: ReactStepBundle) -> ReactLoop:
        with self._session.begin_nested():
            return self._repository.commit_step(self._session, tenant_id=tenant_id, bundle=bundle)


class ControlledReactService:
    def __init__(self, *, classifier=None, budgets=None, replanner=None) -> None:
        self._classifier = classifier or DeterministicFailureClassifier()
        self._budgets = budgets or ReactBudgetSupervisor()
        self._replanner = replanner or DeterministicReplanner()

    def step(
        self,
        *,
        tenant_id: UUID,
        loop: ReactLoop,
        current_plan: PlanRevision,
        failure: TrustedFailureInput,
        failed_action: ProposedAction,
        failed_tool_name: str,
        candidates: tuple[ProposedAction, ...],
        consumption: ReactConsumption,
        registry: TrustedToolRegistry,
        now: datetime,
        store: ReactStepStore,
    ) -> ReactStepResult:
        if loop.status is not ReactLoopStatus.RUNNING:
            raise ValueError("only a running react loop can step")
        if failure.observation.loop_id != loop.id:
            raise ValueError("failure observation belongs to another loop")
        projection = self._budgets.project(
            loop=loop,
            observation=failure.observation,
            plan=current_plan,
            consumption=consumption,
            now=now,
        )
        classified_input = failure
        if projection.stop_category is not None:
            classified_input = replace(
                failure,
                loop_detected=projection.stop_category.value == "loop_detected",
                budget_exhausted=projection.stop_category.value == "budget_exhausted",
            )
        assessment = self._classifier.classify(classified_input, now=now)
        if projection.allowed:
            instruction = self._replanner.decide(
                loop=loop,
                current=current_plan,
                assessment=assessment,
                failed_action=failed_action,
                failed_tool_name=failed_tool_name,
                candidates=candidates,
                registry=registry,
                now=now,
            )
        else:
            from shieldchain.react.replanning import ReplanResult

            instruction = ReplanResult(
                ReactDecision.MANUAL_REVIEW, f"{assessment.category.value}_requires_operator"
            )
        decision = ReactStepDecision(
            uuid5(NAMESPACE_URL, f"shieldchain:react:decision:{loop.id}:{loop.revision + 1}"),
            loop.id,
            failure.observation.id,
            assessment.id,
            instruction.decision,
            instruction.reason_code,
            projection.budget,
            now,
            instruction.plan_revision.id if instruction.plan_revision else None,
        )
        status = (
            ReactLoopStatus.AWAITING_HUMAN
            if instruction.decision is ReactDecision.MANUAL_REVIEW
            else ReactLoopStatus.AWAITING_EXECUTION
        )
        fingerprints = loop.observation_fingerprints
        if projection.fingerprint not in fingerprints:
            fingerprints = (*fingerprints, projection.fingerprint)
        changed = replace(
            loop,
            status=status,
            revision=loop.revision + 1,
            budget=projection.budget,
            observation_fingerprints=fingerprints,
            updated_at=now,
        )
        saved = store.commit_step(
            tenant_id=tenant_id,
            bundle=ReactStepBundle(
                loop, changed, failure.observation, assessment, decision, instruction.plan_revision
            ),
        )
        return ReactStepResult(
            saved,
            decision,
            instruction.plan_revision,
            instruction.query_tool_name,
            instruction.query_target,
        )
