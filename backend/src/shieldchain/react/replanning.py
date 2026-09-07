"""Deterministic plan revision and registered recovery instructions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from shieldchain.react.classification import DeterministicFailureClassifier
from shieldchain.react.domain import (
    FailureAssessment,
    FailureCategory,
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
)
from shieldchain.tools.registry import TrustedToolRegistry


@dataclass(frozen=True, slots=True)
class ReplanResult:
    decision: ReactDecision
    reason_code: str
    plan_revision: PlanRevision | None = None
    query_tool_name: str | None = None
    query_target: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, ReactDecision):
            raise TypeError("decision must be a ReactDecision")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise ValueError("reason_code is required")
        if (self.decision is ReactDecision.REPLAN) != (self.plan_revision is not None):
            raise ValueError("only replan decisions bind a plan revision")
        query = self.query_tool_name is not None or self.query_target is not None
        if query != (self.decision in {ReactDecision.QUERY_STATUS, ReactDecision.RETRY_READ_ONLY}):
            raise ValueError("query fields must bind a query decision")
        if query and (not self.query_tool_name or not self.query_target):
            raise ValueError("query tool and target are both required")


class DeterministicReplanner:
    _REPLAN = frozenset(
        {
            FailureCategory.VERIFICATION_FAILED,
            FailureCategory.EXECUTION_FAILED,
            FailureCategory.EVIDENCE_INSUFFICIENT,
        }
    )

    def decide(
        self,
        *,
        loop: ReactLoop,
        current: PlanRevision,
        assessment: FailureAssessment,
        failed_action: ProposedAction,
        failed_tool_name: str,
        candidates: tuple[ProposedAction, ...],
        registry: TrustedToolRegistry,
        now: datetime,
    ) -> ReplanResult:
        if not all(
            (
                current.loop_id == loop.id,
                current.case_id == loop.case_id,
                current.run_id == loop.run_id,
            )
        ):
            raise ValueError("current plan does not belong to the loop")
        if not isinstance(assessment, FailureAssessment):
            raise TypeError("assessment must be a FailureAssessment")
        if not isinstance(failed_action, ProposedAction):
            raise TypeError("failed_action must be a ProposedAction")
        if not isinstance(candidates, tuple) or any(
            not isinstance(item, ProposedAction) for item in candidates
        ):
            raise TypeError("candidates must be a tuple of ProposedAction values")
        if not isinstance(registry, TrustedToolRegistry):
            raise TypeError("registry must be a TrustedToolRegistry")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("now must be an aware UTC datetime")

        category = assessment.category
        allowed = DeterministicFailureClassifier.allowed_decisions(category)
        if category is FailureCategory.COMPLETED:
            return ReplanResult(ReactDecision.COMPLETE, "verified_result_completed")
        registration = registry.resolve(failed_tool_name, "1")
        definition = registration.definition
        if category in {
            FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
            FailureCategory.VERIFICATION_INCONCLUSIVE,
        }:
            if definition.mutates_state and definition.verifier_name:
                registry.resolve(definition.verifier_name, "1")
                return ReplanResult(
                    ReactDecision.QUERY_STATUS,
                    "query_registered_state_before_replan",
                    query_tool_name=definition.verifier_name,
                    query_target=failed_action.target,
                )
            return ReplanResult(ReactDecision.MANUAL_REVIEW, "unknown_state_requires_operator")
        if category is FailureCategory.DEPENDENCY_UNAVAILABLE and not definition.mutates_state:
            return ReplanResult(
                ReactDecision.RETRY_READ_ONLY,
                "retry_registered_read_only_tool",
                query_tool_name=definition.name,
                query_target=failed_action.target,
            )
        if category not in self._REPLAN or ReactDecision.REPLAN not in allowed:
            return ReplanResult(ReactDecision.MANUAL_REVIEW, f"{category.value}_requires_operator")

        valid = []
        for candidate in candidates:
            action_name = candidate.action.removeprefix("proposed:")
            candidate_definition = registry.resolve(action_name, "1").definition
            if (
                candidate_definition.mutates_state
                and any(reference.case_id == loop.case_id for reference in candidate.references)
                and (candidate.action, candidate.target)
                != (failed_action.action, failed_action.target)
            ):
                valid.append(candidate)
        if not valid:
            return ReplanResult(ReactDecision.MANUAL_REVIEW, "no_safe_alternative_action")
        selected = min(valid, key=lambda item: (item.action, item.target, str(item.id)))
        retained = tuple(
            item
            for item in (
                *current.retained_action_ids,
                *(action.id for action in current.added_actions),
            )
            if item != failed_action.id
        )
        revision_number = current.revision + 1
        revision = PlanRevision(
            uuid5(NAMESPACE_URL, f"shieldchain:react:plan:{loop.id}:{revision_number}"),
            loop.id,
            loop.case_id,
            loop.run_id,
            revision_number,
            current.revision,
            retained,
            (failed_action.id,),
            (selected,),
            category,
            now,
        )
        return ReplanResult(ReactDecision.REPLAN, "safe_alternative_proposed", revision)
