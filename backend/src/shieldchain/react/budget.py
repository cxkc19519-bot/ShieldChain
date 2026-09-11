"""Server-counted ReAct budget projection and deterministic loop detection."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from shieldchain.agents.domain import BudgetSnapshot
from shieldchain.react.domain import FailureCategory, PlanRevision, ReactLoop, ReactObservation


@dataclass(frozen=True, slots=True)
class ReactConsumption:
    tokens: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tokens, int)
            or isinstance(self.tokens, bool)
            or not 0 <= self.tokens <= 200_000
        ):
            raise ValueError("tokens must be between 0 and 200000")
        if (
            not isinstance(self.tool_calls, int)
            or isinstance(self.tool_calls, bool)
            or not 0 <= self.tool_calls <= 100
        ):
            raise ValueError("tool_calls must be between 0 and 100")
        if (
            not isinstance(self.cost_usd, (int, float))
            or isinstance(self.cost_usd, bool)
            or not math.isfinite(self.cost_usd)
            or not 0 <= self.cost_usd <= 100
        ):
            raise ValueError("cost_usd must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class BudgetProjection:
    allowed: bool
    budget: BudgetSnapshot
    fingerprint: str
    stop_category: FailureCategory | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a bool")
        if not isinstance(self.budget, BudgetSnapshot):
            raise TypeError("budget must be a BudgetSnapshot")
        if not isinstance(self.fingerprint, str) or len(self.fingerprint) != 64:
            raise ValueError("fingerprint must be SHA-256")
        if self.allowed != (self.stop_category is None):
            raise ValueError("allowed and stop_category are inconsistent")


class ReactBudgetSupervisor:
    def project(
        self,
        *,
        loop: ReactLoop,
        observation: ReactObservation,
        plan: PlanRevision | None,
        consumption: ReactConsumption,
        now: datetime,
    ) -> BudgetProjection:
        if not isinstance(loop, ReactLoop) or not isinstance(observation, ReactObservation):
            raise TypeError("loop and observation must be ReAct domain objects")
        if plan is not None and not isinstance(plan, PlanRevision):
            raise TypeError("plan must be a PlanRevision")
        if not isinstance(consumption, ReactConsumption):
            raise TypeError("consumption must be a ReactConsumption")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("now must be an aware UTC datetime")
        if now < loop.started_at or now < loop.updated_at:
            raise ValueError("now cannot predate the loop")
        if (
            observation.loop_id != loop.id
            or observation.case_id != loop.case_id
            or observation.run_id != loop.run_id
        ):
            raise ValueError("observation does not belong to the loop")
        if plan is not None and (
            plan.loop_id != loop.id or plan.case_id != loop.case_id or plan.run_id != loop.run_id
        ):
            raise ValueError("plan does not belong to the loop")

        fingerprint = self.fingerprint(observation=observation, plan=plan)
        if fingerprint in loop.observation_fingerprints:
            return BudgetProjection(False, loop.budget, fingerprint, FailureCategory.LOOP_DETECTED)

        current = loop.budget
        if self._at_limit(current):
            return BudgetProjection(False, current, fingerprint, FailureCategory.BUDGET_EXHAUSTED)
        elapsed = math.ceil((now - loop.started_at).total_seconds())
        projected = {
            "steps_used": current.steps_used + 1,
            "loops_used": current.loops_used + 1,
            "time_used_seconds": max(current.time_used_seconds, elapsed),
            "tokens_used": current.tokens_used + consumption.tokens,
            "cost_used_usd": current.cost_used_usd + consumption.cost_usd,
            "tool_calls_used": current.tool_calls_used + consumption.tool_calls,
        }
        limits = {
            "steps_used": current.step_limit,
            "loops_used": current.loop_limit,
            "time_used_seconds": current.time_limit_seconds,
            "tokens_used": current.token_limit,
            "cost_used_usd": current.cost_limit_usd,
            "tool_calls_used": current.tool_call_limit,
        }
        if any(projected[name] > limit for name, limit in limits.items()):
            return BudgetProjection(False, current, fingerprint, FailureCategory.BUDGET_EXHAUSTED)
        return BudgetProjection(True, replace(current, **projected), fingerprint)

    @staticmethod
    def _at_limit(value: BudgetSnapshot) -> bool:
        return any(
            used >= limit
            for used, limit in (
                (value.steps_used, value.step_limit),
                (value.loops_used, value.loop_limit),
                (value.time_used_seconds, value.time_limit_seconds),
                (value.tokens_used, value.token_limit),
                (value.cost_used_usd, value.cost_limit_usd),
                (value.tool_calls_used, value.tool_call_limit),
            )
        )

    @staticmethod
    def fingerprint(*, observation: ReactObservation, plan: PlanRevision | None) -> str:
        payload = {
            "observation": {
                "source": observation.source.value,
                "status": observation.status,
                "reason_code": observation.reason_code,
                "tool_call_id": str(observation.tool_call_id) if observation.tool_call_id else None,
                "verification_id": str(observation.verification_id)
                if observation.verification_id
                else None,
                "references": sorted(str(item.id) for item in observation.references),
            },
            "plan": None
            if plan is None
            else {
                "revision": plan.revision,
                "retained": sorted(str(item) for item in plan.retained_action_ids),
                "removed": sorted(str(item) for item in plan.removed_action_ids),
                "added": sorted(
                    (
                        item.action,
                        item.target,
                        tuple(sorted(item.expected_state.items())),
                        tuple(sorted(str(reference.id) for reference in item.references)),
                    )
                    for item in plan.added_actions
                ),
                "reason": plan.reason.value,
            },
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
