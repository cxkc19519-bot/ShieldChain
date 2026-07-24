"""Strict, offline performance budgets with privacy-safe runtime metadata."""

from __future__ import annotations

import json
import math
import platform
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BUDGET_SCHEMA = "shieldchain.quality.baseline-budget/v1"
REPORT_SCHEMA = "shieldchain.quality.baseline-report/v1"
_TOP_LEVEL_FIELDS = {"schema_version", "profile", "scenarios"}
_SCENARIO_FIELDS = {
    "unit",
    "warmup_iterations",
    "sample_count",
    "percentile",
    "maximum",
}


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 100:
        raise ValueError(f"{field} must be a trimmed non-empty string of at most 100 characters")
    return value


def _count(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _positive_number(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 60_000:
        raise ValueError(f"{field} must be finite and between 0 and 60000")
    return result


@dataclass(frozen=True, slots=True)
class ScenarioBudget:
    unit: str
    warmup_iterations: int
    sample_count: int
    percentile: str
    maximum: float

    def __post_init__(self) -> None:
        if self.unit != "milliseconds":
            raise ValueError("unit must be milliseconds")
        _count(self.warmup_iterations, "warmup_iterations", minimum=0, maximum=100)
        _count(self.sample_count, "sample_count", minimum=5, maximum=1000)
        if self.percentile != "p95":
            raise ValueError("percentile must be p95")
        object.__setattr__(self, "maximum", _positive_number(self.maximum, "maximum"))


@dataclass(frozen=True, slots=True)
class BaselineBudget:
    profile: str
    scenarios: Mapping[str, ScenarioBudget]

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", _text(self.profile, "profile"))
        scenarios = dict(self.scenarios)
        if not scenarios or len(scenarios) > 50:
            raise ValueError("scenarios must contain between 1 and 50 entries")
        for name, budget in scenarios.items():
            _text(name, "scenario name")
            if not isinstance(budget, ScenarioBudget):
                raise TypeError("scenarios must contain ScenarioBudget values")
        object.__setattr__(self, "scenarios", scenarios)


def load_baseline_budget(path: str | Path) -> BaselineBudget:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise ValueError("baseline budget has an invalid top-level schema")
    if payload["schema_version"] != BUDGET_SCHEMA:
        raise ValueError("baseline budget has an unsupported schema version")
    raw_scenarios = payload["scenarios"]
    if not isinstance(raw_scenarios, dict):
        raise TypeError("scenarios must be an object")
    scenarios: dict[str, ScenarioBudget] = {}
    for name, value in raw_scenarios.items():
        if not isinstance(value, dict) or set(value) != _SCENARIO_FIELDS:
            raise ValueError("scenario budget has an invalid schema")
        scenarios[name] = ScenarioBudget(**value)
    return BaselineBudget(profile=payload["profile"], scenarios=scenarios)


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _measure(
    operation: Callable[[], object],
    budget: ScenarioBudget,
    *,
    clock_ns: Callable[[], int],
) -> dict[str, Any]:
    for _ in range(budget.warmup_iterations):
        operation()
    samples: list[float] = []
    for _ in range(budget.sample_count):
        started = clock_ns()
        operation()
        elapsed = max(0, clock_ns() - started) / 1_000_000
        samples.append(elapsed)
    p50 = _percentile(samples, 0.50)
    p95 = _percentile(samples, 0.95)
    return {
        "unit": budget.unit,
        "sample_count": budget.sample_count,
        "p50": round(p50, 3),
        "p95": round(p95, 3),
        "maximum_p95": budget.maximum,
        "passed": p95 <= budget.maximum,
    }


def run_baseline(
    budget: BaselineBudget,
    operations: Mapping[str, Callable[[], object]],
    *,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
) -> dict[str, Any]:
    if set(operations) != set(budget.scenarios):
        raise ValueError("operations must exactly match configured scenarios")
    results = {
        name: _measure(operations[name], scenario, clock_ns=clock_ns)
        for name, scenario in sorted(budget.scenarios.items())
    }
    return {
        "schema_version": REPORT_SCHEMA,
        "profile": budget.profile,
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": sys.platform,
            "architecture": platform.machine() or "unknown",
        },
        "scenarios": results,
        "passed": all(result["passed"] for result in results.values()),
        "boundaries": {
            "network_access_tested": False,
            "real_model_planning_tested": False,
            "real_device_paths_tested": False,
        },
    }
