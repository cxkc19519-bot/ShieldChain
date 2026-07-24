import json
from pathlib import Path

import pytest

from shieldchain.quality.baseline import (
    BUDGET_SCHEMA,
    BaselineBudget,
    ScenarioBudget,
    load_baseline_budget,
    run_baseline,
)

ROOT = Path(__file__).resolve().parents[4]
BUDGET = ROOT / "tests" / "fixtures" / "quality" / "phase8_baseline_v1.json"


def test_committed_budget_is_strict_offline_and_has_real_scenarios() -> None:
    budget = load_baseline_budget(BUDGET)
    assert budget.profile == "offline-local"
    assert set(budget.scenarios) == {"health_live_http", "rag_dataset_load"}
    assert all(item.sample_count >= 15 for item in budget.scenarios.values())
    assert all(item.percentile == "p95" for item in budget.scenarios.values())


def test_measurement_report_has_units_samples_percentiles_and_boundaries() -> None:
    ticks = iter(range(0, 1_000_000_000, 1_000_000))
    budget = BaselineBudget(
        "offline-local",
        {"operation": ScenarioBudget("milliseconds", 1, 5, "p95", 2)},
    )
    report = run_baseline(
        budget,
        {"operation": lambda: None},
        clock_ns=lambda: next(ticks),
    )
    result = report["scenarios"]["operation"]
    assert result == {
        "unit": "milliseconds",
        "sample_count": 5,
        "p50": 1.0,
        "p95": 1.0,
        "maximum_p95": 2.0,
        "passed": True,
    }
    assert report["passed"] is True
    assert set(report["runtime"]) == {"python", "implementation", "platform", "architecture"}
    assert report["boundaries"] == {
        "network_access_tested": False,
        "real_model_planning_tested": False,
        "real_device_paths_tested": False,
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"schema_version": "wrong"}, "schema version"),
        ({"extra": True}, "top-level schema"),
        ({"scenarios": {}}, "between 1 and 50"),
    ],
)
def test_budget_rejects_unknown_versions_fields_and_empty_scenarios(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    payload = {
        "schema_version": BUDGET_SCHEMA,
        "profile": "offline-local",
        "scenarios": {
            "operation": {
                "unit": "milliseconds",
                "warmup_iterations": 1,
                "sample_count": 5,
                "percentile": "p95",
                "maximum": 10,
            }
        },
    }
    payload.update(change)
    path = tmp_path / "budget.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises((TypeError, ValueError), match=message):
        load_baseline_budget(path)


def test_report_fails_closed_for_missing_or_slow_operations() -> None:
    budget = BaselineBudget(
        "offline-local", {"operation": ScenarioBudget("milliseconds", 0, 5, "p95", 0.5)}
    )
    with pytest.raises(ValueError, match="exactly"):
        run_baseline(budget, {})
    ticks = iter(range(0, 100_000_000, 1_000_000))
    report = run_baseline(budget, {"operation": lambda: None}, clock_ns=lambda: next(ticks))
    assert report["passed"] is False
