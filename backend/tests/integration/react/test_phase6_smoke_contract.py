from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_phase6_smoke_is_offline_bounded_and_cleans_temporary_state() -> None:
    wrapper = (ROOT / "tests" / "scripts" / "run-phase6-smoke.ps1").read_text(encoding="utf-8")
    harness = (ROOT / "tests" / "scripts" / "phase6_smoke.py").read_text(encoding="utf-8")
    assert "run-phase5-smoke.ps1" in wrapper
    assert "shieldchain-phase6-smoke-" in wrapper
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in wrapper
    assert "REAL_MODEL_PLANNING_TESTED=False" in wrapper
    assert "REAL_DEVICE_PATHS_TESTED=False" in wrapper
    assert "requests" not in harness and "subprocess" not in harness
    for scenario in (
        "phase6:verified-replan",
        "phase6:unknown-query",
        "phase6:loop-detected",
        "phase6:budget-exhausted",
        "phase6:approval-rejected",
        "operator takeover",
    ):
        assert scenario in harness


def test_phase6_smoke_checks_public_projection_leakage() -> None:
    harness = (ROOT / "tests" / "scripts" / "phase6_smoke.py").read_text(encoding="utf-8")
    for forbidden in (
        "tenant_id",
        "actor_subject_id",
        "reason_summary",
        "request_id",
        "adapter_result",
        "chain_of_thought",
        "raw_prompt",
    ):
        assert f'"{forbidden}"' in harness
