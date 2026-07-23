from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_phase5_smoke_is_offline_bounded_and_cleans_temporary_state() -> None:
    wrapper = (ROOT / "tests" / "scripts" / "run-phase5-smoke.ps1").read_text(
        encoding="utf-8"
    )
    harness = (ROOT / "tests" / "scripts" / "phase5_smoke.py").read_text(
        encoding="utf-8"
    )
    assert "run-phase4-smoke.ps1" in wrapper
    assert "shieldchain-phase5-smoke-" in wrapper
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in wrapper
    assert "REAL_DEVICE_PATHS_TESTED=False" in wrapper
    assert "requests" not in harness and "subprocess" not in harness
    for scenario in (
        "phase5:success",
        "phase5:rejected",
        "phase5:unknown",
        "phase5:emergency",
        "TrustedToolIdempotencyConflict",
        "resume_after_execution",
    ):
        assert scenario in harness


def test_phase5_smoke_checks_public_trace_leakage() -> None:
    harness = (ROOT / "tests" / "scripts" / "phase5_smoke.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "tenant_id",
        "principal_id",
        "token_digest",
        "result_summary",
        "chain_of_thought",
        "raw_prompt",
    ):
        assert f'"{forbidden}"' in harness
