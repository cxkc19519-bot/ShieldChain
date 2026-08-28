from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_phase7_smoke_is_offline_cross_page_and_cleans_temporary_state() -> None:
    wrapper = (ROOT / "tests" / "scripts" / "run-phase7-smoke.ps1").read_text(encoding="utf-8")
    smoke = (ROOT / "frontend" / "src" / "test" / "phase7-smoke.test.tsx").read_text(
        encoding="utf-8"
    )
    assert "run-phase6-smoke.ps1" in wrapper
    assert "shieldchain-phase7-smoke-" in wrapper
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in wrapper
    assert "NETWORK_ACCESS_TESTED=False" in wrapper
    assert "REAL_MODEL_PLANNING_TESTED=False" in wrapper
    assert "REAL_DEVICE_PATHS_TESTED=False" in wrapper
    assert "Phase 7 smoke forbids network access" in smoke
    for page in (
        "['/dashboard', '运营总览']",
        "['/operations-report', '安全运营报告']",
        "['/alerts', '实时告警']",
        "['/agents', '智能体与 ReAct 工作台']",
        "['/knowledge', '知识库工作台']",
        "['/response', '处置中心']",
        "['/reports', '历史报告']",
    ):
        assert page in smoke


def test_phase7_smoke_checks_sensitive_rendering_boundary() -> None:
    smoke = (ROOT / "frontend" / "src" / "test" / "phase7-smoke.test.tsx").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "raw_prompt",
        "chain_of_thought",
        "token_digest",
        "tenant_id",
        "principal_id",
    ):
        assert forbidden in smoke
    assert "fetchMock).toHaveBeenCalledTimes(3)" in smoke
    assert "expect.stringMatching(/^\\/api\\/v1\\//)" in smoke
