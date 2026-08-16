from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_phase8_smoke_is_offline_bounded_and_chains_prior_gate() -> None:
    wrapper = (ROOT / "tests" / "scripts" / "run-phase8-smoke.ps1").read_text(
        encoding="utf-8"
    )
    runner = (ROOT / "tests" / "scripts" / "phase8_smoke.py").read_text(
        encoding="utf-8"
    )
    assert "run-phase7-smoke.ps1" in wrapper
    assert "run-phase8-baseline.ps1" in wrapper
    assert "shieldchain-phase8-smoke-" in wrapper
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in wrapper
    assert "Planned release artifacts must not exist before finalization" in runner
    for flag in (
        "RUN_LIVE_DEEPSEEK_TEST",
        "RUN_LIVE_EMBEDDING_TEST",
        "RUN_LIVE_MILVUS_TEST",
        "RUN_LIVE_RERANKER_TEST",
    ):
        assert flag in wrapper


def test_unfinished_release_artifacts_remain_planned() -> None:
    manifest = json.loads((ROOT / "delivery" / "manifest.json").read_text("utf-8"))
    artifacts = {item["id"]: item for item in manifest["artifacts"]}
    assert {
        artifact_id
        for artifact_id, item in artifacts.items()
        if item["status"] == "planned"
    } == {"slides", "video", "submission-package", "submission-checksums"}
    for artifact_id in ("slides", "video", "submission-package", "submission-checksums"):
        assert not (ROOT / artifacts[artifact_id]["path"]).exists()


def test_submission_document_does_not_claim_final_artifacts_exist() -> None:
    report = ROOT / "docs" / "delivery" / "submission-package.md"
    assert report.is_file()
    content = report.read_text(encoding="utf-8")
    assert "当前仓库不保留半成品 PPT、演示视频、最终 ZIP 或校验和" in content


def test_package_builder_excludes_secrets_and_runtime_data() -> None:
    builder = (ROOT / "tests" / "scripts" / "build-phase8-package.ps1").read_text(
        encoding="utf-8"
    )
    assert "git" in builder and "ls-files" in builder
    assert "node_modules" in builder and "\\.env" in builder
    assert "\\.(db|sqlite|sqlite3)$" in builder
    assert "CreateEntry" in builder
