from __future__ import annotations

import hashlib
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
    assert "Every final delivery artifact must be available" in runner
    for flag in (
        "RUN_LIVE_DEEPSEEK_TEST",
        "RUN_LIVE_EMBEDDING_TEST",
        "RUN_LIVE_MILVUS_TEST",
        "RUN_LIVE_RERANKER_TEST",
    ):
        assert flag in wrapper


def test_final_manifest_has_no_planned_artifacts() -> None:
    manifest = json.loads((ROOT / "delivery" / "manifest.json").read_text("utf-8"))
    assert all(item["status"] == "available" for item in manifest["artifacts"])
    assert all(value is False for value in manifest["boundaries"].values())


def test_submission_package_and_checksums_are_reproducible() -> None:
    package = ROOT / "delivery" / "shieldchain-submission.zip"
    checksums = ROOT / "delivery" / "submission-files.sha256"
    report = ROOT / "docs" / "delivery" / "submission-package.md"
    assert package.is_file() and package.stat().st_size > 1_000_000
    assert checksums.is_file()
    assert report.is_file()

    entries = {}
    for line in checksums.read_text(encoding="utf-8-sig").splitlines():
        digest, relative = line.split("  ", maxsplit=1)
        entries[relative] = digest
    for relative in (
        "delivery/shieldchain-presentation.pptx",
        "delivery/shieldchain-submission.zip",
    ):
        content = (ROOT / relative).read_bytes()
        assert entries[relative] == hashlib.sha256(content).hexdigest()


def test_package_builder_excludes_secrets_and_runtime_data() -> None:
    builder = (ROOT / "tests" / "scripts" / "build-phase8-package.ps1").read_text(
        encoding="utf-8"
    )
    assert "git" in builder and "ls-files" in builder
    assert "node_modules" in builder and "\\.env" in builder
    assert "\\.(db|sqlite|sqlite3)$" in builder
    assert "CreateEntry" in builder
