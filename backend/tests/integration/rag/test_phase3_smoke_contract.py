from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_phase3_smoke_is_offline_bounded_and_cleans_its_temporary_state() -> None:
    script = (ROOT / "tests" / "scripts" / "run-phase3-smoke.ps1").read_text(
        encoding="utf-8"
    )
    harness = (ROOT / "tests" / "scripts" / "phase3_smoke.py").read_text(encoding="utf-8")

    assert '$ErrorActionPreference = "Stop"' in script
    assert "Set-StrictMode" in script
    assert "[System.IO.Path]::GetTempPath()" in script
    assert "Remove-Item -LiteralPath $temporaryRoot -Recurse -Force" in script
    for flag in (
        "RUN_LIVE_DEEPSEEK_TEST",
        "RUN_LIVE_EMBEDDING_TEST",
        "RUN_LIVE_MILVUS_TEST",
        "RUN_LIVE_RERANKER_TEST",
    ):
        assert flag in script
    assert "Refusing to clean an unexpected Phase 3 temporary path." in script
    assert "REAL_CLOUD_PATHS_TESTED=False" in script
    assert "http://" not in script + harness
    assert "https://" not in script + harness
    assert "requests." not in harness and "httpx." not in harness


def test_phase3_harness_exercises_product_modules_not_a_fake_http_response() -> None:
    harness = (ROOT / "tests" / "scripts" / "phase3_smoke.py").read_text(encoding="utf-8")

    required = (
        "SecureIntake",
        "BoundedDocumentParser",
        "DeterministicChunker",
        "DeepSeekSemanticChunker",
        "IndexingService",
        "DeepSeekQueryRewriter",
        "HybridRetrievalService",
        "RerankingService",
        "CitationAssembler",
        "GroundedAnsweringService",
        "sqlite3.connect",
    )
    assert all(name in harness for name in required)
    assert "StructuredRefusal" in harness
    assert "OfflineMilvusClient" in harness
    assert "OfflineEmbedding" in harness
