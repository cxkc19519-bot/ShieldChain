import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]


def test_delivery_manifest_has_every_required_artifact_and_truthful_status() -> None:
    manifest = json.loads((ROOT / "delivery" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "shieldchain.delivery-manifest/v1"
    artifacts = manifest["artifacts"]
    assert {item["id"] for item in artifacts} == {
        "source",
        "design",
        "source-guide",
        "development",
        "container-deployment",
        "testing",
        "performance-baseline",
        "summary",
        "deployment",
        "query-performance",
        "slides",
        "video",
    }
    for artifact in artifacts:
        assert set(artifact) == {"id", "path", "status"}
        assert artifact["status"] in {"available", "planned"}
        path = PurePosixPath(artifact["path"])
        assert not path.is_absolute() and ".." not in path.parts
        if artifact["status"] == "available":
            assert (ROOT / Path(*path.parts)).is_file()
    assert manifest["boundaries"] == {
        "network_access_tested": False,
        "real_model_planning_tested": False,
        "docker_runtime_tested": False,
        "real_device_paths_tested": False,
    }


def test_baseline_wrapper_is_offline_bounded_and_safely_cleans_up() -> None:
    wrapper = (ROOT / "tests" / "scripts" / "run-phase8-baseline.ps1").read_text(
        encoding="utf-8"
    )
    runner = (ROOT / "tests" / "scripts" / "phase8_baseline.py").read_text(
        encoding="utf-8"
    )
    assert "shieldchain-phase8-baseline-" in wrapper
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in wrapper
    for flag in (
        "RUN_LIVE_DEEPSEEK_TEST",
        "RUN_LIVE_EMBEDDING_TEST",
        "RUN_LIVE_MILVUS_TEST",
        "RUN_LIVE_RERANKER_TEST",
    ):
        assert flag in wrapper
    assert "TestClient(create_app())" in runner
    assert "load_evaluation_dataset" in runner
    assert '"sample_count"' in (
        ROOT / "tests" / "fixtures" / "quality" / "phase8_baseline_v1.json"
    ).read_text(encoding="utf-8")
