from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DELIVERY = ROOT / "docs" / "delivery"


def _read(name: str) -> str:
    return (DELIVERY / name).read_text(encoding="utf-8")


def test_delivery_documents_cover_required_topics_and_real_paths() -> None:
    documents = {
        "source-code-guide.md": ("backend/src/shieldchain/main.py", "frontend/src/app/"),
        "overall-design.md": ("ReAct", "FastAPI"),
        "development-guide.md": ("scripts\\verify.ps1", "requirements-runtime.lock"),
        "test-report.md": ("Task 13", "REAL_DEVICE_PATHS_TESTED=False"),
        "deployment-guide.md": ("docker compose up -d --build", "docker compose down -v"),
    }
    for name, required in documents.items():
        text = _read(name)
        assert text.startswith("# ")
        for phrase in required:
            assert phrase in text

    source = _read("source-code-guide.md")
    for path in (
        "backend/src/shieldchain/main.py",
        "frontend/src/app",
        "backend/migrations",
        "tests/scripts",
        "compose.yaml",
    ):
        assert (ROOT / path).exists()
        assert path in source


def test_reports_keep_unverified_boundaries_explicit() -> None:
    reports = _read("test-report.md") + _read("deployment-guide.md")
    for boundary in (
        "DOCKER_RUNTIME_TESTED=False",
        "NETWORK_ACCESS_TESTED=False",
        "REAL_MODEL_PLANNING_TESTED=False",
        "REAL_DEVICE_PATHS_TESTED=False",
    ):
        assert boundary in reports
    assert "REAL_IDENTITY_PLATFORM_TESTED=False" in reports
    assert "REAL_EXTERNAL_MCP_PEER_TESTED=False" in reports
