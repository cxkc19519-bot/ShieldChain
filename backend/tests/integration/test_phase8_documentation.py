from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DELIVERY = ROOT / "docs" / "delivery"


def _read(name: str) -> str:
    return (DELIVERY / name).read_text(encoding="utf-8")


def test_delivery_documents_cover_required_topics_and_real_paths() -> None:
    documents = {
        "source-code-guide.md": ("backend/src/shieldchain/main.py", "frontend/src/main.tsx"),
        "overall-design.md": ("ReAct", "readiness"),
        "development-guide.md": ("scripts\\verify.ps1", "requirements-runtime.lock"),
        "test-report.md": ("1029 passed, 1 skipped", "90 tests passed"),
        "deployment-guide.md": ("docker compose up --build", "docker compose down -v"),
    }
    for name, required in documents.items():
        text = _read(name)
        assert text.startswith("# ShieldChain")
        for phrase in required:
            assert phrase in text

    source = _read("source-code-guide.md")
    for path in (
        "backend/src/shieldchain/main.py",
        "frontend/src/main.tsx",
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
    assert "CI_RUNTIME_TESTED=False" in reports
