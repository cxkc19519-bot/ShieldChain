from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[3]


def test_editable_presentation_is_a_ten_slide_widescreen_pptx() -> None:
    deck = ROOT / "delivery" / "shieldchain-presentation.pptx"
    assert deck.stat().st_size >= 40_000
    with ZipFile(deck) as archive:
        names = set(archive.namelist())
        slides = {
            name
            for name in names
            if name.startswith("ppt/slides/slide") and name.endswith(".xml")
        }
        assert len(slides) == 10
        presentation = archive.read("ppt/presentation.xml").decode("utf-8")
        assert 'cx="12192000"' in presentation
        assert 'cy="6858000"' in presentation
        assert "ppt/slideMasters/slideMaster1.xml" in names


def test_project_summary_matches_verified_evidence_and_boundaries() -> None:
    summary = (ROOT / "docs" / "delivery" / "project-summary.md").read_text(
        encoding="utf-8"
    )
    for evidence in (
        "1029 passed, 1 skipped",
        "90 tests passed",
        "2.499 ms",
        "0.114 ms",
        "DOCKER_RUNTIME_TESTED=False",
        "CI_RUNTIME_TESTED=False",
        "REAL_MODEL_PLANNING_TESTED=False",
        "REAL_DEVICE_PATHS_TESTED=False",
    ):
        assert evidence in summary
