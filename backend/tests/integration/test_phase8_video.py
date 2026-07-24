from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VIDEO_ROOT = ROOT / "video" / "shieldchain-demo"


def test_video_source_has_three_minute_hd_contract() -> None:
    root_source = (VIDEO_ROOT / "src" / "Root.tsx").read_text(encoding="utf-8")
    composition = (VIDEO_ROOT / "src" / "Composition.tsx").read_text(encoding="utf-8")

    assert "durationInFrames={5400}" in root_source
    assert "fps={30}" in root_source
    assert "width={1920}" in root_source
    assert "height={1080}" in root_source
    assert "useCurrentFrame" in composition
    assert "interpolate" in composition


def test_video_captions_cover_full_runtime_without_gaps() -> None:
    captions = json.loads(
        (VIDEO_ROOT / "public" / "captions.json").read_text(encoding="utf-8")
    )

    assert len(captions) == 20
    assert captions[0]["startMs"] == 0
    assert captions[-1]["endMs"] == 180_000
    assert all(item["endMs"] > item["startMs"] for item in captions)
    assert all(
        current["endMs"] == following["startMs"]
        for current, following in zip(captions, captions[1:])
    )


def test_video_delivery_is_documented_and_rendered() -> None:
    storyboard = (ROOT / "docs" / "delivery" / "video-storyboard.md").read_text(
        encoding="utf-8"
    )
    output = ROOT / "delivery" / "shieldchain-demo.mp4"

    assert "00:00–00:18" in storyboard
    assert "02:42–03:00" in storyboard
    assert "未内嵌配音音轨" in storyboard
    assert output.is_file()
    assert output.stat().st_size > 1_000_000


def test_video_styles_do_not_use_wall_clock_css_animation() -> None:
    styles = (VIDEO_ROOT / "src" / "index.css").read_text(encoding="utf-8").lower()

    assert "transition:" not in styles
    assert "animation:" not in styles
