from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path, PurePosixPath


def validate(root: Path) -> dict[str, object]:
    manifest_path = root / "delivery" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    if any(item["status"] != "available" for item in artifacts):
        raise ValueError("Every final delivery artifact must be available")

    checked: list[str] = []
    for item in artifacts:
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Unsafe delivery path: {relative}")
        target = root.joinpath(*relative.parts)
        if not target.is_file():
            raise FileNotFoundError(target)
        checked.append(relative.as_posix())

    slides = root / "delivery" / "shieldchain-presentation.pptx"
    with zipfile.ZipFile(slides) as archive:
        slide_count = sum(
            name.startswith("ppt/slides/slide") and name.endswith(".xml")
            for name in archive.namelist()
        )
    if slide_count != 10:
        raise ValueError(f"Expected 10 slides, found {slide_count}")

    video = root / "delivery" / "shieldchain-demo.mp4"
    if video.stat().st_size <= 1_000_000 or b"ftyp" not in video.read_bytes()[:64]:
        raise ValueError("Rendered MP4 is missing or invalid")

    captions = json.loads(
        (root / "video" / "shieldchain-demo" / "public" / "captions.json").read_text(
            encoding="utf-8"
        )
    )
    if captions[0]["startMs"] != 0 or captions[-1]["endMs"] != 180_000:
        raise ValueError("Captions do not cover the full three-minute runtime")
    if any(a["endMs"] != b["startMs"] for a, b in zip(captions, captions[1:])):
        raise ValueError("Caption timeline contains a gap or overlap")

    expected_boundaries = {
        "docker_runtime_tested": False,
        "network_access_tested": False,
        "real_model_planning_tested": False,
        "real_device_paths_tested": False,
    }
    if manifest["boundaries"] != expected_boundaries:
        raise ValueError("Final boundaries must remain explicit and truthful")
    return {"artifacts_checked": checked, "slides": slide_count, "caption_end_ms": 180_000}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.root.resolve())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
