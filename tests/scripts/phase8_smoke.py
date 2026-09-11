from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath


def validate(root: Path) -> dict[str, object]:
    manifest_path = root / "delivery" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    checked: list[str] = []
    planned: list[str] = []
    for item in artifacts:
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Unsafe delivery path: {relative}")
        target = root.joinpath(*relative.parts)
        if item["status"] == "available":
            if not target.is_file():
                raise FileNotFoundError(target)
            checked.append(relative.as_posix())
        elif item["status"] == "planned":
            if target.exists():
                raise ValueError(
                    "Planned release artifacts must not exist before finalization: "
                    f"{relative}"
                )
            planned.append(relative.as_posix())
        else:
            raise ValueError(f"Unsupported delivery status: {item['status']}")

    required_planned = {
        "delivery/shieldchain-presentation.pptx",
        "delivery/shieldchain-demo.mp4",
        "delivery/shieldchain-submission.zip",
        "delivery/submission-files.sha256",
    }
    if set(planned) != required_planned:
        raise ValueError("Unfinished release artifacts must remain explicitly planned")

    expected_boundaries = {
        "docker_runtime_tested": False,
        "network_access_tested": False,
        "real_model_planning_tested": False,
        "real_device_paths_tested": False,
    }
    if manifest["boundaries"] != expected_boundaries:
        raise ValueError("Final boundaries must remain explicit and truthful")
    return {"artifacts_checked": checked, "artifacts_planned": planned}


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
