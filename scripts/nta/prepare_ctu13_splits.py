#!/usr/bin/env python3
"""Inventory CTU-13, adapt BinetFlow labels, and create scenario-level splits."""

from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

DATASET_ID = "ctu-13"
EXPECTED_COLUMNS = (
    "StartTime",
    "Dur",
    "Proto",
    "SrcAddr",
    "Sport",
    "Dir",
    "DstAddr",
    "Dport",
    "State",
    "sTos",
    "dTos",
    "TotPkts",
    "TotBytes",
    "SrcBytes",
    "Label",
)
DEFAULT_SPLITS = {
    "development": (1, 3, 5, 6, 7, 8, 12),
    "validation": (2, 4, 13),
    "final-blind": (9, 10, 11),
}


def coarse_label(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("flow="):
        normalized = normalized[5:]
    if "botnet" in normalized:
        return "botnet"
    if "normal" in normalized or "legitimate" in normalized:
        return "normal"
    if "background" in normalized:
        return "background"
    return "unknown"


def optional_port(value: str) -> int | str | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return value


def normalize_row(
    row: dict[str, str], *, scenario_id: int, row_number: int
) -> dict[str, object]:
    raw_label = row["Label"].strip()
    return {
        "dataset": DATASET_ID,
        "scenario_id": scenario_id,
        "row_number": row_number,
        "start_time": row["StartTime"].strip(),
        "duration_seconds": float(row["Dur"]),
        "protocol": row["Proto"].strip().lower(),
        "source_ip": row["SrcAddr"].strip(),
        "source_port": optional_port(row["Sport"]),
        "direction": row["Dir"].strip(),
        "destination_ip": row["DstAddr"].strip(),
        "destination_port": optional_port(row["Dport"]),
        "state": row["State"].strip(),
        "packets": int(row["TotPkts"]),
        "bytes": int(row["TotBytes"]),
        "source_bytes": int(row["SrcBytes"]),
        "raw_label": raw_label,
        "label": coarse_label(raw_label),
    }


def iter_normalized_flows(
    path: Path, *, scenario_id: int
) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8", errors="strict", newline="") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != EXPECTED_COLUMNS:
            raise ValueError(
                f"unexpected BinetFlow columns in {path}: {reader.fieldnames}"
            )
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"malformed BinetFlow row {row_number} in {path}")
            yield normalize_row(row, scenario_id=scenario_id, row_number=row_number)


def label_summary(path: Path, *, scenario_id: int) -> dict[str, object]:
    coarse: Counter[str] = Counter()
    raw: Counter[str] = Counter()
    rows = 0
    for flow in iter_normalized_flows(path, scenario_id=scenario_id):
        rows += 1
        coarse[str(flow["label"])] += 1
        raw[str(flow["raw_label"])] += 1
    return {
        "scenario_id": scenario_id,
        "rows": rows,
        "coarse_labels": dict(sorted(coarse.items())),
        "raw_labels": dict(sorted(raw.items())),
    }


def load_extraction_hashes(root: Path) -> dict[str, str]:
    manifest = root / "shieldchain-extraction-manifest.json"
    if not manifest.is_file():
        return {}
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    return {
        str(item["path"]): str(item["sha256"])
        for item in payload.get("extracted_files", [])
        if isinstance(item, dict) and item.get("path") and item.get("sha256")
    }


def file_record(path: Path, *, root: Path, hashes: dict[str, str]) -> dict[str, object]:
    relative = path.relative_to(root).as_posix()
    return {
        "path": relative,
        "bytes": path.stat().st_size,
        "sha256": hashes.get(relative),
    }


def discover_scenarios(root: Path) -> list[dict[str, object]]:
    dataset_root = root / "CTU-13-Dataset"
    if not dataset_root.is_dir():
        raise FileNotFoundError(f"CTU-13-Dataset directory not found under {root}")
    hashes = load_extraction_hashes(root)
    scenarios = []
    for scenario_id in range(1, 14):
        scenario_root = dataset_root / str(scenario_id)
        pcaps = sorted(scenario_root.glob("*.pcap"))
        flows = sorted(scenario_root.glob("*.binetflow"))
        readmes = sorted(scenario_root.glob("README*"))
        if len(pcaps) != 1 or len(flows) != 1 or len(readmes) != 1:
            raise ValueError(
                f"scenario {scenario_id} must contain exactly one PCAP, BinetFlow and README"
            )
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "pcap": file_record(pcaps[0], root=root, hashes=hashes),
                "binetflow": file_record(flows[0], root=root, hashes=hashes),
                "readme": file_record(readmes[0], root=root, hashes=hashes),
            }
        )
    return scenarios


def validate_splits(splits: dict[str, tuple[int, ...]], scenario_ids: set[int]) -> None:
    assigned = [scenario_id for values in splits.values() for scenario_id in values]
    duplicates = sorted({value for value in assigned if assigned.count(value) > 1})
    if duplicates:
        raise ValueError(f"scenario appears in multiple splits: {duplicates}")
    if set(assigned) != scenario_ids:
        missing = sorted(scenario_ids - set(assigned))
        extra = sorted(set(assigned) - scenario_ids)
        raise ValueError(f"split coverage mismatch; missing={missing}, extra={extra}")


def atomic_json(path: Path, payload: object, *, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temporary, mode)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_text(path: Path, value: str, *, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
        os.chmod(temporary, mode)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_manifests(
    root: Path,
    output_root: Path,
    label_root: Path | None = None,
    label_splits: tuple[str, ...] = ("development",),
) -> dict[str, object]:
    scenarios = discover_scenarios(root)
    by_id = {int(item["scenario_id"]): item for item in scenarios}
    validate_splits(DEFAULT_SPLITS, set(by_id))
    if label_splits and label_root is None:
        raise ValueError("label_root is required when label_splits are requested")
    label_payloads = {}
    for split_name in label_splits:
        if split_name not in DEFAULT_SPLITS:
            raise ValueError(f"unknown label split: {split_name}")
        summaries = []
        total: Counter[str] = Counter()
        for scenario_id in DEFAULT_SPLITS[split_name]:
            flow_path = root / str(by_id[scenario_id]["binetflow"]["path"])
            summary = label_summary(flow_path, scenario_id=scenario_id)
            summaries.append(summary)
            total.update(summary["coarse_labels"])
        label_payloads[split_name] = {
            "dataset": DATASET_ID,
            "split": split_name,
            "rows": sum(int(item["rows"]) for item in summaries),
            "coarse_labels": dict(sorted(total.items())),
            "scenarios": summaries,
        }

    inventory = {
        "dataset": DATASET_ID,
        "split_unit": "complete scenario",
        "scenarios": scenarios,
    }
    atomic_json(output_root / "inventory.json", inventory)
    for split_name, scenario_ids in DEFAULT_SPLITS.items():
        atomic_json(
            output_root / f"{split_name}.json",
            {
                "dataset": DATASET_ID,
                "split": split_name,
                "split_unit": "complete scenario",
                "labels_included": False,
                "scenario_ids": list(scenario_ids),
                "scenarios": [by_id[value] for value in scenario_ids],
            },
        )
        pcap_names = [
            Path(str(by_id[value]["pcap"]["path"])).name for value in scenario_ids
        ]
        atomic_text(
            output_root / f"{split_name}-pcaps.txt", "\n".join(pcap_names) + "\n"
        )
    for split_name, payload in label_payloads.items():
        atomic_json(label_root / f"{split_name}-labels.json", payload, mode=0o600)
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="safe CTU-13 extraction root")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--label-root", type=Path)
    parser.add_argument(
        "--label-splits",
        nargs="*",
        default=["development"],
        choices=tuple(DEFAULT_SPLITS),
        help="splits whose BinetFlow labels may be read (default: development only)",
    )
    args = parser.parse_args()
    inventory = build_manifests(
        args.root, args.output_root, args.label_root, tuple(args.label_splits)
    )
    print(
        json.dumps(
            {"dataset": DATASET_ID, "scenarios": len(inventory["scenarios"])}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
