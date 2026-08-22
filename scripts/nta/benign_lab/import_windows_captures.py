#!/usr/bin/env python3
"""Validate and import Windows benign PCAPs without exposing held-out labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from windows_capture_plan import select_windows_scenarios


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_records(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise FileNotFoundError(f"capture record is missing: {path}")
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"record {line_number} is not an object")
        records.append(row)
    return records


def validate_source(
    source: Path,
    split: str,
    allow_held_out: bool = False,
    require_complete: bool = True,
) -> list[dict[str, object]]:
    expected_rows = select_windows_scenarios(split, allow_held_out)
    expected = {row.scenario_id: row for row in expected_rows}
    records = read_records(source / "windows-captures.jsonl")
    seen: set[str] = set()
    for record in records:
        scenario_id = str(record.get("scenario_id", ""))
        if scenario_id not in expected:
            raise ValueError(f"unexpected scenario for {split}: {scenario_id!r}")
        if scenario_id in seen:
            raise ValueError(f"duplicate capture record: {scenario_id}")
        seen.add(scenario_id)
        scenario = expected[scenario_id]
        if record.get("pcap_name") != scenario.pcap_name:
            raise ValueError(f"anonymous PCAP name mismatch for {scenario_id}")
        pcap = source / "pcap" / scenario.pcap_name
        if not pcap.is_file() or pcap.stat().st_size <= 24:
            raise ValueError(f"missing or empty PCAP for {scenario_id}: {pcap}")
        if record.get("sha256") != sha256_file(pcap):
            raise ValueError(f"SHA-256 mismatch for {scenario_id}")
        if int(record.get("bytes", -1)) != pcap.stat().st_size:
            raise ValueError(f"byte-size mismatch for {scenario_id}")
    missing = sorted(set(expected) - seen)
    if require_complete and missing:
        raise ValueError(f"capture set is incomplete; missing {len(missing)} scenarios")
    return records


def import_source(source: Path, destination: Path, records: list[dict[str, object]]) -> None:
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite destination: {destination}")
    (destination / "pcap").mkdir(parents=True)
    for record in records:
        name = str(record["pcap_name"])
        shutil.copy2(source / "pcap" / name, destination / "pcap" / name)
    shutil.copy2(source / "windows-captures.jsonl", destination / "windows-captures.jsonl")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--split", choices=("development", "validation", "final_blind"), default="development")
    parser.add_argument("--allow-held-out", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    records = validate_source(
        args.source,
        args.split,
        allow_held_out=args.allow_held_out,
        require_complete=not args.allow_partial,
    )
    if not args.validate_only:
        import_source(args.source, args.destination, records)
    print(f"validated {len(records)} Windows {args.split} captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
