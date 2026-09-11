#!/usr/bin/env python3
"""Build and validate the Windows benign-capture execution plan."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from scenario_catalog import Scenario, build_catalog, validate_catalog

SUPPORTED_SPLITS = ("development", "validation", "final_blind")
WINDOWS_PROTOCOL = "windows_admin"


def select_windows_scenarios(split: str, allow_held_out: bool = False) -> list[Scenario]:
    if split not in SUPPORTED_SPLITS:
        raise ValueError(f"unsupported split: {split}")
    if split != "development" and not allow_held_out:
        raise PermissionError(
            f"refusing protected split {split!r}; freeze rules and pass --allow-held-out"
        )
    rows = build_catalog()
    validate_catalog(rows)
    return [row for row in rows if row.protocol == WINDOWS_PROTOCOL and row.split == split]


def write_plan(output: Path, rows: list[Scenario]) -> None:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite capture plan: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "protocol": WINDOWS_PROTOCOL,
        "split": rows[0].split if rows else None,
        "scenario_count": len(rows),
        "scenarios": [asdict(row) for row in rows],
    }
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--split", choices=SUPPORTED_SPLITS, default="development")
    parser.add_argument("--allow-held-out", action="store_true")
    args = parser.parse_args()
    rows = select_windows_scenarios(args.split, args.allow_held_out)
    write_plan(args.output, rows)
    print(f"wrote {len(rows)} Windows {args.split} scenarios to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
