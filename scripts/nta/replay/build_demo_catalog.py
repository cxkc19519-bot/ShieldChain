"""Build an audited demo-replay allowlist from isolated Suricata detections."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACKNOWLEDGEMENT = "I_UNDERSTAND_ISOLATED_REPLAY"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("samples"), list):
        raise TypeError("demo replay manifest must contain a samples list")
    return payload


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def _event_summary(events_path: Path) -> tuple[str, tuple[str, ...]] | None:
    rows: list[dict[str, Any]] = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if isinstance(row, dict) and isinstance(row.get("rule_id"), str):
            rows.append(row)
    if not rows:
        return None
    rule_ids = tuple(sorted({str(row["rule_id"]) for row in rows}))
    title = str(rows[0].get("title") or "Suricata 检测场景")
    title = title.removeprefix("NTA 隔离回放：").strip()[:160]
    return title or "Suricata 检测场景", rule_ids


def build_catalog(
    *,
    manifest_path: Path,
    pcap_root: Path,
    output_root: Path,
    target_count: int,
    max_per_rule: int,
    candidate_limit: int,
    timeout: int,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve(strict=True)
    pcap_root = pcap_root.resolve(strict=True)
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    payload = _load_manifest(manifest_path)
    samples = payload["samples"]
    if len(samples) >= target_count:
        return {"status": "already_complete", "sample_count": len(samples)}

    existing_paths = {str(row.get("path")) for row in samples if isinstance(row, dict)}
    existing_hashes = {
        str(row.get("sha256")) for row in samples if isinstance(row, dict)
    }
    rule_counts: Counter[str] = Counter()
    for row in samples:
        if isinstance(row, dict):
            rule_counts.update(
                str(item)
                for item in row.get("expected_rule_ids", [])
                if isinstance(item, str)
            )

    repository = Path(__file__).resolve().parents[3]
    replay_script = repository / "scripts" / "nta" / "pcap_replay_lab.py"
    candidates = sorted(
        pcap_root.rglob("*.pcap"),
        key=lambda item: (item.stat().st_size, item.as_posix()),
    )
    checked = accepted = failed = no_detection = saturated = 0
    for candidate in candidates:
        if len(samples) >= target_count or checked >= candidate_limit:
            break
        relative = candidate.relative_to(pcap_root).as_posix()
        if relative in existing_paths:
            continue
        digest = _sha256(candidate)
        if digest in existing_hashes:
            continue
        checked += 1
        command = [
            sys.executable,
            str(replay_script),
            str(candidate),
            "--pcap-root",
            str(pcap_root),
            "--output-root",
            str(output_root),
            "--pps",
            "500",
            "--timeout",
            str(timeout),
            "--acknowledgement",
            ACKNOWLEDGEMENT,
        ]
        environment = dict(os.environ, SHIELDCHAIN_NTA_REPLAY_ENABLED="true")
        run_dir: Path | None = None
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout + 60,
                env=environment,
                check=False,
            )
            if completed.returncode:
                failed += 1
                continue
            run_dir = Path(completed.stdout.strip()).resolve(strict=True)
            summary = _event_summary(run_dir / "events.jsonl")
            if summary is None:
                no_detection += 1
                continue
            title, rule_ids = summary
            eligible = tuple(
                rule_id for rule_id in rule_ids if rule_counts[rule_id] < max_per_rule
            )
            if not eligible:
                saturated += 1
                continue
            sample_id = f"pcap-{digest[:16]}"
            samples.append(
                {
                    "id": sample_id,
                    "path": relative,
                    "title": title,
                    "sha256": digest,
                    "expected_rule_ids": list(rule_ids),
                }
            )
            existing_paths.add(relative)
            existing_hashes.add(digest)
            rule_counts.update(eligible)
            accepted += 1
            payload["catalog_updated_at"] = datetime.now(timezone.utc).isoformat()
            payload["catalog_validation"] = {
                "mode": "isolated_suricata_replay",
                "target_count": target_count,
                "max_samples_per_rule": max_per_rule,
            }
            _write_manifest(manifest_path, payload)
            print(
                json.dumps(
                    {
                        "checked": checked,
                        "accepted": accepted,
                        "sample_count": len(samples),
                        "rule_ids": eligible,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
            failed += 1
        finally:
            if run_dir is not None and run_dir.is_relative_to(output_root):
                shutil.rmtree(run_dir, ignore_errors=True)

    result = {
        "status": "completed" if len(samples) >= target_count else "target_not_reached",
        "sample_count": len(samples),
        "checked": checked,
        "accepted": accepted,
        "failed": failed,
        "no_detection": no_detection,
        "saturated": saturated,
    }
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate PCAPs with isolated Suricata and extend the demo replay allowlist"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pcap-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--target-count", type=int, default=100)
    parser.add_argument("--max-per-rule", type=int, default=12)
    parser.add_argument("--candidate-limit", type=int, default=2337)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--acknowledgement", required=True)
    args = parser.parse_args()
    if args.acknowledgement != ACKNOWLEDGEMENT:
        raise ValueError("explicit isolated replay acknowledgement is required")
    if not 1 <= args.target_count <= 500:
        raise ValueError("target-count must be between 1 and 500")
    if not 1 <= args.max_per_rule <= args.target_count:
        raise ValueError(
            "max-per-rule must be positive and no greater than target-count"
        )
    result = build_catalog(
        manifest_path=args.manifest,
        pcap_root=args.pcap_root,
        output_root=args.output_root,
        target_count=args.target_count,
        max_per_rule=args.max_per_rule,
        candidate_limit=args.candidate_limit,
        timeout=args.timeout,
    )
    return 0 if result["status"] in {"completed", "already_complete"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
