#!/usr/bin/env python3
"""Inspect or safely extract the network-analysis subset of CTU-13."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath

EXPECTED_BYTES = 1_997_547_391
ALLOWED_SUFFIXES = {".biargus", ".binetflow", ".cap", ".csv", ".md", ".pcap", ".txt"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive path: {name!r}")
    return path


def selected_file(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return name.startswith("readme") or Path(name).suffix in ALLOWED_SUFFIXES


def inspect_archive(
    archive: Path,
    *,
    expected_bytes: int = EXPECTED_BYTES,
    expected_sha256: str | None = None,
    max_members: int = 20_000,
    max_selected_bytes: int = 100 * 1024**3,
) -> tuple[list[tuple[tarfile.TarInfo, PurePosixPath]], dict[str, object]]:
    if not archive.is_file():
        raise FileNotFoundError(archive)
    if archive.stat().st_size != expected_bytes:
        raise ValueError(f"unexpected archive size: {archive.stat().st_size}; expected {expected_bytes}")
    archive_sha256 = sha256(archive)
    if expected_sha256 and archive_sha256.lower() != expected_sha256.lower():
        raise ValueError("archive SHA-256 does not match --expected-sha256")

    selected: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    selected_suffixes: Counter[str] = Counter()
    skipped_suffixes: Counter[str] = Counter()
    seen: set[PurePosixPath] = set()
    selected_bytes = 0
    member_count = 0
    with tarfile.open(archive, "r:bz2") as bundle:
        for member in bundle:
            member_count += 1
            if member_count > max_members:
                raise ValueError(f"archive exceeds member limit: {max_members}")
            relative = safe_path(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError(f"links and device members are forbidden: {member.name!r}")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"unsupported archive member: {member.name!r}")
            if relative in seen:
                raise ValueError(f"duplicate archive path: {member.name!r}")
            seen.add(relative)
            suffix = Path(relative.name.lower()).suffix or "<no-suffix>"
            if not selected_file(relative):
                skipped_suffixes[suffix] += 1
                continue
            selected_bytes += member.size
            if selected_bytes > max_selected_bytes:
                raise ValueError("selected files exceed expanded-size limit")
            selected_suffixes[suffix] += 1
            selected.append((member, relative))

    report: dict[str, object] = {
        "dataset_id": "ctu-13",
        "archive": str(archive.resolve()),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": archive_sha256,
        "archive_members": member_count,
        "selected_files": len(selected),
        "selected_bytes": selected_bytes,
        "selected_suffixes": dict(sorted(selected_suffixes.items())),
        "skipped_files": sum(skipped_suffixes.values()),
        "skipped_suffixes": dict(sorted(skipped_suffixes.items())),
        "selection_policy": "PCAP, flow labels and documentation only; executable payloads excluded",
    }
    return selected, report


def extract_selected(archive: Path, output: Path, selected, report) -> dict[str, object]:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-staging-", dir=output.parent))
    extracted = []
    try:
        selected_by_name = {member.name: relative for member, relative in selected}
        with tarfile.open(archive, "r:bz2") as bundle:
            for member in bundle:
                relative = selected_by_name.get(member.name)
                if relative is None:
                    continue
                target = staging.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError(f"cannot read selected member: {member.name!r}")
                digest = hashlib.sha256()
                written = 0
                with source, target.open("xb") as destination:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        destination.write(block)
                        digest.update(block)
                        written += len(block)
                if written != member.size:
                    raise ValueError(f"short archive member: {member.name!r}")
                os.chmod(target, 0o440)
                extracted.append(
                    {"path": relative.as_posix(), "bytes": written, "sha256": digest.hexdigest()}
                )
        manifest = dict(report)
        manifest["extracted_files"] = extracted
        manifest_path = staging / "shieldchain-extraction-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o440)
        staging.rename(output)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect CTU-13 or safely extract network-analysis artifacts")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--extract-to", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    selected, report = inspect_archive(args.archive, expected_sha256=args.expected_sha256)
    if args.extract_to:
        report = extract_selected(args.archive, args.extract_to, selected, report)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
