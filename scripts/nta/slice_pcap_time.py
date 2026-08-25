#!/usr/bin/env python3
"""Stream a classic PCAP once and write deterministic absolute-time slices."""

from __future__ import annotations

import argparse
import json
import re
import struct
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from typing import NamedTuple


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_CAPTURED_PACKET = 64 * 1024 * 1024


class Window(NamedTuple):
    name: str
    start: float
    finish: float


def parse_window(value: str) -> Window:
    try:
        name, start_text, finish_text = value.split(",", 2)
        start = datetime.fromisoformat(start_text)
        finish = datetime.fromisoformat(finish_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "window must be NAME,START_ISO,FINISH_ISO"
        ) from exc
    if not SAFE_NAME.fullmatch(name):
        raise argparse.ArgumentTypeError("window name contains unsafe characters")
    if start.tzinfo is None or finish.tzinfo is None:
        raise argparse.ArgumentTypeError("window timestamps must include UTC offsets")
    if finish <= start:
        raise argparse.ArgumentTypeError("window finish must be after start")
    return Window(name, start.timestamp(), finish.timestamp())


def slice_pcap(
    source: Path,
    output_dir: Path,
    windows: list[Window],
    *,
    allow_truncated_tail: bool = False,
) -> dict[str, object]:
    if not windows:
        raise ValueError("at least one time window is required")
    if len({window.name for window in windows}) != len(windows):
        raise ValueError("window names must be unique")
    output_dir.mkdir(parents=True, exist_ok=True)
    counters = {window.name: {"packets": 0, "captured_bytes": 0} for window in windows}
    truncated_tail = False
    with source.open("rb") as stream, ExitStack() as stack:
        global_header = stream.read(24)
        if len(global_header) != 24 or global_header[:4] not in MAGIC:
            raise ValueError("only classic PCAP files are supported")
        byte_order, resolution = MAGIC[global_header[:4]]
        packet_struct = struct.Struct(f"{byte_order}IIII")
        outputs = {
            window.name: stack.enter_context(
                (output_dir / f"{window.name}.pcap").open("wb")
            )
            for window in windows
        }
        for output in outputs.values():
            output.write(global_header)
        while header := stream.read(16):
            if len(header) != 16:
                if allow_truncated_tail:
                    truncated_tail = True
                    break
                raise ValueError("truncated PCAP packet header")
            seconds, fraction, captured_length, _ = packet_struct.unpack(header)
            if captured_length > MAX_CAPTURED_PACKET:
                raise ValueError(
                    f"implausible captured packet length: {captured_length}"
                )
            packet = stream.read(captured_length)
            if len(packet) != captured_length:
                if allow_truncated_tail:
                    truncated_tail = True
                    break
                raise ValueError("truncated PCAP packet payload")
            timestamp = seconds + fraction / resolution
            for window in windows:
                if window.start <= timestamp < window.finish:
                    outputs[window.name].write(header)
                    outputs[window.name].write(packet)
                    counters[window.name]["packets"] += 1
                    counters[window.name]["captured_bytes"] += captured_length
    return {
        "source": str(source),
        "source_size": source.stat().st_size,
        "truncated_tail_discarded": truncated_tail,
        "windows": [
            {
                "name": window.name,
                "start_epoch": window.start,
                "finish_epoch": window.finish,
                **counters[window.name],
                "output": str(output_dir / f"{window.name}.pcap"),
            }
            for window in windows
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--window", action="append", type=parse_window, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--allow-truncated-tail",
        action="store_true",
        help="discard only a final incomplete record and disclose it in the manifest",
    )
    args = parser.parse_args()
    report = slice_pcap(
        args.source,
        args.output_dir,
        args.window,
        allow_truncated_tail=args.allow_truncated_tail,
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
