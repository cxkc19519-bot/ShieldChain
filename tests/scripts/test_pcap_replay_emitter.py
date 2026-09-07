from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "nta" / "replay" / "emitter.py"
SPEC = importlib.util.spec_from_file_location("pcap_replay_emitter", MODULE_PATH)
assert SPEC and SPEC.loader
emitter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = emitter
SPEC.loader.exec_module(emitter)


def write_capture(path: Path, frames: list[bytes]) -> None:
    content = bytearray(b"\xd4\xc3\xb2\xa1")
    content.extend(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for frame in frames:
        content.extend(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
        content.extend(frame)
    path.write_bytes(content)


def test_iter_frames_reads_classic_pcap_without_loading_it_all() -> None:
    with tempfile.TemporaryDirectory() as temp:
        capture = Path(temp) / "sample.pcap"
        write_capture(capture, [b"first", b"second"])

        assert list(emitter.iter_frames(capture)) == [b"first", b"second"]


def test_iter_frames_rejects_truncated_frame() -> None:
    with tempfile.TemporaryDirectory() as temp:
        capture = Path(temp) / "sample.pcap"
        write_capture(capture, [b"frame"])
        capture.write_bytes(capture.read_bytes()[:-1])

        with pytest.raises(ValueError, match="truncated PCAP frame"):
            list(emitter.iter_frames(capture))


def test_replay_rejects_any_interface_except_isolated_eth0() -> None:
    with pytest.raises(ValueError, match="only permits eth0"):
        emitter.replay(Path("unused.pcap"), "ens3", 500, 1)
