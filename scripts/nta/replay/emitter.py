"""Minimal fixed-rate classic-PCAP emitter for an isolated Linux interface."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path


MAGIC_ENDIAN = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
    b"\x4d\x3c\xb2\xa1": "<",
}
MAX_FRAME_BYTES = 262_144


def iter_frames(path: Path) -> Iterator[bytes]:
    with path.open("rb") as stream:
        global_header = stream.read(24)
        if len(global_header) != 24 or global_header[:4] not in MAGIC_ENDIAN:
            raise ValueError("input must be a complete classic PCAP capture")
        endian = MAGIC_ENDIAN[global_header[:4]]
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            _, _, captured_length, _ = struct.unpack(f"{endian}IIII", packet_header)
            if captured_length <= 0 or captured_length > MAX_FRAME_BYTES:
                raise ValueError("invalid PCAP captured frame length")
            frame = stream.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError("truncated PCAP frame")
            yield frame


def replay(path: Path, interface: str, pps: int, loops: int) -> dict[str, object]:
    if interface != "eth0":
        raise ValueError("the isolated replay image only permits eth0")
    interval = 1.0 / pps
    packets = 0
    bytes_sent = 0
    started = time.monotonic()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
        sender.bind((interface, 0))
        deadline = time.monotonic()
        for _ in range(loops):
            for frame in iter_frames(path):
                now = time.monotonic()
                if deadline > now:
                    time.sleep(deadline - now)
                bytes_sent += sender.send(frame)
                packets += 1
                deadline += interval
    return {
        "packets_sent": packets,
        "bytes_sent": bytes_sent,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "interface": interface,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--interface", choices=("eth0",), default="eth0")
    parser.add_argument("--pps", type=int, required=True)
    parser.add_argument("--loops", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.pps <= 100_000:
        raise ValueError("pps must be between 1 and 100000")
    if not 1 <= args.loops <= 10:
        raise ValueError("loops must be between 1 and 10")
    print(json.dumps(replay(args.pcap, args.interface, args.pps, args.loops)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
