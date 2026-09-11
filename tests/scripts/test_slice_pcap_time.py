from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "nta" / "slice_pcap_time.py"
)
SPEC = importlib.util.spec_from_file_location("slice_pcap_time", MODULE_PATH)
assert SPEC and SPEC.loader
slicer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(slicer)


def write_pcap(path: Path, timestamps: list[float]) -> None:
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for timestamp in timestamps:
            seconds = int(timestamp)
            micros = int((timestamp - seconds) * 1_000_000)
            payload = b"packet"
            stream.write(
                struct.pack("<IIII", seconds, micros, len(payload), len(payload))
            )
            stream.write(payload)


class SlicePcapTests(unittest.TestCase):
    def test_single_pass_writes_only_half_open_window_packets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.pcap"
            write_pcap(source, [100.0, 105.5, 110.0, 120.0])
            report = slicer.slice_pcap(
                source,
                root / "out",
                [slicer.Window("attack", 105.0, 120.0)],
            )

            self.assertEqual(report["windows"][0]["packets"], 2)
            self.assertEqual((root / "out" / "attack.pcap").stat().st_size, 68)

    def test_truncated_tail_requires_explicit_opt_in_and_is_disclosed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input.pcap"
            write_pcap(source, [100.0, 105.0])
            with source.open("ab") as stream:
                stream.write(struct.pack("<IIII", 110, 0, 100, 100))
                stream.write(b"partial")
            window = [slicer.Window("all", 90.0, 120.0)]

            with self.assertRaisesRegex(ValueError, "truncated PCAP packet payload"):
                slicer.slice_pcap(source, root / "strict", window)
            report = slicer.slice_pcap(
                source,
                root / "allowed",
                window,
                allow_truncated_tail=True,
            )

            self.assertTrue(report["truncated_tail_discarded"])
            self.assertEqual(report["windows"][0]["packets"], 2)

    def test_parse_window_requires_timezone_and_safe_name(self) -> None:
        window = slicer.parse_window(
            "udp,2018-02-21T10:09:00+00:00,2018-02-21T10:19:00+00:00"
        )
        self.assertEqual(window.name, "udp")
        self.assertEqual(
            window.start,
            datetime(2018, 2, 21, 10, 9, tzinfo=timezone.utc).timestamp(),
        )
        with self.assertRaises(Exception):
            slicer.parse_window(
                "../bad,2018-02-21T10:09:00+00:00,2018-02-21T10:19:00+00:00"
            )
        with self.assertRaises(Exception):
            slicer.parse_window("bad,2018-02-21T10:09:00,2018-02-21T10:19:00")


if __name__ == "__main__":
    unittest.main()
