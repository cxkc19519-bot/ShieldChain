from __future__ import annotations

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "nta"
    / "generate_benign_fixture.py"
)
SPEC = importlib.util.spec_from_file_location("generate_benign_fixture", MODULE_PATH)
assert SPEC and SPEC.loader
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class GenerateBenignFixtureTests(unittest.TestCase):
    def test_generates_ethernet_pcap_with_expected_packet_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "benign.pcap"
            packet_count = fixture.build_fixture(output)

            self.assertEqual(packet_count, 65)
            self.assertGreater(output.stat().st_size, 40_000)
            magic, major, minor = struct.unpack("<IHH", output.read_bytes()[:8])
            self.assertEqual(magic, 0xA1B2C3D4)
            self.assertEqual((major, minor), (2, 4))


if __name__ == "__main__":
    unittest.main()
