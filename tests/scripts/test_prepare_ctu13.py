from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "nta" / "prepare_ctu13.py"
SPEC = importlib.util.spec_from_file_location("prepare_ctu13", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def add_bytes(bundle: tarfile.TarFile, name: str, value: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    bundle.addfile(info, io.BytesIO(value))


class PrepareCtu13Tests(unittest.TestCase):
    def make_archive(self, root: Path, members: dict[str, bytes]) -> Path:
        archive = root / "fixture.tar.bz2"
        with tarfile.open(archive, "w:bz2") as bundle:
            for name, value in members.items():
                add_bytes(bundle, name, value)
        return archive

    def inspect(self, archive: Path, **kwargs):
        return MODULE.inspect_archive(archive, expected_bytes=archive.stat().st_size, **kwargs)

    def test_selects_network_files_and_skips_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.make_archive(Path(temporary), {
                "CTU-13/1/capture.pcap": b"pcap",
                "CTU-13/1/labels.binetflow": b"labels",
                "CTU-13/1/README.txt": b"readme",
                "CTU-13/1/malware.exe": b"payload",
            })
            selected, report = self.inspect(archive)
            self.assertEqual(len(selected), 3)
            self.assertEqual(report["skipped_suffixes"], {".exe": 1})

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.make_archive(Path(temporary), {"../escape.pcap": b"x"})
            with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                self.inspect(archive)

    def test_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture.tar.bz2"
            with tarfile.open(archive, "w:bz2") as bundle:
                info = tarfile.TarInfo("CTU-13/link.pcap")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                bundle.addfile(info)
            with self.assertRaisesRegex(ValueError, "forbidden"):
                self.inspect(archive)

    def test_extracts_manifest_without_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.make_archive(root, {
                "CTU-13/1/capture.pcap": b"pcap",
                "CTU-13/1/malware.exe": b"payload",
            })
            selected, report = self.inspect(archive)
            output = root / "output"
            MODULE.extract_selected(archive, output, selected, report)
            self.assertEqual((output / "CTU-13/1/capture.pcap").read_bytes(), b"pcap")
            self.assertFalse((output / "CTU-13/1/malware.exe").exists())
            self.assertTrue((output / "shieldchain-extraction-manifest.json").is_file())

    def test_rejects_wrong_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = self.make_archive(Path(temporary), {"capture.pcap": b"pcap"})
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.inspect(archive, expected_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
