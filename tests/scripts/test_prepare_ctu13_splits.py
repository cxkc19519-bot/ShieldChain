from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "nta" / "prepare_ctu13_splits.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_ctu13_splits", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

HEADER = ",".join(MODULE.EXPECTED_COLUMNS)
ROW = (
    "2011/08/10 09:46:59.607825,1.026539,tcp,10.0.0.1,1577,->,10.0.0.2,"
    "6881,S_RA,0,0,4,276,156,flow=Background-TCP-Established"
)


class PrepareCtu13SplitsTests(unittest.TestCase):
    def make_dataset(self, root: Path) -> None:
        extracted = []
        for scenario_id in range(1, 14):
            scenario = root / "CTU-13-Dataset" / str(scenario_id)
            scenario.mkdir(parents=True)
            files = {
                f"scenario-{scenario_id}.pcap": b"pcap",
                f"scenario-{scenario_id}.binetflow": f"{HEADER}\n{ROW}\n".encode(),
                "README": b"readme",
            }
            for name, content in files.items():
                path = scenario / name
                path.write_bytes(content)
                extracted.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "sha256": f"sha-{scenario_id}-{name}",
                    }
                )
        (root / "shieldchain-extraction-manifest.json").write_text(
            json.dumps({"extracted_files": extracted}), encoding="utf-8"
        )

    def test_coarse_labels(self) -> None:
        self.assertEqual(MODULE.coarse_label("flow=From-Botnet-V42-TCP"), "botnet")
        self.assertEqual(MODULE.coarse_label("flow=Normal-V42-HTTP"), "normal")
        self.assertEqual(
            MODULE.coarse_label("flow=Background-TCP-Attempt"), "background"
        )
        self.assertEqual(MODULE.coarse_label("other"), "unknown")

    def test_normalized_flow_types(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.binetflow"
            path.write_text(f"{HEADER}\n{ROW}\n", encoding="utf-8")
            flow = next(MODULE.iter_normalized_flows(path, scenario_id=3))
            self.assertEqual(flow["scenario_id"], 3)
            self.assertEqual(flow["source_port"], 1577)
            self.assertEqual(flow["packets"], 4)
            self.assertEqual(flow["label"], "background")

    def test_hex_and_named_ports_are_preserved(self) -> None:
        self.assertEqual(MODULE.optional_port("0x0303"), 771)
        self.assertEqual(MODULE.optional_port("http"), "http")

    def test_rejects_unexpected_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.binetflow"
            path.write_text("StartTime,Label\nx,flow=Botnet\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected BinetFlow columns"):
                list(MODULE.iter_normalized_flows(path, scenario_id=1))

    def test_default_splits_cover_scenarios_without_overlap(self) -> None:
        MODULE.validate_splits(MODULE.DEFAULT_SPLITS, set(range(1, 14)))
        values = [value for split in MODULE.DEFAULT_SPLITS.values() for value in split]
        self.assertEqual(len(values), len(set(values)))

    def test_builds_manifests_and_reads_development_labels_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dataset"
            output = Path(temporary) / "splits"
            labels = Path(temporary) / "labels"
            self.make_dataset(root)
            MODULE.build_manifests(root, output, labels, ("development",))
            inventory = json.loads(
                (output / "inventory.json").read_text(encoding="utf-8")
            )
            development = json.loads(
                (output / "development.json").read_text(encoding="utf-8")
            )
            label_report = json.loads(
                (labels / "development-labels.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(inventory["scenarios"]), 13)
            self.assertTrue(
                inventory["scenarios"][0]["pcap"]["sha256"].startswith("sha-1-")
            )
            self.assertEqual(development["scenario_ids"], [1, 3, 5, 6, 7, 8, 12])
            self.assertEqual(
                (output / "development-pcaps.txt")
                .read_text(encoding="utf-8")
                .splitlines(),
                [f"scenario-{value}.pcap" for value in [1, 3, 5, 6, 7, 8, 12]],
            )
            self.assertEqual(label_report["rows"], 7)
            self.assertFalse((labels / "validation-labels.json").exists())
            self.assertFalse((labels / "final-blind-labels.json").exists())

    def test_label_failure_does_not_write_split_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dataset"
            output = Path(temporary) / "splits"
            labels = Path(temporary) / "labels"
            self.make_dataset(root)
            flow = next((root / "CTU-13-Dataset" / "1").glob("*.binetflow"))
            flow.write_text("StartTime,Label\nx,flow=Botnet\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected BinetFlow columns"):
                MODULE.build_manifests(root, output, labels, ("development",))
            self.assertFalse(output.exists())
            self.assertFalse(labels.exists())

    def test_rejects_split_overlap(self) -> None:
        with self.assertRaisesRegex(ValueError, "multiple splits"):
            MODULE.validate_splits({"a": (1, 2), "b": (2, 3)}, {1, 2, 3})


if __name__ == "__main__":
    unittest.main()
