from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts" / "nta" / "benign_lab" / "scenario_catalog.py"
)
SPEC = importlib.util.spec_from_file_location("scenario_catalog", MODULE_PATH)
assert SPEC and SPEC.loader
scenario_catalog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scenario_catalog
SPEC.loader.exec_module(scenario_catalog)


class BenignScenarioCatalogTests(unittest.TestCase):
    def test_catalog_has_expected_protocol_and_split_counts(self) -> None:
        rows = scenario_catalog.build_catalog()
        scenario_catalog.validate_catalog(rows)
        self.assertEqual(Counter(row.protocol for row in rows), scenario_catalog.EXPECTED_COUNTS)
        self.assertEqual(
            Counter(row.split for row in rows),
            {"development": 180, "validation": 60, "final_blind": 60},
        )

    def test_related_variants_never_cross_splits(self) -> None:
        groups: dict[str, set[str]] = defaultdict(set)
        for row in scenario_catalog.build_catalog():
            groups[row.group_id].add(row.split)
        self.assertTrue(all(len(splits) == 1 for splits in groups.values()))

    def test_pcap_names_do_not_reveal_labels(self) -> None:
        for row in scenario_catalog.build_catalog():
            lowered = row.pcap_name.lower()
            self.assertNotIn("benign", lowered)
            self.assertNotIn(row.protocol.lower(), lowered)
            self.assertRegex(row.pcap_name, r"^b-[0-9a-f]{16}\.pcap$")

    def test_writer_creates_complete_manifests(self) -> None:
        rows = scenario_catalog.build_catalog()
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp)
            scenario_catalog.write_catalog(destination, rows)
            self.assertEqual(len((destination / "development.txt").read_text().splitlines()), 180)
            self.assertEqual(len((destination / "validation.txt").read_text().splitlines()), 60)
            self.assertEqual(len((destination / "final_blind.txt").read_text().splitlines()), 60)
            self.assertEqual(len((destination / "scenarios.jsonl").read_text().splitlines()), 300)


if __name__ == "__main__":
    unittest.main()
