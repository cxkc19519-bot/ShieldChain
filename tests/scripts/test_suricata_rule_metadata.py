from __future__ import annotations

import re
import unittest
from pathlib import Path


RULES_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "suricata"
    / "shieldchain-nta.rules"
)


class SuricataRuleMetadataTests(unittest.TestCase):
    def test_local_sids_are_unique_and_in_reserved_range(self) -> None:
        rules = RULES_PATH.read_text(encoding="utf-8")
        sids = [int(value) for value in re.findall(r"\bsid:(\d+);", rules)]

        self.assertGreaterEqual(len(sids), 78)
        self.assertEqual(len(sids), len(set(sids)))
        self.assertTrue(all(9_000_001 <= sid <= 9_000_999 for sid in sids))

    def test_noalert_rules_store_flow_state(self) -> None:
        lines = RULES_PATH.read_text(encoding="utf-8").splitlines()
        noalert_rules = [line for line in lines if "flowbits:noalert" in line]

        self.assertEqual(len(noalert_rules), 2)
        self.assertTrue(all("flowbits:set" in line for line in noalert_rules))

    def test_large_post_rule_excludes_standard_winrm_ports(self) -> None:
        rules = RULES_PATH.read_text(encoding="utf-8").splitlines()
        rule = next(line for line in rules if "sid:9000005;" in line)

        self.assertIn("-> any ![5985,5986]", rule)
        self.assertIn("rev:4;", rule)

if __name__ == "__main__":
    unittest.main()
