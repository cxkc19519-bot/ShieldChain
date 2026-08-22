from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parents[2] / "scripts" / "nta" / "benign_lab"
sys.path.insert(0, str(MODULE_DIR))
SPEC = importlib.util.spec_from_file_location("run_http_lab", MODULE_DIR / "run_http_lab.py")
assert SPEC and SPEC.loader
run_http_lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_http_lab
SPEC.loader.exec_module(run_http_lab)


class BenignHttpLabTests(unittest.TestCase):
    def test_all_http_scenarios_have_supported_transactions(self) -> None:
        rows = [
            row for row in run_http_lab.build_catalog()
            if row.protocol == "http"
        ]
        self.assertEqual(len(rows), 60)
        for row in rows:
            method, path, body = run_http_lab.build_http_transaction(row)
            self.assertIn(method, {"GET", "POST"})
            self.assertTrue(path.startswith("/"))
            if method == "POST":
                self.assertTrue(body)

    def test_security_research_profile_is_a_hard_negative(self) -> None:
        row = next(
            row for row in run_http_lab.build_catalog()
            if row.protocol == "http"
            and row.action == "search"
            and row.profile == "security_research_terms"
        )
        method, path, body = run_http_lab.build_http_transaction(row)
        self.assertEqual(method, "GET")
        self.assertFalse(body)
        decoded = __import__("urllib.parse", fromlist=["unquote_plus"]).unquote_plus(path)
        self.assertIn("UNION SELECT", decoded)
        self.assertIn("PowerShell", decoded)

    def test_capture_uses_only_dedicated_bridge(self) -> None:
        self.assertEqual(run_http_lab.NETWORK, "shieldchain-benign-lab")
        self.assertEqual(run_http_lab.BRIDGE, "br-scbenign")
        self.assertNotIn("eno", run_http_lab.BRIDGE)
        self.assertNotIn("eth", run_http_lab.BRIDGE)


if __name__ == "__main__":
    unittest.main()
