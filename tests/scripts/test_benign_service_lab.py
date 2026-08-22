from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "scripts" / "nta" / "benign_lab"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_transaction_builders_cover_all_catalog_actions(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(MODULE_DIR))
    catalog = load("scenario_catalog")
    service = load("run_service_lab")
    for row in catalog.build_catalog():
        if row.protocol == "database":
            assert service.database_sql(row)
        elif row.protocol == "dns":
            name, query_type = service.dns_query(row)
            assert name == "benign.test" or name.endswith(".benign.test")
            assert query_type in {1, 15, 16, 28}
        elif row.protocol == "ssh":
            assert service.ssh_remote_command(row)
        elif row.protocol == "smb":
            assert service.smb_command(row)


def test_service_labs_are_isolated_and_do_not_fake_windows(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(MODULE_DIR))
    service = load("run_service_lab")
    assert set(service.LABS) == {"database", "mail", "dns", "ssh", "smb"}
    bridges = [lab.bridge for lab in service.LABS.values()]
    assert len(bridges) == len(set(bridges))
    assert all(len(name) <= 15 for name in bridges)
    assert all(lab.network.startswith("sc-benign-") for lab in service.LABS.values())
    assert "windows_admin" not in service.LABS


class BenignServiceLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if str(MODULE_DIR) not in sys.path:
            sys.path.insert(0, str(MODULE_DIR))
        cls.catalog = load("scenario_catalog")
        cls.service = load("run_service_lab")

    def test_all_catalog_actions_have_builders(self) -> None:
        for row in self.catalog.build_catalog():
            if row.protocol == "database":
                self.assertTrue(self.service.database_sql(row))
            elif row.protocol == "dns":
                name, query_type = self.service.dns_query(row)
                self.assertTrue(name == "benign.test" or name.endswith(".benign.test"))
                self.assertIn(query_type, {1, 15, 16, 28})
            elif row.protocol == "ssh":
                self.assertTrue(self.service.ssh_remote_command(row))
            elif row.protocol == "smb":
                self.assertTrue(self.service.smb_command(row))

    def test_isolated_labs_do_not_fake_windows(self) -> None:
        self.assertEqual(
            set(self.service.LABS),
            {"database", "mail", "dns", "ssh", "smb"},
        )
        bridges = [lab.bridge for lab in self.service.LABS.values()]
        self.assertEqual(len(bridges), len(set(bridges)))
        self.assertTrue(all(len(name) <= 15 for name in bridges))
        self.assertTrue(
            all(
                lab.network.startswith("sc-benign-")
                for lab in self.service.LABS.values()
            )
        )
        self.assertNotIn("windows_admin", self.service.LABS)


if __name__ == "__main__":
    unittest.main()
