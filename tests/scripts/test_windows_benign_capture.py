from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "scripts" / "nta" / "benign_lab"


def load(name: str):
    if str(MODULE_DIR) not in sys.path:
        sys.path.insert(0, str(MODULE_DIR))
    spec = importlib.util.spec_from_file_location(name, MODULE_DIR / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_development_plan_contains_only_the_18_fixed_windows_rows(tmp_path: Path) -> None:
    plan = load("windows_capture_plan")
    rows = plan.select_windows_scenarios("development")
    assert len(rows) == 18
    assert {row.protocol for row in rows} == {"windows_admin"}
    assert {row.split for row in rows} == {"development"}
    output = tmp_path / "plan.json"
    plan.write_plan(output, rows)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scenario_count"] == 18
    with pytest.raises(FileExistsError):
        plan.write_plan(output, rows)


def test_held_out_plans_require_explicit_permission() -> None:
    plan = load("windows_capture_plan")
    with pytest.raises(PermissionError):
        plan.select_windows_scenarios("validation")
    assert len(plan.select_windows_scenarios("validation", allow_held_out=True)) == 6
    assert len(plan.select_windows_scenarios("final_blind", allow_held_out=True)) == 6


def test_import_validates_hash_size_name_and_completeness(tmp_path: Path) -> None:
    plan = load("windows_capture_plan")
    importer = load("import_windows_captures")
    rows = plan.select_windows_scenarios("development")
    source = tmp_path / "source"
    pcap_dir = source / "pcap"
    pcap_dir.mkdir(parents=True)
    records = []
    for row in rows:
        payload = b"\xd4\xc3\xb2\xa1" + bytes(48) + row.scenario_id.encode()
        pcap = pcap_dir / row.pcap_name
        pcap.write_bytes(payload)
        records.append({
            "scenario_id": row.scenario_id,
            "pcap_name": row.pcap_name,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    (source / "windows-captures.jsonl").write_text(
        "\n".join(json.dumps(row) for row in records) + "\n",
        encoding="utf-8",
    )
    validated = importer.validate_source(source, "development")
    assert len(validated) == 18
    destination = tmp_path / "imported"
    importer.import_source(source, destination, validated)
    assert len(list((destination / "pcap").glob("*.pcap"))) == 18
    with pytest.raises(FileExistsError):
        importer.import_source(source, destination, validated)


def test_import_rejects_partial_and_tampered_sets(tmp_path: Path) -> None:
    plan = load("windows_capture_plan")
    importer = load("import_windows_captures")
    row = plan.select_windows_scenarios("development")[0]
    source = tmp_path / "source"
    (source / "pcap").mkdir(parents=True)
    pcap = source / "pcap" / row.pcap_name
    pcap.write_bytes(b"x" * 64)
    record = {
        "scenario_id": row.scenario_id,
        "pcap_name": row.pcap_name,
        "bytes": 64,
        "sha256": hashlib.sha256(b"x" * 64).hexdigest(),
    }
    (source / "windows-captures.jsonl").write_text(json.dumps(record) + "\n")
    with pytest.raises(ValueError, match="incomplete"):
        importer.validate_source(source, "development")
    pcap.write_bytes(b"y" * 64)
    with pytest.raises(ValueError, match="SHA-256"):
        importer.validate_source(source, "development", require_complete=False)


def test_powershell_collector_keeps_mutations_in_named_lab_scope() -> None:
    text = (MODULE_DIR / "Collect-ShieldChainWindowsBaseline.ps1").read_text(encoding="utf-8")
    assert "ShieldChainBenignLab" in text
    assert "AllowHeldOut" in text
    assert "LabMsiPath" in text
    assert "CredentialDirectory" in text
    assert "Import-Clixml" in text
    assert "'-F', 'pcap'" in text
    assert """'-f', ('"host {0} and tcp"' -f $targetAddress)""" in text
    assert "Remove-Item -Recurse" not in text


def test_benign_msi_fixture_has_no_service_or_firewall_side_effects() -> None:
    source = (MODULE_DIR / "ShieldChainBenignFixture.wxs").read_text(encoding="utf-8")
    payload = (MODULE_DIR / "ShieldChainBenignFixture.txt").read_text(encoding="utf-8")
    assert 'Scope="perMachine"' in source
    assert 'Source="ShieldChainBenignFixture.txt"' in source
    assert "<ServiceInstall" not in source
    assert "<ServiceControl" not in source
    assert "FirewallException" not in source
    assert "isolated ShieldChain laboratory" in payload
