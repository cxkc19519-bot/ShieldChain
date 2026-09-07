from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "nta" / "replay" / "demo_runner.py"
SPEC = importlib.util.spec_from_file_location("demo_replay_runner", MODULE_PATH)
assert SPEC and SPEC.loader
runner_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner_module
SPEC.loader.exec_module(runner_module)


def test_runner_accepts_hashed_sample_inside_allowed_root() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        capture = root / "sample.pcap"
        capture.write_bytes(b"pcap-data")
        manifest = root / "samples.json"
        manifest.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "id": "verified-sample",
                            "path": "sample.pcap",
                            "title": "Verified sample",
                            "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
                            "expected_rule_ids": ["suricata:9000097"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        runner = runner_module.DemoReplayRunner(
            manifest=manifest, pcap_root=root, runtime_root=root / "runtime"
        )

        assert runner._samples()[0].sample_id == "verified-sample"


def test_runner_reports_invalid_manifest_without_starting_replay() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        manifest = root / "samples.json"
        manifest.write_text('{"samples": []}', encoding="utf-8")
        runner = runner_module.DemoReplayRunner(
            manifest=manifest, pcap_root=root, runtime_root=root / "runtime"
        )

        assert runner.start()["state"] == "failed"
        assert runner.status()["reason"] == "manifest_invalid"
