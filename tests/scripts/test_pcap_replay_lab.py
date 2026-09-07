from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "nta" / "pcap_replay_lab.py"
SPEC = importlib.util.spec_from_file_location("pcap_replay_lab", MODULE_PATH)
assert SPEC and SPEC.loader
replay = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = replay
SPEC.loader.exec_module(replay)


def write_pcap(path: Path, payload: bytes = b"x" * 64) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + payload)


def test_validate_pcap_requires_capture_inside_allowed_root() -> None:
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        allowed = base / "allowed"
        allowed.mkdir()
        outside = base / "outside.pcap"
        write_pcap(outside)

        with pytest.raises(ValueError, match="explicitly allowed"):
            replay.validate_pcap(outside, allowed, 1024)


def test_validate_pcap_checks_magic_and_size() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        invalid = root / "invalid.pcap"
        invalid.write_bytes(b"not-a-capture" * 4)
        with pytest.raises(ValueError, match="not a supported"):
            replay.validate_pcap(invalid, root, 1024)

        valid = root / "valid.pcap"
        write_pcap(valid)
        with pytest.raises(ValueError, match="exceeds"):
            replay.validate_pcap(valid, root, 32)


def test_plan_is_internal_and_never_uses_host_network() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pcap = root / "sample.pcap"
        rules = root / "rules.rules"
        write_pcap(pcap)
        rules.write_text("# test\n", encoding="utf-8")
        plan = replay.build_plan(
            pcap=pcap,
            output_root=root / "output",
            rules=rules,
            pps=500,
            loops=1,
            run_id="0123456789ab",
        )

        assert "--internal" in plan.create_network
        assert plan.network_name in plan.run_replayer
        assert "host" not in plan.start_sensor
        assert "host" not in plan.run_replayer
        assert f"{pcap}:/pcap/input.pcap:ro" in plan.run_replayer
        assert plan.start_sensor.count("NET_RAW") == 1
        assert plan.run_replayer.count("NET_RAW") == 1
        assert "998:998" in plan.start_sensor
        assert "0:0" in plan.run_replayer


def test_sensor_readiness_requires_engine_started_marker() -> None:
    with tempfile.TemporaryDirectory() as temp:
        log = Path(temp) / "suricata.log"
        assert replay.sensor_is_ready(log) is False
        log.write_text("rules loaded\n", encoding="utf-8")
        assert replay.sensor_is_ready(log) is False
        log.write_text("all processing threads initialized, engine started\n", encoding="utf-8")
        assert replay.sensor_is_ready(log) is True


def test_plan_rejects_unbounded_rate_and_loop_count() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pcap = root / "sample.pcap"
        rules = root / "rules.rules"
        write_pcap(pcap)
        rules.write_text("# test\n", encoding="utf-8")
        for pps, loops in [(0, 1), (100_001, 1), (500, 0), (500, 11)]:
            with pytest.raises(ValueError):
                replay.build_plan(
                    pcap=pcap,
                    output_root=root,
                    rules=rules,
                    pps=pps,
                    loops=loops,
                    run_id="0123456789ab",
                )


def test_build_events_deduplicates_signatures_and_records_isolation() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pcap = root / "sample.pcap"
        eve = root / "eve.json"
        write_pcap(pcap)
        alert = {
            "event_type": "alert",
            "alert": {
                "signature_id": 9000001,
                "signature": "ShieldChain test alert",
                "severity": 1,
            },
        }
        eve.write_text(
            json.dumps(alert) + "\n" + json.dumps(alert) + "\n",
            encoding="utf-8",
        )

        events = replay.build_events(
            pcap=pcap,
            run_id="0123456789ab",
            eve_path=eve,
            pps=500,
            loops=1,
        )

        assert len(events) == 1
        assert events[0]["severity"] == 12
        assert events[0]["rule_id"] == "suricata:9000001"
        assert events[0]["evidence"]["isolated_docker_network"] is True
        assert events[0]["evidence"]["source_kind"] == "nta_pcap_isolated_replay"


def test_build_events_ignores_informational_alerts() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pcap = root / "sample.pcap"
        eve = root / "eve.json"
        write_pcap(pcap)
        eve.write_text(
            json.dumps(
                {
                    "event_type": "alert",
                    "alert": {
                        "signature_id": 1,
                        "signature": "ET INFO protocol detail",
                        "category": "Not Suspicious Traffic",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        events = replay.build_events(
            pcap=pcap,
            run_id="0123456789ab",
            eve_path=eve,
            pps=500,
            loops=1,
        )

        assert events == []
