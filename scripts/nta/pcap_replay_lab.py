"""Replay one authorized PCAP inside an isolated Docker network namespace.

Packets are emitted only on a disposable, Docker-internal interface shared by a
Suricata sensor. The script never accepts a host interface or host networking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_ROOT = REPOSITORY_ROOT / "data" / "nta-replay"
DEFAULT_RULES = REPOSITORY_ROOT / "config" / "suricata" / "shieldchain-nta.rules"
DEFAULT_SURICATA_IMAGE = "jasonish/suricata:7.0.16"
DEFAULT_REPLAY_IMAGE = "shieldchain/pcap-replay:local"
MAX_ALLOWED_BYTES = 2 * 1024 * 1024 * 1024
PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
ACKNOWLEDGEMENT = "I_UNDERSTAND_ISOLATED_REPLAY"


@dataclass(frozen=True)
class ReplayPlan:
    run_id: str
    network_name: str
    sensor_name: str
    replayer_name: str
    output_dir: Path
    suricata_image: str
    replay_image: str
    create_network: list[str]
    start_sensor: list[str]
    run_replayer: list[str]


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_pcap(pcap: Path, pcap_root: Path, max_bytes: int) -> Path:
    resolved_root = pcap_root.expanduser().resolve(strict=True)
    resolved_pcap = pcap.expanduser().resolve(strict=True)
    if not resolved_root.is_dir():
        raise ValueError("PCAP root must be a directory")
    if not resolved_pcap.is_relative_to(resolved_root):
        raise ValueError("PCAP must be inside the explicitly allowed PCAP root")
    if not resolved_pcap.is_file():
        raise ValueError("PCAP path must be a regular file")
    size = resolved_pcap.stat().st_size
    if size <= 24:
        raise ValueError("PCAP is empty or too small")
    if size > max_bytes:
        raise ValueError(f"PCAP exceeds the configured {max_bytes}-byte limit")
    with resolved_pcap.open("rb") as stream:
        magic = stream.read(4)
    if magic not in PCAP_MAGIC:
        raise ValueError("file is not a supported classic PCAP capture")
    return resolved_pcap


def build_plan(
    *,
    pcap: Path,
    output_root: Path,
    rules: Path,
    pps: int,
    loops: int,
    suricata_image: str = DEFAULT_SURICATA_IMAGE,
    replay_image: str = DEFAULT_REPLAY_IMAGE,
    run_id: str | None = None,
) -> ReplayPlan:
    token = run_id or uuid.uuid4().hex[:12]
    if not re.fullmatch(r"[a-f0-9]{12}", token):
        raise ValueError("run ID must contain exactly 12 lowercase hexadecimal characters")
    if not 1 <= pps <= 100_000:
        raise ValueError("replay rate must be between 1 and 100000 packets/second")
    if not 1 <= loops <= 10:
        raise ValueError("loop count must be between 1 and 10")
    rules = rules.expanduser().resolve(strict=True)
    if not rules.is_file():
        raise ValueError("Suricata rules path must be a regular file")

    network_name = f"sc-nta-replay-{token}"
    sensor_name = f"sc-nta-sensor-{token}"
    replayer_name = f"sc-nta-emitter-{token}"
    output_dir = output_root.expanduser().resolve() / f"run-{token}"
    sensor_logs = output_dir / "suricata"
    create_network = [
        "docker",
        "network",
        "create",
        "--internal",
        "--driver",
        "bridge",
        "--label",
        "shieldchain.nta.replay=true",
        network_name,
    ]
    start_sensor = [
        "docker",
        "run",
        "--detach",
        "--name",
        sensor_name,
        "--network",
        network_name,
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--volume",
        f"{sensor_logs}:/logs",
        "--volume",
        f"{rules}:/rules/shieldchain-nta.rules:ro",
        suricata_image,
        "--runmode",
        "workers",
        "-i",
        "eth0",
        "-l",
        "/logs",
        "-s",
        "/rules/shieldchain-nta.rules",
    ]
    run_replayer = [
        "docker",
        "run",
        "--name",
        replayer_name,
        "--network",
        f"container:{sensor_name}",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--user",
        "0:0",
        "--volume",
        f"{pcap}:/pcap/input.pcap:ro",
        replay_image,
        "/pcap/input.pcap",
        "--interface",
        "eth0",
        "--pps",
        str(pps),
        "--loops",
        str(loops),
    ]
    return ReplayPlan(
        run_id=token,
        network_name=network_name,
        sensor_name=sensor_name,
        replayer_name=replayer_name,
        output_dir=output_dir,
        suricata_image=suricata_image,
        replay_image=replay_image,
        create_network=create_network,
        start_sensor=start_sensor,
        run_replayer=run_replayer,
    )


def public_plan(plan: ReplayPlan, pcap: Path) -> dict[str, object]:
    return {
        "run_id": plan.run_id,
        "mode": "isolated_docker_namespace",
        "pcap_name": pcap.name,
        "pcap_sha256": sha256(pcap),
        "output_dir": str(plan.output_dir),
        "network": {
            "name": plan.network_name,
            "internal": True,
            "host_interface_allowed": False,
        },
        "sensor": plan.sensor_name,
        "replayer": plan.replayer_name,
    }


def _iter_alerts(eve_path: Path) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    if not eve_path.exists():
        return alerts
    with eve_path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("event_type") == "alert":
                alerts.append(row)
    return alerts


def preflight_runtime(plan: ReplayPlan) -> None:
    info = run(["docker", "info", "--format", "{{.OSType}}"])
    if info.stdout.strip() != "linux":
        raise RuntimeError("isolated replay requires a Linux Docker engine")
    for image in (plan.suricata_image, plan.replay_image):
        inspected = run(["docker", "image", "inspect", image], check=False)
        if inspected.returncode:
            raise RuntimeError(f"required Docker image is unavailable: {image}")


def build_events(
    *, pcap: Path, run_id: str, eve_path: Path, pps: int, loops: int
) -> list[dict[str, object]]:
    capture_hash = sha256(pcap)
    events: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for row in _iter_alerts(eve_path):
        alert = row.get("alert")
        if not isinstance(alert, dict):
            continue
        category = str(alert.get("category") or "").casefold()
        if "not suspicious" in category or int(alert.get("signature_id") or 0) == 2026850:
            continue
        signature = str(alert.get("signature") or "Suricata network alert")[:300]
        signature_id = str(alert.get("signature_id") or "unknown")[:40]
        key = (signature_id, signature)
        if key in seen:
            continue
        seen.add(key)
        suricata_severity = int(alert.get("severity") or 3)
        severity = {1: 12, 2: 9, 3: 6}.get(suricata_severity, 6)
        signature_hash = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12]
        events.append(
            {
                "external_id": (
                    f"nta-replay:{capture_hash[:16]}:{signature_id}:"
                    f"{signature_hash}:{run_id}"
                ),
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "severity": severity,
                "rule_id": f"suricata:{signature_id}",
                "title": f"NTA 隔离回放：{signature}",
                "agent_name": "nta-isolated-replay-suricata",
                "mitre_ids": [],
                "evidence": {
                    "source_kind": "nta_pcap_isolated_replay",
                    "capture_name": pcap.name[:512],
                    "capture_sha256": capture_hash,
                    "suricata_signature": signature,
                    "suricata_signature_id": signature_id,
                    "replay_packets_per_second": pps,
                    "replay_loops": loops,
                    "isolated_docker_network": True,
                },
            }
        )
        if len(events) >= 50:
            break
    return events


def cleanup(plan: ReplayPlan) -> None:
    run(["docker", "rm", "--force", plan.replayer_name], check=False)
    run(["docker", "rm", "--force", plan.sensor_name], check=False)
    run(["docker", "network", "rm", plan.network_name], check=False)


def execute(plan: ReplayPlan, *, pcap: Path, pps: int, loops: int, timeout: int) -> None:
    preflight_runtime(plan)
    sensor_logs = plan.output_dir / "suricata"
    sensor_logs.mkdir(parents=True, exist_ok=False)
    sensor_logs.chmod(0o777)
    replay_output = ""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        run(plan.create_network)
        run(plan.start_sensor)
        time.sleep(2)
        state = run(
            ["docker", "inspect", "-f", "{{.State.Running}}", plan.sensor_name]
        )
        if state.stdout.strip() != "true":
            raise RuntimeError("Suricata sensor stopped before replay")
        completed = run(plan.run_replayer, check=False, timeout=timeout)
        replay_output = (completed.stdout + completed.stderr)[-12_000:]
        if completed.returncode:
            raise RuntimeError(f"replay emitter exited with status {completed.returncode}")
        time.sleep(2)
    finally:
        run(["docker", "stop", "--time", "5", plan.sensor_name], check=False)
        cleanup(plan)

    eve_path = sensor_logs / "eve.json"
    events = build_events(
        pcap=pcap,
        run_id=plan.run_id,
        eve_path=eve_path,
        pps=pps,
        loops=loops,
    )
    events_path = plan.output_dir / "events.jsonl"
    events_path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in events),
        encoding="utf-8",
    )
    manifest = public_plan(plan, pcap)
    manifest.update(
        {
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "unique_alert_events": len(events),
            "events_file": str(events_path),
            "replay_output_tail": replay_output,
        }
    )
    (plan.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    sensor_logs.chmod(0o750)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay one PCAP only inside an isolated Docker namespace"
    )
    parser.add_argument("pcap", type=Path)
    parser.add_argument(
        "--pcap-root",
        type=Path,
        required=True,
        help="authorized directory that must contain the PCAP",
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--pps", type=int, default=500)
    parser.add_argument("--loops", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-mib", type=int, default=512)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument(
        "--acknowledgement",
        help=f"required for execution; exact value: {ACKNOWLEDGEMENT}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 1 <= args.max_mib <= MAX_ALLOWED_BYTES // (1024 * 1024):
        raise ValueError("max-mib must be between 1 and 2048")
    if not 5 <= args.timeout <= 600:
        raise ValueError("timeout must be between 5 and 600 seconds")
    pcap = validate_pcap(args.pcap, args.pcap_root, args.max_mib * 1024 * 1024)
    plan = build_plan(
        pcap=pcap,
        output_root=args.output_root,
        rules=args.rules,
        pps=args.pps,
        loops=args.loops,
    )
    if args.plan:
        print(json.dumps(public_plan(plan, pcap), ensure_ascii=False, indent=2))
        return 0
    if args.acknowledgement != ACKNOWLEDGEMENT:
        print("Refusing replay without the exact isolation acknowledgement.", file=sys.stderr)
        return 2
    if os.environ.get("SHIELDCHAIN_NTA_REPLAY_ENABLED") != "true":
        print("Set SHIELDCHAIN_NTA_REPLAY_ENABLED=true to enable replay.", file=sys.stderr)
        return 2
    execute(
        plan,
        pcap=pcap,
        pps=args.pps,
        loops=args.loops,
        timeout=args.timeout,
    )
    print(plan.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
