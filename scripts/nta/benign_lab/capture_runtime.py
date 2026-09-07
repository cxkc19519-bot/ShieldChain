"""Shared Docker isolation and packet-capture primitives for benign labs."""

from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path
from typing import Callable

CAPTURE_IMAGE = "jasonish/suricata:7.0.16"


def run(
    command: list[str], *, capture: bool = False, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture,
        encoding="utf-8",
    )


def docker_object_exists(kind: str, name: str) -> bool:
    result = run(["docker", kind, "inspect", name], capture=True, check=False)
    return result.returncode == 0


def refuse_collisions(network: str, containers: list[str]) -> None:
    collisions = []
    if docker_object_exists("network", network):
        collisions.append(network)
    collisions.extend(
        name for name in containers if docker_object_exists("container", name)
    )
    if collisions:
        raise RuntimeError(
            f"refusing to reuse existing Docker objects: {collisions}"
        )


def create_internal_network(network: str, bridge: str) -> None:
    run([
        "docker", "network", "create", "--internal",
        "--label", "com.shieldchain.benign-lab=true",
        "--opt", f"com.docker.network.bridge.name={bridge}",
        network,
    ])


def cleanup_lab(network: str, containers: list[str]) -> None:
    for name in containers:
        if docker_object_exists("container", name):
            run(["docker", "stop", "-t", "1", name], capture=True, check=False)
            run(["docker", "rm", "-f", name], capture=True, check=False)
    if docker_object_exists("network", network):
        run(["docker", "network", "rm", network], capture=True, check=False)


def wait_for(
    probe: Callable[[], subprocess.CompletedProcess[str]],
    description: str,
    attempts: int = 80,
) -> None:
    last = ""
    for _ in range(attempts):
        result = probe()
        last = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{description} did not become ready: {last}")


def wait_for_log(container: str, marker: str, attempts: int = 120) -> None:
    last = ""
    for _ in range(attempts):
        result = run(
            ["docker", "logs", container],
            capture=True,
            check=False,
        )
        last = result.stdout + result.stderr
        if marker in last:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{container} log marker not found: {marker}; {last[-500:]}")

def capture_transaction(
    *,
    capture_name: str,
    bridge: str,
    pcap_dir: Path,
    pcap_name: str,
    transaction: Callable[[], subprocess.CompletedProcess[str]],
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    output = pcap_dir / pcap_name
    if output.exists():
        raise RuntimeError(f"refusing to overwrite capture: {output}")
    started = time.time()
    run([
        "docker", "run", "-d", "--name", capture_name,
        "--network", "host", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "-v", f"{pcap_dir}:/capture",
        "--entrypoint", "tcpdump", CAPTURE_IMAGE,
        "-i", bridge, "--immediate-mode", "-s", "0", "-U",
        "-w", f"/capture/{pcap_name}",
    ])
    capture_log = ""
    response: subprocess.CompletedProcess[str] | None = None
    try:
        for _ in range(50):
            logs = run(
                ["docker", "logs", capture_name], capture=True, check=False
            )
            capture_log = logs.stdout + logs.stderr
            if "listening on" in capture_log:
                break
            time.sleep(0.10)
        else:
            raise RuntimeError(
                f"tcpdump did not become ready: {capture_log.strip()}"
            )
        response = transaction()
        time.sleep(1.00)
    finally:
        run(
            ["docker", "stop", "-t", "1", capture_name],
            capture=True, check=False,
        )
        logs = run(
            ["docker", "logs", capture_name], capture=True, check=False
        )
        capture_log = logs.stdout + logs.stderr
        run(["docker", "rm", capture_name], capture=True, check=False)
    if response is None:
        raise RuntimeError("transaction did not run")
    if not output.exists() or output.stat().st_size <= 24:
        raise RuntimeError(
            f"capture is empty: {output}; tcpdump={capture_log.strip()}"
        )
    metadata = {
        "pcap_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "pcap_bytes": output.stat().st_size,
        "started_at_epoch": started,
        "completed_at_epoch": time.time(),
    }
    return response, metadata
