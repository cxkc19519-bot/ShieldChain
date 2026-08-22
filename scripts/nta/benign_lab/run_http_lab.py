#!/usr/bin/env python3
"""Capture authorized HTTP transactions inside a dedicated internal Docker network."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
from dataclasses import asdict
from pathlib import Path

from scenario_catalog import Scenario, build_catalog, validate_catalog

NETWORK = "shieldchain-benign-lab"
BRIDGE = "br-scbenign"
SERVER = "sc-benign-http-server"
CLIENT = "sc-benign-http-client"
CAPTURE_PREFIX = "sc-benign-http-capture"
NGINX_IMAGE = "nginxinc/nginx-unprivileged:1.29.1-alpine3.22"
CLIENT_IMAGE = "shieldchain-backend:local"
CAPTURE_IMAGE = "jasonish/suricata:7.0.16"

CLIENT_SCRIPT = r"""
import http.client
import json
import sys

method, path, body = sys.argv[1], sys.argv[2], sys.argv[3]
payload = body.encode("utf-8") if body else None
headers = {
    "User-Agent": "ShieldChain-Benign-Lab/1.0",
    "X-Scenario-Purpose": "authorized-normal-traffic",
}
if payload is not None:
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
connection = http.client.HTTPConnection("sc-benign-http-server", 8080, timeout=10)
connection.request(method, path, body=payload, headers=headers)
response = connection.getresponse()
content = response.read()
print(json.dumps({"status": response.status, "bytes": len(content)}))
connection.close()
"""


def run(command: list[str], *, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
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


def profile_text(scenario: Scenario) -> str:
    if scenario.profile == "security_research_terms":
        return (
            f"authorized training note variant {scenario.variant}: "
            "CVE Struts2 UNION SELECT PowerShell phishing /login"
        )
    if scenario.profile == "encoded_business_text":
        return f"quarterly report 上海 team {scenario.variant} + percent 100%"
    return f"ordinary business request variant {scenario.variant}"


def build_http_transaction(scenario: Scenario) -> tuple[str, str, str]:
    text = profile_text(scenario)
    encoded = urllib.parse.urlencode({"text": text, "variant": scenario.variant})
    if scenario.action == "homepage_get":
        return "GET", f"/?variant={scenario.variant}", ""
    if scenario.action == "login_form_submit":
        body = urllib.parse.urlencode(
            {"username": f"demo-user-{scenario.variant}", "password": "synthetic-only"}
        )
        return "POST", "/login", body
    if scenario.action == "logout":
        return "POST", "/logout", f"session=synthetic-{scenario.variant}"
    if scenario.action == "search":
        return "GET", f"/search?{encoded}", ""
    if scenario.action == "api_list":
        return "GET", f"/api/items?{encoded}", ""
    if scenario.action == "form_submit":
        return "POST", "/forms/feedback", encoded
    if scenario.action == "file_download":
        return "GET", f"/download/report-{scenario.variant}.txt", ""
    if scenario.action == "health_check":
        return "GET", f"/health?probe={scenario.variant}", ""
    if scenario.action == "missing_page":
        return "GET", f"/documents/archived-{scenario.variant}", ""
    if scenario.action == "report_export":
        return "POST", "/report/export", f"range=30d&{encoded}"
    raise ValueError(f"unsupported HTTP action: {scenario.action}")


def ensure_clean_names() -> None:
    collisions = [
        name
        for kind, name in (("network", NETWORK), ("container", SERVER), ("container", CLIENT))
        if docker_object_exists(kind, name)
    ]
    if collisions:
        raise RuntimeError(f"refusing to reuse existing Docker objects: {collisions}")


def start_lab(repository: Path) -> None:
    ensure_clean_names()
    run([
        "docker", "network", "create", "--internal",
        "--label", "com.shieldchain.benign-lab=true",
        "--opt", f"com.docker.network.bridge.name={BRIDGE}",
        NETWORK,
    ])
    run([
        "docker", "run", "-d", "--rm", "--name", SERVER, "--network", NETWORK,
        "-v", f"{repository / 'config' / 'benign-lab' / 'nginx.conf'}:/etc/nginx/conf.d/default.conf:ro",
        NGINX_IMAGE,
    ])
    run([
        "docker", "run", "-d", "--rm", "--name", CLIENT, "--network", NETWORK,
        "--entrypoint", "sh", CLIENT_IMAGE, "-lc", "sleep infinity",
    ])
    for _ in range(40):
        probe = run(
            ["docker", "exec", CLIENT, "python", "-c", CLIENT_SCRIPT, "GET", "/health", ""],
            capture=True,
            check=False,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError("HTTP lab did not become ready")


def stop_lab() -> None:
    for name in (CLIENT, SERVER):
        if docker_object_exists("container", name):
            run(["docker", "stop", "-t", "1", name], check=False)
    if docker_object_exists("network", NETWORK):
        run(["docker", "network", "rm", NETWORK], check=False)


def capture_scenario(scenario: Scenario, pcap_dir: Path) -> dict[str, object]:
    capture_name = f"{CAPTURE_PREFIX}-{scenario.scenario_id.rsplit('-', 1)[-1].lower()}"
    output = pcap_dir / scenario.pcap_name
    started = time.time()
    run([
        "docker", "run", "-d", "--name", capture_name,
        "--network", "host", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
        "-v", f"{pcap_dir}:/capture",
        "--entrypoint", "tcpdump", CAPTURE_IMAGE,
        "-i", BRIDGE, "--immediate-mode", "-s", "0", "-U", "-w", f"/capture/{scenario.pcap_name}",
    ])
    capture_log = ""
    try:
        for _ in range(40):
            logs = run(["docker", "logs", capture_name], capture=True, check=False)
            capture_log = logs.stdout + logs.stderr
            if "listening on" in capture_log:
                break
            time.sleep(0.10)
        else:
            raise RuntimeError(f"tcpdump did not become ready: {capture_log.strip()}")
        method, path, body = build_http_transaction(scenario)
        response = run(
            ["docker", "exec", CLIENT, "python", "-c", CLIENT_SCRIPT, method, path, body],
            capture=True,
        )
        time.sleep(1.00)
    finally:
        run(["docker", "stop", "-t", "1", capture_name], capture=True, check=False)
        logs = run(["docker", "logs", capture_name], capture=True, check=False)
        capture_log = logs.stdout + logs.stderr
        run(["docker", "rm", capture_name], capture=True, check=False)
    if not output.exists() or output.stat().st_size <= 24:
        raise RuntimeError(
            f"capture is empty: {output}; tcpdump={capture_log.strip()}"
        )
    response_row = json.loads(response.stdout.strip())
    return {
        "scenario_id": scenario.scenario_id,
        "split": scenario.split,
        "protocol": scenario.protocol,
        "pcap_name": scenario.pcap_name,
        "pcap_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "pcap_bytes": output.stat().st_size,
        "http_status": response_row["status"],
        "response_bytes": response_row["bytes"],
        "started_at_epoch": started,
        "completed_at_epoch": time.time(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--split",
        choices=("development", "validation", "final_blind"),
        default="development",
        help="Capture one frozen split at a time; final_blind must not be analysed during tuning.",
    )
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise SystemExit("live capture must run on the Linux server")
    args = parse_args()
    repository = Path(__file__).resolve().parents[3]
    scenarios = build_catalog()
    validate_catalog(scenarios)
    selected = [row for row in scenarios if row.protocol == "http" and row.split == args.split]
    if args.limit is not None:
        if args.limit < 1:
            raise SystemExit("--limit must be positive")
        selected = selected[: args.limit]
    args.output.mkdir(parents=True, exist_ok=True)
    pcap_dir = (args.output / "pcap").resolve()
    pcap_dir.mkdir(parents=True, exist_ok=True)
    result_path = args.output / f"http-{args.split}-captures.jsonl"
    if result_path.exists():
        raise SystemExit(f"refusing to overwrite existing result: {result_path}")
    results: list[dict[str, object]] = []
    try:
        start_lab(repository)
        for index, scenario in enumerate(selected, 1):
            result = capture_scenario(scenario, pcap_dir)
            results.append(result)
            print(f"[{index}/{len(selected)}] {scenario.scenario_id} -> {scenario.pcap_name}")
    finally:
        stop_lab()
    with result_path.open("w", encoding="utf-8") as handle:
        for row in results:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"captured {len(results)} isolated HTTP scenarios in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
