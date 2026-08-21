#!/usr/bin/env python3
"""Safely analyse NTA PCAP baseline files offline with Zeek and Suricata.

The script never replays packets, never captures a host interface, and runs each
analyser container with network access disabled.  Labels derived from filenames
are retained as dataset labels rather than being presented as detector findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


DATASET_NAME = os.environ.get("SHIELDCHAIN_NTA_DATASET_NAME", "NTA PCAP dataset")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ROOT = Path(
    os.environ.get("SHIELDCHAIN_NTA_ROOT", str(REPOSITORY_ROOT / "data" / "nta"))
).expanduser()
ARCHIVE = Path(
    os.environ.get(
        "SHIELDCHAIN_NTA_ARCHIVE",
        str(ROOT / "archive" / "nta-dataset.zip"),
    )
).expanduser()
PCAP_ROOT = Path(
    os.environ.get("SHIELDCHAIN_NTA_PCAP_ROOT", str(ROOT / "pcap"))
).expanduser()
RESULT_ROOT = Path(
    os.environ.get("SHIELDCHAIN_NTA_RESULT_ROOT", str(ROOT / "results"))
).expanduser()
SURICATA_IMAGE = os.environ.get(
    "SHIELDCHAIN_SURICATA_IMAGE", "jasonish/suricata:7.0.16"
)
ZEEK_IMAGE = os.environ.get("SHIELDCHAIN_ZEEK_IMAGE", "zeek/zeek:latest")
CUSTOM_RULES = Path(
    os.environ.get(
        "SHIELDCHAIN_SURICATA_RULES",
        str(REPOSITORY_ROOT / "config" / "suricata" / "shieldchain-nta.rules"),
    )
).expanduser()


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def safe_extract() -> None:
    if not ARCHIVE.exists():
        raise FileNotFoundError(f"dataset archive not found: {ARCHIVE}")
    PCAP_ROOT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ARCHIVE) as bundle:
        for member in bundle.infolist():
            target = (PCAP_ROOT / member.filename).resolve()
            if not target.is_relative_to(PCAP_ROOT.resolve()):
                raise ValueError(f"unsafe archive member: {member.filename}")
        bundle.extractall(PCAP_ROOT)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def choose_samples(paths: list[Path], limit: int) -> list[Path]:
    # Blind sample identifiers are random and contain no label semantics.
    return paths[:limit]


def prepare_output_dir(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o777)


def finish_output_dir(destination: Path) -> None:
    destination.chmod(0o750)


def analyse_with_suricata(pcap: Path, destination: Path, sequence: int) -> tuple[int, str]:
    prepare_output_dir(destination)
    name = f"nta-suricata-{sequence}-{sha256(pcap)[:12]}"
    command = [
        "docker", "run", "--rm", "--name", name, "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--read-only", "--user", "998:998",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{pcap.resolve()}:/pcap/input.pcap:ro",
        "-v", f"{destination.resolve()}:/logs",
        "-v", f"{CUSTOM_RULES.resolve()}:/rules/shieldchain-nta.rules:ro",
        SURICATA_IMAGE,
        "--runmode", "single", "-r", "/pcap/input.pcap", "-l", "/logs",
        "-k", "none", "-s", "/rules/shieldchain-nta.rules",
    ]
    completed = run(command, check=False)
    (destination / "engine-output.txt").write_text(
        (completed.stderr + completed.stdout)[-8000:], encoding="utf-8"
    )
    finish_output_dir(destination)
    code = completed.returncode
    if not (destination / "eve.json").exists():
        code = code or 90
    return code, (completed.stderr + completed.stdout)[-2000:]


def analyse_with_zeek(pcap: Path, destination: Path, sequence: int) -> tuple[int, str]:
    prepare_output_dir(destination)
    name = f"nta-zeek-{sequence}-{sha256(pcap)[:12]}"
    command = [
        "docker", "run", "--rm", "--name", name, "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--read-only", "--workdir", "/logs",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{pcap.resolve()}:/pcap/input.pcap:ro",
        "-v", f"{destination.resolve()}:/logs",
        ZEEK_IMAGE,
        "zeek", "-C", "-r", "/pcap/input.pcap", "LogAscii::use_json=T",
    ]
    completed = run(command, check=False)
    (destination / "engine-output.txt").write_text(
        (completed.stderr + completed.stdout)[-8000:], encoding="utf-8"
    )
    finish_output_dir(destination)
    code = completed.returncode
    if not any(destination.glob("*.log")):
        code = code or 91
    return code, (completed.stderr + completed.stdout)[-2000:]


def json_lines(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def is_decoder_alert(row: dict[str, object]) -> bool:
    alert = row.get("alert") or {}
    signature = str(alert.get("signature") or "")
    category = str(alert.get("category") or "")
    return signature.startswith("SURICATA ") or category == "Generic Protocol Command Decode"


def classify_findings(result_dir: Path) -> tuple[str, int, list[str], list[str], list[str]]:
    suricata_rows = json_lines(result_dir / "suricata" / "eve.json")
    raw_alerts = [row for row in suricata_rows if row.get("event_type") == "alert"]
    alerts = [row for row in raw_alerts if not is_decoder_alert(row)]
    signatures = [str((row.get("alert") or {}).get("signature") or "") for row in alerts]
    searchable = " ".join(signatures).lower()
    findings: list[str] = []
    decoder_count = len(raw_alerts) - len(alerts)
    if decoder_count:
        findings.append(f"Ignored {decoder_count} Suricata decoder/checksum event(s)")

    if alerts:
        findings.append(f"Suricata matched {len(alerts)} security rule alert(s)")
        if any(word in searchable for word in ("webshell", "web shell", "behinder", "godzilla", "antsword", "chopper")):
            return "命令与 WebShell 行为", 12, ["T1059", "T1505.003"], signatures, findings
        if any(word in searchable for word in ("exploit", "cve-", "remote code", "code execution", "jboss")):
            return "漏洞利用", 11, ["T1190"], signatures, findings
        if any(word in searchable for word in ("malware", "trojan", "command and control", "c2", "coinminer")):
            return "恶意软件或命令控制", 11, ["T1071.001"], signatures, findings
        if any(word in searchable for word in ("scan", "recon", "attempted information leak")):
            return "扫描与侦察", 8, ["T1595"], signatures, findings

    http_rows = json_lines(result_dir / "zeek" / "http.log")
    conn_rows = json_lines(result_dir / "zeek" / "conn.log")
    dns_rows = json_lines(result_dir / "zeek" / "dns.log")
    exploit_tokens = (
        "jbossmq-httpil", "/invoker/jmxinvokerservlet", "/web-console",
        "../", "%2e%2e", "%00", "etc/passwd",
    )
    exploit_http = []
    shell_http = []
    per_uri: dict[str, list[dict[str, object]]] = {}
    transfer_seen = False
    for row in http_rows:
        uri = str(row.get("uri") or "").lower()
        agent = str(row.get("user_agent") or "").lower()
        method = str(row.get("method") or "").upper()
        per_uri.setdefault(uri, []).append(row)
        if any(token in uri for token in exploit_tokens):
            exploit_http.append(uri[:512])
        if "/shell/" in uri or "shell." in uri:
            shell_http.append(uri[:512])
        if "wget" in agent or "curl" in agent or "/shell/" in uri:
            transfer_seen = True
        body_len = int(row.get("request_body_len") or 0)
        if method == "POST" and body_len >= 8192 and uri.endswith((".jsp", ".jspx", ".php", ".asp", ".aspx")):
            shell_http.append(uri[:512])

    repeated_large_posts = []
    for uri, rows in per_uri.items():
        posts = [row for row in rows if str(row.get("method") or "").upper() == "POST"]
        if len(posts) >= 3 and max((int(row.get("request_body_len") or 0) for row in posts), default=0) >= 8192:
            repeated_large_posts.append(uri[:512])
    shell_http.extend(repeated_large_posts)

    if exploit_http:
        findings.append(f"Zeek observed {len(exploit_http)} exploit-pattern HTTP request(s)")
        mitre = ["T1190"]
        if transfer_seen:
            mitre.append("T1105")
        return "疑似 Web 漏洞利用", 10, mitre, signatures, findings
    if shell_http:
        findings.append(f"Zeek observed {len(set(shell_http))} WebShell-like HTTP endpoint(s)")
        return "疑似 WebShell 交互", 11, ["T1505.003", "T1059"], signatures, findings
    if alerts:
        return "Suricata 安全规则告警", 9, [], signatures, findings
    if http_rows or conn_rows or dns_rows:
        findings.append(f"Zeek parsed conn={len(conn_rows)}, http={len(http_rows)}, dns={len(dns_rows)}")
        return "网络行为待研判", 5, [], signatures, findings
    return "未检出有效网络行为", 3, [], signatures, findings


def build_event(pcap: Path, pcap_hash: str, result_dir: Path, suricata_code: int, zeek_code: int) -> dict[str, object]:
    category, severity, mitre_ids, signatures, findings = classify_findings(result_dir)
    suricata_rows = json_lines(result_dir / "suricata" / "eve.json")
    zeek_conn_rows = json_lines(result_dir / "zeek" / "conn.log")
    zeek_http_rows = json_lines(result_dir / "zeek" / "http.log")
    zeek_dns_rows = json_lines(result_dir / "zeek" / "dns.log")
    raw_alert_rows = [row for row in suricata_rows if row.get("event_type") == "alert"]
    decoder_alert_count = sum(is_decoder_alert(row) for row in raw_alert_rows)
    alert_count = len(raw_alert_rows) - decoder_alert_count
    return {
        "external_id": f"nta-offline:{pcap_hash}",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "rule_id": f"nta-baseline:{category}",
        "title": f"NTA 离线基线样本：{category}",
        "agent_name": "nta-offline-zeek-suricata",
        "mitre_ids": mitre_ids,
        "evidence": {
            "source_kind": "nta_pcap_offline_analysis",
            "dataset": DATASET_NAME,
            "classification_basis": "Suricata rule output and Zeek protocol metadata; filename labels were not used",
            "pcap_filename": pcap.name[:512],
            "pcap_sha256": pcap_hash,
            "suricata_exit_code": suricata_code,
            "zeek_exit_code": zeek_code,
            "suricata_alert_count": alert_count,
            "suricata_raw_alert_count": len(raw_alert_rows),
            "suricata_decoder_event_count": decoder_alert_count,
            "suricata_signatures": signatures[:50],
            "zeek_conn_record_count": len(zeek_conn_rows),
            "zeek_http_record_count": len(zeek_http_rows),
            "zeek_dns_record_count": len(zeek_dns_rows),
            "content_findings": findings,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline NTA PCAP baseline analyser")
    parser.add_argument("--limit", type=int, default=12, help="number of representative samples to process")
    parser.add_argument("--all", action="store_true", help="process all PCAP files; may take a long time")
    parser.add_argument("--extract", action="store_true", help="extract archive before analysis")
    parser.add_argument(
        "--sample-list",
        type=Path,
        help="UTF-8 file containing one opaque PCAP filename per line",
    )
    args = parser.parse_args()

    if args.extract or not any(PCAP_ROOT.rglob("*.pcap")):
        safe_extract()

    samples = sorted(PCAP_ROOT.rglob("*.pcap"), key=lambda item: item.name.lower())
    if not samples:
        raise RuntimeError("no PCAP files found after extraction")
    if not CUSTOM_RULES.is_file():
        raise RuntimeError(f"custom Suricata rules not found: {CUSTOM_RULES}")
    if args.sample_list:
        requested = [
            line.strip()
            for line in args.sample_list.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        by_name = {item.name: item for item in samples}
        unknown = [name for name in requested if name not in by_name]
        if unknown:
            raise ValueError(f"sample list contains unknown filename(s): {unknown[:5]}")
        if len(requested) != len(set(requested)):
            raise ValueError("sample list contains duplicate filenames")
        samples = [by_name[name] for name in requested]
    targets = (
        samples
        if args.all or args.sample_list
        else choose_samples(samples, max(1, args.limit))
    )
    run_id = datetime.now().strftime("run-%Y%m%d-%H%M%S")
    run_dir = RESULT_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    events: list[dict[str, object]] = []

    for index, pcap in enumerate(targets, start=1):
        sample_hash = sha256(pcap)
        sample_dir = run_dir / f"{index:04d}-{sample_hash[:12]}"
        suricata_code, _ = analyse_with_suricata(pcap, sample_dir / "suricata", index)
        zeek_code, _ = analyse_with_zeek(pcap, sample_dir / "zeek", index)
        events.append(build_event(pcap, sample_hash, sample_dir, suricata_code, zeek_code))
        print(f"[{index}/{len(targets)}] {pcap.name} -> Suricata={suricata_code}, Zeek={zeek_code}")

    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8"
    )
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "dataset": DATASET_NAME,
                "run_id": run_id,
                "samples": len(events),
                "classification_basis": "detector output only; no filename labels",
                "custom_rules_sha256": sha256(CUSTOM_RULES),
                "sample_list": str(args.sample_list) if args.sample_list else None,
                "categories": Counter(str(event["rule_id"]) for event in events),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
