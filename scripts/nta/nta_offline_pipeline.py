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
import subprocess
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
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
CONTEXTUAL_SIGNATURE_IDS = {2026850}  # WinRM use alone is not lateral movement.


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


def analyse_with_suricata(
    pcap: Path, destination: Path, sequence: int
) -> tuple[int, str]:
    prepare_output_dir(destination)
    name = f"nta-suricata-{sequence}-{sha256(pcap)[:12]}"
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--user",
        "998:998",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        f"{pcap.resolve()}:/pcap/input.pcap:ro",
        "-v",
        f"{destination.resolve()}:/logs",
        "-v",
        f"{CUSTOM_RULES.resolve()}:/rules/shieldchain-nta.rules:ro",
        SURICATA_IMAGE,
        "--runmode",
        "single",
        "-r",
        "/pcap/input.pcap",
        "-l",
        "/logs",
        "-k",
        "none",
        "-s",
        "/rules/shieldchain-nta.rules",
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
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--workdir",
        "/logs",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        f"{pcap.resolve()}:/pcap/input.pcap:ro",
        "-v",
        f"{destination.resolve()}:/logs",
        ZEEK_IMAGE,
        "zeek",
        "-C",
        "-r",
        "/pcap/input.pcap",
        "LogAscii::use_json=T",
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


def iter_json_lines(path: Path) -> Iterator[dict[str, object]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def json_lines(path: Path) -> list[dict[str, object]]:
    return list(iter_json_lines(path))


def count_json_records(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("rb") as stream:
        return sum(1 for line in stream if line.strip())


def alert_disposition(row: dict[str, object]) -> str:
    alert = row.get("alert") or {}
    signature = str(alert.get("signature") or "")
    category = str(alert.get("category") or "")
    try:
        signature_id = int(alert.get("signature_id") or 0)
    except (TypeError, ValueError):
        signature_id = 0
    if signature_id in CONTEXTUAL_SIGNATURE_IDS:
        return "contextual"
    if (
        signature.startswith(("SURICATA ", "ET INFO "))
        or category == "Generic Protocol Command Decode"
        or category == "Not Suspicious Traffic"
    ):
        return "informational"
    return "security"


def is_non_security_alert(row: dict[str, object]) -> bool:
    return alert_disposition(row) != "security"


def summarize_suricata_alerts(path: Path) -> dict[str, object]:
    raw_count = 0
    informational_count = 0
    contextual_count = 0
    security_count = 0
    signature_counts: Counter[str] = Counter()
    signature_samples: list[str] = []
    if path.exists():
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if '"event_type":"alert"' not in line and '"event_type": "alert"' not in line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("event_type") != "alert":
                    continue
                raw_count += 1
                disposition = alert_disposition(row)
                if disposition == "informational":
                    informational_count += 1
                elif disposition == "contextual":
                    contextual_count += 1
                else:
                    security_count += 1
                    signature = str((row.get("alert") or {}).get("signature") or "")
                    signature_counts[signature] += 1
                    if len(signature_samples) < 50:
                        signature_samples.append(signature)
    return {
        "raw_count": raw_count,
        "informational_count": informational_count,
        "contextual_count": contextual_count,
        "security_count": security_count,
        "signature_counts": signature_counts,
        "signature_samples": signature_samples,
    }


def _number(value: object, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _origin_profiles(conn_rows: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    profiles: dict[str, dict[str, object]] = {}
    for row in conn_rows:
        origin = str(row.get("id.orig_h") or "")
        if not origin:
            continue
        profile = profiles.setdefault(
            origin,
            {
                "origin": origin,
                "connections": 0,
                "destinations": set(),
                "destination_ports": set(),
                "udp": 0,
                "rejected": 0,
            },
        )
        profile["connections"] = int(profile["connections"]) + 1
        destination = str(row.get("id.resp_h") or "")
        if destination:
            profile["destinations"].add(destination)
        port = int(_number(row.get("id.resp_p")))
        if port:
            profile["destination_ports"].add(port)
        if str(row.get("proto") or "").lower() == "udp":
            profile["udp"] = int(profile["udp"]) + 1
        if str(row.get("conn_state") or "").upper() in {"REJ", "S0"}:
            profile["rejected"] = int(profile["rejected"]) + 1
    return list(profiles.values())


def _periodic_connections(
    conn_rows: Iterable[dict[str, object]], active_origins: set[str]
) -> list[dict[str, object]]:
    timestamps: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    for row in conn_rows:
        origin = str(row.get("id.orig_h") or "")
        if origin not in active_origins:
            continue
        key = (
            origin,
            str(row.get("id.resp_h") or ""),
            int(_number(row.get("id.resp_p"))),
            str(row.get("proto") or "").lower(),
        )
        timestamp = _number(row.get("ts"), -1)
        if timestamp >= 0:
            timestamps[key].append(timestamp)

    periodic: list[dict[str, object]] = []
    for key, values in timestamps.items():
        if len(values) < 12:
            continue
        ordered = sorted(values)
        intervals = [right - left for left, right in zip(ordered, ordered[1:])]
        usable = [value for value in intervals if value > 0]
        if not usable:
            continue
        ordered_intervals = sorted(usable)
        midpoint = len(ordered_intervals) // 2
        median = (
            ordered_intervals[midpoint]
            if len(ordered_intervals) % 2
            else (ordered_intervals[midpoint - 1] + ordered_intervals[midpoint]) / 2
        )
        mean = sum(usable) / len(usable)
        variance = sum((value - mean) ** 2 for value in usable) / len(usable)
        coefficient = variance**0.5 / mean if mean else float("inf")
        span = ordered[-1] - ordered[0]
        if 5 <= median <= 3600 and coefficient <= 0.10 and span >= 180:
            periodic.append(
                {
                    "origin": key[0],
                    "destination": key[1],
                    "port": key[2],
                    "protocol": key[3],
                    "samples": len(values),
                    "median_seconds": round(median, 3),
                    "coefficient_of_variation": round(coefficient, 4),
                }
            )
    return periodic


def classify_findings(
    result_dir: Path,
    alert_summary: dict[str, object] | None = None,
) -> tuple[str, int, list[str], list[str], list[str]]:
    summary = alert_summary or summarize_suricata_alerts(
        result_dir / "suricata" / "eve.json"
    )
    signature_counts = summary["signature_counts"]
    assert isinstance(signature_counts, Counter)
    signatures = list(summary["signature_samples"])
    searchable = " ".join(signature_counts).lower()
    security_alert_count = int(summary["security_count"])
    findings: list[str] = []
    informational_count = int(summary["informational_count"])
    contextual_count = int(summary["contextual_count"])
    if informational_count:
        findings.append(
            f"Ignored {informational_count} Suricata informational/decoder event(s)"
        )
    if contextual_count:
        findings.append(
            f"Retained {contextual_count} Suricata contextual observation(s)"
        )

    if security_alert_count:
        findings.append(
            f"Suricata matched {security_alert_count} security rule alert(s)"
        )
        if any(word in searchable for word in ("sql injection", "sql extraction")):
            return "数据库攻击与数据提取", 10, ["T1190", "T1213"], signatures, findings
        if "phishing" in searchable:
            return "钓鱼邮件与凭据诱导", 9, ["T1566.002"], signatures, findings
        if any(word in searchable for word in ("weak password", "credential access")):
            return "弱密码与凭据攻击", 9, ["T1110"], signatures, findings
        if any(word in searchable for word in ("command execution", "command form")):
            return "命令执行", 11, ["T1059"], signatures, findings
        if any(word in searchable for word in ("tunnel", "reduh")):
            return "隧道与命令控制", 11, ["T1572", "T1071.001"], signatures, findings
        if any(
            word in searchable
            for word in ("reverse shell", "interactive shell", "powershell")
        ):
            return (
                "命令执行与反弹连接",
                11,
                ["T1059.001", "T1071"],
                signatures,
                findings,
            )
        if any(
            word in searchable
            for word in (
                "webshell",
                "web shell",
                "behinder",
                "godzilla",
                "antsword",
                "chopper",
            )
        ):
            return (
                "命令与 WebShell 行为",
                12,
                ["T1059", "T1505.003"],
                signatures,
                findings,
            )
        if any(
            word in searchable
            for word in (
                "exploit",
                "cve-",
                "remote code",
                "code execution",
                "jboss",
                "struts",
                "fastjson",
                "shiro",
                "weblogic",
            )
        ):
            return "漏洞利用", 11, ["T1190"], signatures, findings
        if any(
            word in searchable
            for word in ("malware", "trojan", "command and control", "c2", "coinminer")
        ):
            return "恶意软件或命令控制", 11, ["T1071.001"], signatures, findings
        if any(
            word in searchable
            for word in ("scan", "recon", "attempted information leak")
        ):
            return "扫描与侦察", 8, ["T1595"], signatures, findings

        irc_commands = {
            command
            for command in ("user", "nick", "join", "privmsg", "ping", "pong")
            if any(
                f"irc {command}" in signature.lower()
                for signature in signature_counts
            )
        }
        irc_alert_count = sum(
            count
            for signature, count in signature_counts.items()
            if any(f"irc {command}" in signature.lower() for command in irc_commands)
        )
        if len(irc_commands) >= 3 and irc_alert_count >= 10:
            findings.append(
                "Aggregated IRC command sequence: "
                f"commands={sorted(irc_commands)}, alerts={irc_alert_count}"
            )
            return "疑似 IRC 命令控制", 10, ["T1071"], signatures, findings

    http_rows = json_lines(result_dir / "zeek" / "http.log")
    conn_path = result_dir / "zeek" / "conn.log"
    dns_rows = json_lines(result_dir / "zeek" / "dns.log")
    exploit_tokens = (
        "jbossmq-httpil",
        "/invoker/jmxinvokerservlet",
        "/web-console",
        "../",
        "%2e%2e",
        "%00",
        "etc/passwd",
    )
    exploit_http = []
    shell_http = []
    http_command_channels = []
    command_endpoint_tokens = (
        "cmd",
        "command",
        "shell",
        "gateway",
        "console",
        "upload",
        "eval",
        "exec",
        "manager",
        "admin",
    )
    per_uri: dict[str, list[dict[str, object]]] = {}
    transfer_seen = False
    for row in http_rows:
        uri = str(row.get("uri") or "").lower()
        agent = str(row.get("user_agent") or "").lower()
        method = str(row.get("method") or "").upper()
        per_uri.setdefault(uri, []).append(row)
        if "jspspy.jsp" in uri or "/bsh.servlet.bshservlet" in uri:
            shell_http.append(uri[:512])
        if any(token in uri for token in exploit_tokens):
            exploit_http.append(uri[:512])
        if "/shell/" in uri or "shell." in uri:
            shell_http.append(uri[:512])
        if "wget" in agent or "curl" in agent or "/shell/" in uri:
            transfer_seen = True
        body_len = int(row.get("request_body_len") or 0)
        script_path = uri.split("?", 1)[0].endswith(
            (".jsp", ".jspx", ".php", ".asp", ".aspx")
        )
        if method == "POST" and body_len >= 8192 and script_path:
            if any(token in uri for token in command_endpoint_tokens):
                shell_http.append(uri[:512])
            else:
                http_command_channels.append(uri[:512])

    repeated_large_posts = []
    for uri, rows in per_uri.items():
        posts = [row for row in rows if str(row.get("method") or "").upper() == "POST"]
        max_body = max(
            (int(row.get("request_body_len") or 0) for row in posts),
            default=0,
        )
        max_response = max(
            (int(row.get("response_body_len") or 0) for row in posts),
            default=0,
        )
        script_endpoint = uri.split("?", 1)[0].endswith(
            (".jsp", ".jspx", ".php", ".asp", ".aspx")
        )
        repeated_medium_payload = len(posts) >= 3 and max_body >= 2048
        repeated_large_responses = len(posts) >= 3 and max_response >= 4096
        repeated_small_commands = len(posts) >= 8 and max_response >= 512
        agents = [str(row.get("user_agent") or "").strip() for row in posts]
        missing_agent = bool(posts) and not any(agents)
        command_endpoint = any(token in uri for token in command_endpoint_tokens)
        strong_context = missing_agent or command_endpoint or max_body >= 8192
        if (
            script_endpoint
            and strong_context
            and (
                repeated_medium_payload
                or repeated_large_responses
                or repeated_small_commands
            )
        ):
            if command_endpoint:
                repeated_large_posts.append(uri[:512])
            else:
                http_command_channels.append(uri[:512])
    shell_http.extend(repeated_large_posts)

    suspicious_reverse_ports = set()
    for row in iter_json_lines(conn_path):
        try:
            port = int(row.get("id.resp_p") or 0)
            duration = float(row.get("duration") or 0)
        except (TypeError, ValueError):
            continue
        protocol = str(row.get("proto") or "").lower()
        orig_bytes = _number(row.get("orig_bytes"))
        resp_bytes = _number(row.get("resp_bytes"))
        if (
            protocol == "tcp"
            and port in {1337, 4444, 5555, 6666, 7777, 9001}
            and duration >= 5
            and orig_bytes > 0
            and resp_bytes > 0
        ):
            suspicious_reverse_ports.add(port)

    profiles = _origin_profiles(iter_json_lines(conn_path))
    conn_count = sum(int(profile["connections"]) for profile in profiles)
    p2p_profiles = [
        profile
        for profile in profiles
        if int(profile["connections"]) >= 200
        and len(profile["destinations"]) >= 100
        and int(profile["udp"]) / int(profile["connections"]) >= 0.60
        and len(profile["destination_ports"]) >= 50
    ]
    fanout_profiles = [
        profile
        for profile in profiles
        if int(profile["connections"]) >= 200
        and len(profile["destinations"]) >= 100
        and int(profile["rejected"]) / int(profile["connections"]) >= 0.50
    ]
    active_origins = {
        str(profile["origin"]) for profile in p2p_profiles + fanout_profiles
    }
    periodic = _periodic_connections(iter_json_lines(conn_path), active_origins)

    if exploit_http:
        findings.append(
            f"Zeek observed {len(exploit_http)} exploit-pattern HTTP request(s)"
        )
        mitre = ["T1190"]
        if transfer_seen:
            mitre.append("T1105")
        return "疑似 Web 漏洞利用", 10, mitre, signatures, findings
    if shell_http:
        findings.append(
            f"Zeek observed {len(set(shell_http))} WebShell-like HTTP endpoint(s)"
        )
        return "疑似 WebShell 交互", 11, ["T1505.003", "T1059"], signatures, findings
    if http_command_channels:
        findings.append(
            "Zeek observed repeated script POST behavior with strong command-channel "
            f"context on {len(set(http_command_channels))} endpoint(s)"
        )
        return (
            "疑似 HTTP 命令控制或数据外传",
            10,
            ["T1071.001", "T1041"],
            signatures,
            findings,
        )
    if suspicious_reverse_ports:
        findings.append(
            "Zeek observed long-lived connection on suspicious post-exploitation "
            f"port(s): {sorted(suspicious_reverse_ports)}"
        )
        return "疑似反弹连接", 9, ["T1059", "T1071"], signatures, findings
    if p2p_profiles:
        profile = max(p2p_profiles, key=lambda value: int(value["connections"]))
        findings.append(
            "Zeek observed high-fanout UDP/P2P behavior: "
            f"connections={profile['connections']}, "
            f"destinations={len(profile['destinations'])}, "
            f"ports={len(profile['destination_ports'])}"
        )
        if periodic:
            findings.append(
                f"Zeek observed {len(periodic)} stable periodic connection group(s)"
            )
        return "疑似 P2P/UDP 僵尸网络", 9, ["T1071"], signatures, findings
    if fanout_profiles:
        profile = max(fanout_profiles, key=lambda value: int(value["connections"]))
        findings.append(
            "Zeek observed high-rejection destination fanout: "
            f"connections={profile['connections']}, "
            f"destinations={len(profile['destinations'])}, "
            f"rejected={profile['rejected']}"
        )
        if periodic:
            findings.append(
                f"Zeek observed {len(periodic)} stable periodic connection group(s)"
            )
            return "疑似周期信标与僵尸网络活动", 10, ["T1071"], signatures, findings
        return "疑似扫描与僵尸网络传播", 9, ["T1046"], signatures, findings
    if security_alert_count:
        return "Suricata 安全规则告警", 9, [], signatures, findings
    if http_rows or conn_count or dns_rows:
        findings.append(
            f"Zeek parsed conn={conn_count}, http={len(http_rows)}, dns={len(dns_rows)}"
        )
        return "网络行为待研判", 5, [], signatures, findings
    return "未检出有效网络行为", 3, [], signatures, findings


def build_event(
    pcap: Path, pcap_hash: str, result_dir: Path, suricata_code: int, zeek_code: int
) -> dict[str, object]:
    alert_summary = summarize_suricata_alerts(result_dir / "suricata" / "eve.json")
    category, severity, mitre_ids, signatures, findings = classify_findings(
        result_dir, alert_summary
    )
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
            "suricata_alert_count": int(alert_summary["security_count"]),
            "suricata_raw_alert_count": int(alert_summary["raw_count"]),
            "suricata_ignored_informational_event_count": int(
                alert_summary["informational_count"]
            ),
            "suricata_contextual_observation_count": int(
                alert_summary["contextual_count"]
            ),
            "suricata_signatures": signatures[:50],
            "zeek_conn_record_count": count_json_records(
                result_dir / "zeek" / "conn.log"
            ),
            "zeek_http_record_count": count_json_records(
                result_dir / "zeek" / "http.log"
            ),
            "zeek_dns_record_count": count_json_records(
                result_dir / "zeek" / "dns.log"
            ),
            "content_findings": findings,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline NTA PCAP baseline analyser")
    parser.add_argument(
        "--limit",
        type=int,
        default=12,
        help="number of representative samples to process",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="process all PCAP files; may take a long time",
    )
    parser.add_argument(
        "--extract", action="store_true", help="extract archive before analysis"
    )
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
        event = build_event(pcap, sample_hash, sample_dir, suricata_code, zeek_code)
        events.append(event)
        evidence = event["evidence"]
        category = str(event["rule_id"]).split(":", 1)[-1]
        print(
            f"[{index}/{len(targets)}] {pcap.name} -> category={category}, "
            f"alerts={evidence['suricata_alert_count']}, "
            f"engine_exit=(Suricata:{suricata_code}, Zeek:{zeek_code})"
        )

    (run_dir / "events.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events),
        encoding="utf-8",
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
