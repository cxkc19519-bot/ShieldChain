#!/usr/bin/env python3
"""Capture benign database, mail, DNS, SSH, or SMB traffic in Docker."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from capture_runtime import (
    capture_transaction,
    cleanup_lab,
    create_internal_network,
    refuse_collisions,
    run,
    wait_for,
    wait_for_log,
)
from scenario_catalog import Scenario, build_catalog, validate_catalog

CLIENT_IMAGE = "shieldchain-backend:local"
DATABASE_IMAGE = "mariadb:11.4"
MAIL_IMAGE = "greenmail/standalone:2.1.7"
DNS_IMAGE = "internetsystemsconsortium/bind9:9.20"
SSH_IMAGE = "lscr.io/linuxserver/openssh-server:latest"
SMB_IMAGE = "ghcr.io/servercontainers/samba:latest"


@dataclass(frozen=True)
class Lab:
    protocol: str
    network: str
    bridge: str
    server: str
    client: str
    port: int


LABS = {
    "database": Lab("database", "sc-benign-db", "br-scdb", "sc-db-server", "sc-db-client", 3306),
    "mail": Lab("mail", "sc-benign-mail", "br-scmail", "sc-mail-server", "sc-mail-client", 3025),
    "dns": Lab("dns", "sc-benign-dns", "br-scdns", "sc-dns-server", "sc-dns-client", 53),
    "ssh": Lab("ssh", "sc-benign-ssh", "br-scssh", "sc-ssh-server", "sc-ssh-client", 2222),
    "smb": Lab("smb", "sc-benign-smb", "br-scsmb", "sc-smb-server", "sc-smb-client", 445),
}

DB_PASSWORD = "SyntheticLab-2026"
SSH_USER = "lab"
SSH_PASSWORD = "SyntheticSsh-2026"
SMB_USER = "lab"
SMB_PASSWORD = "SyntheticSmb-2026"

MAIL_SCRIPT = r"""
import smtplib
import sys
from email.message import EmailMessage

action, profile, variant = sys.argv[1:4]
subject = {
    "plain_message": "Routine team update",
    "html_message": "Formatted project summary",
    "attachment_notice": "Approved file transfer notice",
    "password_reset": "Requested password reset confirmation",
    "login_notification": "Expected login notification",
    "security_advisory": "Internal CVE research advisory",
    "forwarded_message": "Forwarded business message",
    "internal_alert": "Authorized security exercise notice",
    "numeric_ip_reference": "Service endpoint 192.0.2.25",
    "mailing_list": "Engineering mailing list digest",
}[action]
body = {
    "chinese": "Authorized benign lab message for the Shanghai team.",
    "english": "Routine authorized business communication.",
    "security_research_terms": "Defensive research mentions CVE, phishing, PowerShell and ATT&CK.",
}[profile]
message = EmailMessage()
message["From"] = "sender@benign.test"
message["To"] = "receiver@benign.test"
message["Subject"] = f"{subject} #{variant}"
message.set_content(f"{body}\nScenario variant {variant}. No action required.")
if action == "html_message":
    message.add_alternative(f"<p>{body}</p><p>Variant {variant}</p>", subtype="html")
with smtplib.SMTP("sc-mail-server", 3025, timeout=10) as smtp:
    smtp.send_message(message)
print("smtp-ok")
"""

DNS_SCRIPT = r"""
import random
import socket
import struct
import sys

name, qtype = sys.argv[1], int(sys.argv[2])
transaction = random.randint(1, 65535)
labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\0"
packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
packet += labels + struct.pack("!HH", qtype, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(packet, ("sc-dns-server", 53))
data, _ = sock.recvfrom(4096)
if len(data) < 12 or struct.unpack("!H", data[:2])[0] != transaction:
    raise SystemExit("invalid DNS response")
print(f"dns-ok bytes={len(data)}")
"""

SOCKET_PROBE = r"""
import socket
import sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
s.close()
"""


def database_sql(scenario: Scenario) -> str:
    value = scenario.variant
    statements = {
        "select_rows": f"SELECT * FROM assets WHERE id <= {value + 1}",
        "insert_row": f"INSERT INTO audit_log(message) VALUES ('routine insert {value}')",
        "update_row": f"UPDATE assets SET owner='team-{value}' WHERE id={value}",
        "delete_row": f"DELETE FROM temp_jobs WHERE id={value}",
        "join_report": "SELECT a.name,o.owner FROM assets a JOIN owners o ON a.id=o.id",
        "union_report": (
            "SELECT name AS item FROM assets UNION SELECT owner AS item FROM owners"
        ),
        "pagination": f"SELECT * FROM audit_log ORDER BY id LIMIT 2 OFFSET {value - 1}",
        "aggregate_report": "SELECT owner,COUNT(*) FROM assets GROUP BY owner",
        "permission_lookup": (
            "SELECT user_name,role_name FROM permissions ORDER BY user_name"
        ),
        "backup_metadata": "SHOW TABLE STATUS",
    }
    return statements[scenario.action]


def dns_query(scenario: Scenario) -> tuple[str, int]:
    prefix = {
        "business_domain": "portal",
        "cdn_domain": "cdn",
        "long_legitimate_name": f"quarterly-report-{scenario.variant}.portal",
    }[scenario.profile]
    if scenario.action == "nxdomain_lookup":
        prefix = f"missing-{scenario.variant}"
    qtype = {
        "a_lookup": 1,
        "aaaa_lookup": 28,
        "mx_lookup": 15,
        "txt_lookup": 16,
        "nxdomain_lookup": 1,
    }[scenario.action]
    name = "benign.test" if qtype in (15, 16) else f"{prefix}.benign.test"
    return name, qtype


def ssh_remote_command(scenario: Scenario) -> str:
    commands = {
        "interactive_login": f"echo authorized-session-{scenario.variant}",
        "file_copy": f"printf file-{scenario.variant} > /tmp/benign-copy-{scenario.variant}",
        "git_operation": "printf 'git status: clean\n'",
        "health_check": "uptime",
        "admin_command": "id && df -h /tmp",
    }
    return commands[scenario.action]


def smb_command(scenario: Scenario) -> str:
    suffix = scenario.variant
    commands = {
        "list_share": "ls",
        "download_file": f"get welcome.txt /tmp/download-{suffix}.txt",
        "upload_file": f"put /etc/hostname upload-{suffix}.txt",
        "rename_file": (
            f"put /etc/hostname rename-source-{suffix}.txt; "
            f"rename rename-source-{suffix}.txt renamed-{suffix}.txt"
        ),
        "delete_temp_file": (
            f"put /etc/hostname delete-temp-{suffix}.txt; "
            f"del delete-temp-{suffix}.txt"
        ),
    }
    return commands[scenario.action]


def _probe(lab: Lab):
    return run(
        [
            "docker", "run", "--rm", "--network", lab.network,
            CLIENT_IMAGE, "python", "-c", SOCKET_PROBE, lab.server, str(lab.port),
        ],
        capture=True,
        check=False,
    )


def _start_database(lab: Lab, _: Path, state: dict[str, object]) -> None:
    run([
        "docker", "run", "-d", "--rm", "--name", lab.server,
        "--network", lab.network,
        "-e", f"MARIADB_ROOT_PASSWORD={DB_PASSWORD}",
        "-e", "MARIADB_DATABASE=shieldchain",
        "-e", "MARIADB_USER=lab",
        "-e", f"MARIADB_PASSWORD={DB_PASSWORD}",
        DATABASE_IMAGE,
    ])
    wait_for_log(lab.server, "MariaDB init process done")
    wait_for(lambda: _probe(lab), "MariaDB final TCP listener")
    schema = """
CREATE TABLE assets(id INT PRIMARY KEY, name VARCHAR(80), owner VARCHAR(80));
CREATE TABLE owners(id INT PRIMARY KEY, owner VARCHAR(80));
CREATE TABLE audit_log(id INT AUTO_INCREMENT PRIMARY KEY, message VARCHAR(200));
CREATE TABLE temp_jobs(id INT PRIMARY KEY, label VARCHAR(80));
CREATE TABLE permissions(user_name VARCHAR(80), role_name VARCHAR(80));
INSERT INTO assets VALUES (1,'portal','platform'),(2,'mail','operations'),(3,'dns','network');
INSERT INTO owners VALUES (1,'platform'),(2,'operations'),(3,'network');
INSERT INTO audit_log(message) VALUES ('startup'),('health check'),('backup complete');
INSERT INTO temp_jobs VALUES (1,'complete'),(2,'complete');
INSERT INTO permissions VALUES ('analyst','reader'),('operator','maintainer');
"""
    run([
        "docker", "exec", lab.server, "mariadb", "-uroot",
        f"-p{DB_PASSWORD}", "shieldchain", "-e", schema,
    ])
    wait_for(
        lambda: run([
            "docker", "run", "--rm", "--network", lab.network,
            DATABASE_IMAGE, "mariadb", "--protocol=tcp", "--connect-timeout=3",
            "-h", lab.server, "-ulab", f"-p{DB_PASSWORD}",
            "shieldchain", "-e", "SELECT 1",
        ], capture=True, check=False),
        "MariaDB remote client",
    )



def _start_mail(lab: Lab, _: Path, state: dict[str, object]) -> None:
    run([
        "docker", "run", "-d", "--rm", "--name", lab.server,
        "--network", lab.network,
        "-e", "GREENMAIL_OPTS=-Dgreenmail.setup.test.smtp -Dgreenmail.hostname=0.0.0.0",
        MAIL_IMAGE,
    ])
    wait_for(lambda: _probe(lab), "GreenMail SMTP")


def _start_dns(lab: Lab, repository: Path, state: dict[str, object]) -> None:
    config = repository / "config" / "benign-lab"
    run([
        "docker", "run", "-d", "--rm", "--name", lab.server,
        "--network", lab.network,
        "-v", f"{config / 'named.conf'}:/etc/bind/named.conf:ro",
        "-v", f"{config / 'db.benign.test'}:/etc/bind/db.benign.test:ro",
        DNS_IMAGE,
    ])
    wait_for(lambda: _probe(lab), "BIND DNS")


def _start_ssh(lab: Lab, _: Path, state: dict[str, object]) -> None:
    key_dir = Path(tempfile.mkdtemp(prefix="shieldchain-benign-ssh-"))
    private_key = key_dir / "id_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)])
    public_key = (key_dir / "id_ed25519.pub").read_text(encoding="utf-8").strip()
    state["key_dir"] = key_dir
    state["private_key"] = private_key
    run([
        "docker", "run", "-d", "--rm", "--name", lab.server,
        "--network", lab.network,
        "-e", "PUID=1000", "-e", "PGID=1000", "-e", "TZ=Asia/Shanghai",
        "-e", f"USER_NAME={SSH_USER}", "-e", f"USER_PASSWORD={SSH_PASSWORD}",
        "-e", "PASSWORD_ACCESS=false", "-e", f"PUBLIC_KEY={public_key}",
        SSH_IMAGE,
    ])
    wait_for(lambda: _probe(lab), "OpenSSH")


def _start_smb(lab: Lab, _: Path, state: dict[str, object]) -> None:
    share = Path(tempfile.mkdtemp(prefix="shieldchain-benign-smb-"))
    (share / "welcome.txt").write_text("authorized benign SMB lab\n", encoding="utf-8")
    for variant in (1, 2):
        (share / f"rename-source-{variant}.txt").write_text("rename me\n", encoding="utf-8")
        (share / f"delete-temp-{variant}.txt").write_text("delete me\n", encoding="utf-8")
    os.chmod(share, 0o777)
    for child in share.iterdir():
        os.chmod(child, 0o666)
    state["share_dir"] = share
    share_config = (
        f"[share]; path=/shares/share; valid users = {SMB_USER}; "
        "guest ok = no; read only = no; browseable = yes"
    )
    run([
        "docker", "run", "-d", "--rm", "--name", lab.server,
        "--network", lab.network,
        "-e", f"ACCOUNT_{SMB_USER}={SMB_PASSWORD}",
        "-e", f"UID_{SMB_USER}=1000",
        "-e", f"SAMBA_VOLUME_CONFIG_share={share_config}",
        "-v", f"{share}:/shares/share",
        SMB_IMAGE,
    ])
    wait_for(lambda: _probe(lab), "Samba")


STARTERS = {
    "database": _start_database,
    "mail": _start_mail,
    "dns": _start_dns,
    "ssh": _start_ssh,
    "smb": _start_smb,
}


def start_lab(lab: Lab, repository: Path, state: dict[str, object]) -> None:
    refuse_collisions(lab.network, [lab.server, lab.client])
    create_internal_network(lab.network, lab.bridge)
    STARTERS[lab.protocol](lab, repository, state)


def stop_lab(lab: Lab, state: dict[str, object]) -> None:
    cleanup_lab(lab.network, [lab.client, lab.server])
    for key in ("key_dir", "share_dir"):
        path = state.get(key)
        if isinstance(path, Path):
            shutil.rmtree(path, ignore_errors=True)


def _transaction(lab: Lab, scenario: Scenario, state: dict[str, object]):
    if lab.protocol == "database":
        return run([
            "docker", "run", "--rm", "--name", lab.client,
            "--network", lab.network, DATABASE_IMAGE,
            "mariadb", "--protocol=tcp", "--connect-timeout=3",
            "-h", lab.server, "-ulab", f"-p{DB_PASSWORD}",
            "shieldchain", "-e", database_sql(scenario),
        ], capture=True)
    if lab.protocol == "mail":
        return run([
            "docker", "run", "--rm", "--name", lab.client,
            "--network", lab.network, CLIENT_IMAGE,
            "python", "-c", MAIL_SCRIPT,
            scenario.action, scenario.profile, str(scenario.variant),
        ], capture=True)
    if lab.protocol == "dns":
        name, qtype = dns_query(scenario)
        return run([
            "docker", "run", "--rm", "--name", lab.client,
            "--network", lab.network, CLIENT_IMAGE,
            "python", "-c", DNS_SCRIPT, name, str(qtype),
        ], capture=True)
    if lab.protocol == "ssh":
        private_key = state["private_key"]
        assert isinstance(private_key, Path)
        return run([
            "docker", "run", "--rm", "--name", lab.client,
            "--network", lab.network,
            "-v", f"{private_key}:/tmp/id_ed25519:ro",
            "--entrypoint", "ssh", SSH_IMAGE,
            "-i", "/tmp/id_ed25519", "-p", "2222",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{SSH_USER}@{lab.server}", ssh_remote_command(scenario),
        ], capture=True)
    if lab.protocol == "smb":
        return run([
            "docker", "run", "--rm", "--name", lab.client,
            "--network", lab.network,
            "--entrypoint", "smbclient", SMB_IMAGE,
            f"//{lab.server}/share", "-U", f"{SMB_USER}%{SMB_PASSWORD}",
            "-c", smb_command(scenario),
        ], capture=True)
    raise ValueError(f"unsupported protocol: {lab.protocol}")


def capture_scenario(
    lab: Lab,
    scenario: Scenario,
    pcap_dir: Path,
    state: dict[str, object],
) -> dict[str, object]:
    sequence = scenario.scenario_id.rsplit("-", 1)[-1].lower()
    response, metadata = capture_transaction(
        capture_name=f"sc-{lab.protocol[:4]}-capture-{sequence}",
        bridge=lab.bridge,
        pcap_dir=pcap_dir,
        pcap_name=scenario.pcap_name,
        transaction=lambda: _transaction(lab, scenario, state),
    )
    return {
        "scenario_id": scenario.scenario_id,
        "split": scenario.split,
        "protocol": scenario.protocol,
        "pcap_name": scenario.pcap_name,
        "transaction_stdout": response.stdout.strip()[-500:],
        **metadata,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", choices=tuple(LABS))
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--split",
        choices=("development", "validation", "final_blind"),
        default="development",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--allow-held-out",
        action="store_true",
        help="Required to capture validation/final_blind; never use during rule tuning.",
    )
    return parser.parse_args()


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise SystemExit("live capture must run on the Linux server")
    args = parse_args()
    if args.split != "development" and not args.allow_held_out:
        raise SystemExit(
            "held-out split is protected; pass --allow-held-out only for frozen evaluation"
        )
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    scenarios = build_catalog()
    validate_catalog(scenarios)
    selected = [
        row for row in scenarios
        if row.protocol == args.protocol and row.split == args.split
    ]
    if args.limit is not None:
        selected = selected[:args.limit]
    args.output.mkdir(parents=True, exist_ok=True)
    pcap_dir = (args.output / "pcap").resolve()
    pcap_dir.mkdir(parents=True, exist_ok=True)
    result_path = args.output / f"{args.protocol}-{args.split}-captures.jsonl"
    if result_path.exists():
        raise SystemExit(f"refusing to overwrite existing result: {result_path}")
    repository = Path(__file__).resolve().parents[3]
    lab = LABS[args.protocol]
    state: dict[str, object] = {}
    results: list[dict[str, object]] = []
    try:
        start_lab(lab, repository, state)
        for index, scenario in enumerate(selected, 1):
            result = capture_scenario(lab, scenario, pcap_dir, state)
            results.append(result)
            print(
                f"[{index}/{len(selected)}] {scenario.scenario_id} -> "
                f"{scenario.pcap_name}"
            )
    finally:
        stop_lab(lab, state)
    with result_path.open("w", encoding="utf-8") as handle:
        for row in results:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(
        f"captured {len(results)} isolated {args.protocol} scenarios in {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
