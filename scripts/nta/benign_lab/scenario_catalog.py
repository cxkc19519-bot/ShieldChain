#!/usr/bin/env python3
"""Build the deterministic ShieldChain benign-traffic scenario catalogue."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

CATALOG_SEED = "shieldchain-benign-baseline-20260822"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    protocol: str
    action: str
    profile: str
    variant: int
    group_id: str
    split: str
    capture_mode: str
    expected_disposition: str
    expected_custom_rule_alerts: tuple[str, ...]
    pcap_name: str
    description: str


PROTOCOL_MATRIX: dict[str, tuple[list[str], list[str], str]] = {
    "http": (
        ["homepage_get", "login_form_submit", "logout", "search", "api_list",
         "form_submit", "file_download", "health_check", "missing_page", "report_export"],
        ["ordinary", "security_research_terms", "encoded_business_text"],
        "live_docker",
    ),
    "database": (
        ["select_rows", "insert_row", "update_row", "delete_row", "join_report",
         "union_report", "pagination", "aggregate_report", "permission_lookup", "backup_metadata"],
        ["application", "administrator", "security_audit"],
        "live_docker",
    ),
    "mail": (
        ["plain_message", "html_message", "attachment_notice", "password_reset",
         "login_notification", "security_advisory", "forwarded_message", "internal_alert",
         "numeric_ip_reference", "mailing_list"],
        ["chinese", "english", "security_research_terms"],
        "live_docker",
    ),
    "dns": (
        ["a_lookup", "aaaa_lookup", "mx_lookup", "txt_lookup", "nxdomain_lookup"],
        ["business_domain", "cdn_domain", "long_legitimate_name"],
        "live_docker",
    ),
    "ssh": (
        ["interactive_login", "file_copy", "git_operation", "health_check", "admin_command"],
        ["developer", "operator", "automation_account"],
        "live_docker",
    ),
    "smb": (
        ["list_share", "download_file", "upload_file", "rename_file", "delete_temp_file"],
        ["office_document", "security_report", "software_package"],
        "live_docker",
    ),
    "windows_admin": (
        ["delete_temp_file", "powershell_inventory", "software_install", "scheduled_task",
         "registry_update"],
        ["interactive_admin", "automation_account", "security_operator"],
        "windows_vm_required",
    ),
}

EXPECTED_COUNTS = {
    "http": 60,
    "database": 60,
    "mail": 60,
    "dns": 30,
    "ssh": 30,
    "smb": 30,
    "windows_admin": 30,
}


def stable_digest(value: str) -> str:
    return hashlib.sha256(f"{CATALOG_SEED}:{value}".encode()).hexdigest()


def split_groups(protocol: str, group_ids: list[str]) -> dict[str, str]:
    ordered = sorted(group_ids, key=lambda group: stable_digest(f"split:{protocol}:{group}"))
    development_end = len(ordered) * 60 // 100
    validation_end = development_end + len(ordered) * 20 // 100
    return {
        group: (
            "development" if index < development_end
            else "validation" if index < validation_end
            else "final_blind"
        )
        for index, group in enumerate(ordered)
    }


def build_catalog() -> list[Scenario]:
    scenarios: list[Scenario] = []
    counters = {protocol: 0 for protocol in PROTOCOL_MATRIX}
    for protocol, (actions, profiles, capture_mode) in PROTOCOL_MATRIX.items():
        groups = [f"{protocol}:{action}:{profile}" for action in actions for profile in profiles]
        assignments = split_groups(protocol, groups)
        for action in actions:
            for profile in profiles:
                group_id = f"{protocol}:{action}:{profile}"
                for variant in (1, 2):
                    counters[protocol] += 1
                    sequence = counters[protocol]
                    scenario_id = f"BENIGN-{protocol.upper()}-{sequence:03d}"
                    pcap_name = f"b-{stable_digest(scenario_id)[:16]}.pcap"
                    scenarios.append(
                        Scenario(
                            scenario_id=scenario_id,
                            protocol=protocol,
                            action=action,
                            profile=profile,
                            variant=variant,
                            group_id=group_id,
                            split=assignments[group_id],
                            capture_mode=capture_mode,
                            expected_disposition="benign",
                            expected_custom_rule_alerts=(),
                            pcap_name=pcap_name,
                            description=(
                                f"Authorized isolated normal {protocol} transaction: "
                                f"{action} using {profile} profile, variant {variant}."
                            ),
                        )
                    )
    return scenarios


def validate_catalog(scenarios: Iterable[Scenario]) -> None:
    rows = list(scenarios)
    if len(rows) != 300:
        raise ValueError(f"expected 300 scenarios, got {len(rows)}")
    if len({row.scenario_id for row in rows}) != len(rows):
        raise ValueError("duplicate scenario_id")
    if len({row.pcap_name for row in rows}) != len(rows):
        raise ValueError("duplicate pcap_name")
    for protocol, expected in EXPECTED_COUNTS.items():
        actual = sum(row.protocol == protocol for row in rows)
        if actual != expected:
            raise ValueError(f"{protocol}: expected {expected}, got {actual}")
    groups: dict[str, set[str]] = {}
    for row in rows:
        groups.setdefault(row.group_id, set()).add(row.split)
        if row.expected_disposition != "benign":
            raise ValueError(f"non-benign scenario: {row.scenario_id}")
        if row.protocol in row.pcap_name:
            raise ValueError(f"label leaked into pcap name: {row.pcap_name}")
    leaked = {group: splits for group, splits in groups.items() if len(splits) != 1}
    if leaked:
        raise ValueError(f"scenario groups cross splits: {leaked}")
    split_counts = {
        split: sum(row.split == split for row in rows)
        for split in ("development", "validation", "final_blind")
    }
    if split_counts != {"development": 180, "validation": 60, "final_blind": 60}:
        raise ValueError(f"unexpected split counts: {split_counts}")


def write_catalog(output: Path, scenarios: list[Scenario]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output / "scenarios.jsonl").open("w", encoding="utf-8") as handle:
        for scenario in scenarios:
            handle.write(json.dumps(asdict(scenario), ensure_ascii=False, sort_keys=True) + "\n")
    for split in ("development", "validation", "final_blind"):
        with (output / f"{split}.txt").open("w", encoding="utf-8") as handle:
            for scenario in scenarios:
                if scenario.split == split:
                    handle.write(f"{scenario.pcap_name}\n")
    summary = {
        "catalog_seed": CATALOG_SEED,
        "scenario_count": len(scenarios),
        "protocol_counts": EXPECTED_COUNTS,
        "split_counts": {
            split: sum(row.split == split for row in scenarios)
            for split in ("development", "validation", "final_blind")
        },
        "label_policy": "Labels live in scenarios.jsonl; neutral PCAP names prevent filename inference.",
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Output directory for manifests")
    args = parser.parse_args()
    scenarios = build_catalog()
    validate_catalog(scenarios)
    write_catalog(args.output, scenarios)
    print(f"wrote {len(scenarios)} scenarios to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
