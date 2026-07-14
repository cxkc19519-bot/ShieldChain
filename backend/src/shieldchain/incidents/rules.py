from __future__ import annotations

from ipaddress import IPv4Address

from shieldchain.incidents.domain import Assessment, Conclusion, Evidence, RiskLevel

_EVIDENCE_TYPES = (
    "alert",
    "network_connection",
    "threat_intelligence",
    "process",
    "parent_process",
)
_RULE_IDS = ("PHISH-001", "PHISH-002", "PHISH-003", "PHISH-004", "PHISH-005")
_SOURCES = {
    "alert": "simulated_siem",
    "network_connection": "simulated_edr",
    "threat_intelligence": "simulated_ti",
    "process": "simulated_edr",
    "parent_process": "simulated_edr",
}
_PAYLOAD_KEYS = {
    "alert": {"alert_id", "status", "endpoint", "username"},
    "network_connection": {
        "source_ip",
        "remote_ip",
        "remote_port",
        "status",
        "process_name",
    },
    "threat_intelligence": {"remote_ip", "label", "malicious"},
    "process": {"endpoint", "process_name"},
    "parent_process": {
        "endpoint",
        "process_name",
        "parent_process_name",
        "parent_family",
    },
}


def _unknown() -> Assessment:
    return Assessment(
        conclusion=Conclusion.INSUFFICIENT_EVIDENCE,
        risk_level=RiskLevel.UNKNOWN,
        rule_ids=(),
        evidence_ids=(),
        recommended_action=None,
        explanation="Evidence is incomplete, malformed, conflicting, or does not match all rules.",
    )


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _ipv4_text(value: object) -> bool:
    if not _non_empty_text(value):
        return False
    try:
        IPv4Address(value)
    except ValueError:
        return False
    return True


def _valid_payloads(items: dict[str, Evidence]) -> bool:
    alert = items["alert"].payload
    connection = items["network_connection"].payload
    intelligence = items["threat_intelligence"].payload
    process = items["process"].payload
    parent = items["parent_process"].payload
    return (
        all(
            _non_empty_text(alert.get(key))
            for key in ("alert_id", "status", "endpoint", "username")
        )
        and _ipv4_text(connection.get("source_ip"))
        and _ipv4_text(connection.get("remote_ip"))
        and isinstance(connection.get("remote_port"), int)
        and not isinstance(connection.get("remote_port"), bool)
        and 1 <= connection["remote_port"] <= 65535
        and all(_non_empty_text(connection.get(key)) for key in ("status", "process_name"))
        and _ipv4_text(intelligence.get("remote_ip"))
        and _non_empty_text(intelligence.get("label"))
        and isinstance(intelligence.get("malicious"), bool)
        and all(_non_empty_text(process.get(key)) for key in ("endpoint", "process_name"))
        and all(
            _non_empty_text(parent.get(key))
            for key in ("endpoint", "process_name", "parent_process_name", "parent_family")
        )
    )


def assess(evidence: tuple[Evidence, ...]) -> Assessment:
    if len(evidence) != len(_EVIDENCE_TYPES) or not all(item.confirmed for item in evidence):
        return _unknown()
    items = {item.evidence_type: item for item in evidence}
    if len(items) != len(_EVIDENCE_TYPES) or set(items) != set(_EVIDENCE_TYPES):
        return _unknown()
    if len({item.id for item in evidence}) != len(evidence):
        return _unknown()
    if len({item.integrity_sha256 for item in evidence}) != len(evidence):
        return _unknown()
    if any(item.source != _SOURCES[item.evidence_type] for item in evidence):
        return _unknown()
    if any(set(item.payload) != _PAYLOAD_KEYS[item.evidence_type] for item in evidence):
        return _unknown()
    if not _valid_payloads(items):
        return _unknown()

    alert = items["alert"].payload
    connection = items["network_connection"].payload
    intelligence = items["threat_intelligence"].payload
    process = items["process"].payload
    parent = items["parent_process"].payload
    endpoint = alert["endpoint"]
    remote_ip = connection["remote_ip"]
    process_name = connection["process_name"]
    if not (
        alert["alert_id"] == "ALT-2026-0001"
        and alert["status"] == "pending"
        and remote_ip == "198.51.100.24"
        and connection["remote_port"] == 443
        and connection["status"] == "active"
        and intelligence["remote_ip"] == remote_ip
        and intelligence["malicious"] is True
        and process_name == process["process_name"] == parent["process_name"] == "powershell.exe"
        and endpoint == process["endpoint"] == parent["endpoint"]
        and parent["parent_process_name"] == "WINWORD.EXE"
        and parent["parent_family"] == "office"
    ):
        return _unknown()
    return Assessment(
        conclusion=Conclusion.CONFIRMED_THREAT,
        risk_level=RiskLevel.HIGH,
        rule_ids=_RULE_IDS,
        evidence_ids=tuple(item.id for item in evidence),
        recommended_action="block_ip",
        explanation="All five deterministic phishing rules matched consistent evidence.",
    )
