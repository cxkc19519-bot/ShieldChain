from dataclasses import replace
from datetime import UTC, datetime

import pytest

from shieldchain.incidents.domain import Conclusion, Evidence, RiskLevel
from shieldchain.incidents.rules import assess
from shieldchain.incidents.scenario import collect_evidence, seed_phishing_scenario

NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)


def _evidence() -> tuple[Evidence, ...]:
    return collect_evidence(seed_phishing_scenario(NOW), NOW)


def _with_payload(item: Evidence, **changes: object) -> Evidence:
    payload = dict(item.payload)
    payload.update(changes)
    return replace(item, payload=payload)


def test_full_consistent_evidence_confirms_all_rules_in_order() -> None:
    evidence = _evidence()
    result = assess(evidence)

    assert result.conclusion is Conclusion.CONFIRMED_THREAT
    assert result.risk_level is RiskLevel.HIGH
    assert result.rule_ids == (
        "PHISH-001",
        "PHISH-002",
        "PHISH-003",
        "PHISH-004",
        "PHISH-005",
    )
    assert result.evidence_ids == tuple(item.id for item in evidence)
    assert result.recommended_action == "block_ip"


def test_assessment_reads_payload_not_summary_or_reference() -> None:
    evidence = tuple(
        replace(item, summary="misleading", raw_reference="simulation://misleading")
        for item in _evidence()
    )

    assert assess(evidence).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    "change",
    [
        {"summary": "tampered"},
        {"raw_reference": "simulation://tampered"},
        {"confidence": 0.5},
        {"confirmed": False},
        {"integrity_sha256": "0" * 64},
    ],
)
def test_integrity_tamper_cannot_confirm_a_threat(change: dict[str, object]) -> None:
    evidence = list(_evidence())
    evidence[0] = replace(evidence[0], **change)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize("missing_index", range(5))
def test_missing_evidence_type_is_insufficient(missing_index: int) -> None:
    evidence = _evidence()
    result = assess(evidence[:missing_index] + evidence[missing_index + 1 :])

    assert result.conclusion is Conclusion.INSUFFICIENT_EVIDENCE
    assert result.risk_level is RiskLevel.UNKNOWN
    assert result.rule_ids == ()
    assert result.evidence_ids == ()
    assert result.recommended_action is None


def test_duplicate_evidence_type_is_insufficient() -> None:
    evidence = _evidence()
    assert assess(evidence + (evidence[0],)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_duplicate_evidence_identifier_across_types_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[1] = replace(evidence[1], id=evidence[0].id)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_duplicate_evidence_digest_across_types_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[1] = replace(evidence[1], integrity_sha256=evidence[0].integrity_sha256)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_unexpected_evidence_source_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[0] = replace(evidence[0], source="untrusted_source")
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_extra_payload_field_is_malformed_and_insufficient() -> None:
    evidence = list(_evidence())
    evidence[0] = _with_payload(evidence[0], unexpected="value")
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_unconfirmed_evidence_is_insufficient() -> None:
    evidence = _evidence()
    changed = evidence[:2] + (replace(evidence[2], confirmed=False),) + evidence[3:]
    assert assess(changed).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    ("index", "changes"),
    [
        (0, {"alert_id": ""}),
        (1, {"remote_port": "443"}),
        (2, {"malicious": "true"}),
        (3, {"endpoint": None}),
        (4, {"parent_family": 7}),
    ],
)
def test_malformed_payload_fields_are_insufficient(index: int, changes: dict[str, object]) -> None:
    evidence = list(_evidence())
    evidence[index] = _with_payload(evidence[index], **changes)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    ("index", "changes"),
    [
        (1, {"remote_ip": "198.51.100.25"}),
        (2, {"remote_ip": "198.51.100.25"}),
        (3, {"endpoint": "PC-999"}),
        (4, {"process_name": "cmd.exe"}),
    ],
)
def test_conflicting_identity_fields_are_insufficient(
    index: int, changes: dict[str, object]
) -> None:
    evidence = list(_evidence())
    evidence[index] = _with_payload(evidence[index], **changes)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_noncanonical_alert_identity_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[0] = _with_payload(evidence[0], alert_id="ALT-OTHER")
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_internally_consistent_noncanonical_target_ip_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[1] = _with_payload(evidence[1], remote_ip="203.0.113.99")
    evidence[2] = _with_payload(evidence[2], remote_ip="203.0.113.99")
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


def test_noncanonical_target_port_is_insufficient() -> None:
    evidence = list(_evidence())
    evidence[1] = _with_payload(evidence[1], remote_port=80)
    assert assess(tuple(evidence)).conclusion is Conclusion.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize(
    ("index", "changes"),
    [
        (0, {"status": "closed"}),
        (1, {"status": "blocked"}),
        (2, {"malicious": False}),
        (3, {"process_name": "cmd.exe"}),
        (4, {"parent_process_name": "explorer.exe"}),
        (4, {"parent_family": "browser"}),
    ],
)
def test_non_matching_rule_fields_are_insufficient(index: int, changes: dict[str, object]) -> None:
    evidence = list(_evidence())
    evidence[index] = _with_payload(evidence[index], **changes)
    result = assess(tuple(evidence))
    assert result.conclusion is Conclusion.INSUFFICIENT_EVIDENCE
    assert result.recommended_action is None
