from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest

from shieldchain.incidents.domain import (
    Assessment,
    AuditEvent,
    BlockOutcome,
    Conclusion,
    Evidence,
    IncidentDetail,
    InvalidInvestigationTransition,
    InvestigationRun,
    InvestigationStatus,
    PhishingScenarioState,
    RiskLevel,
    RunMode,
    StepStatus,
    ToolCallStatus,
    ToolResult,
    VerificationResult,
    is_active,
    is_terminal,
    transition,
)

NOW = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)


def make_evidence(**changes: object) -> Evidence:
    values: dict[str, object] = {
        "id": uuid4(),
        "evidence_type": "network_connection",
        "source": "simulated_edr",
        "observed_at": NOW,
        "summary": "Suspicious outbound connection",
        "raw_reference": "simulation://evidence/alert-1",
        "integrity_sha256": "a" * 64,
        "confidence": 0.95,
        "confirmed": True,
    }
    values.update(changes)
    return Evidence(**values)  # type: ignore[arg-type]


def make_tool_result() -> ToolResult:
    return ToolResult(
        status=ToolCallStatus.BLOCKED,
        tool_name="simulated_firewall",
        target="203.0.113.7",
        idempotency_key="block:203.0.113.7",
        before_state={"firewall_status": "allowed"},
        after_state={"firewall_status": "blocked"},
    )


def make_scenario_state(**changes: object) -> PhishingScenarioState:
    values: dict[str, object] = {
        "simulation_id": uuid4(),
        "generation": 1,
        "environment": "simulation",
        "incident_id": uuid4(),
        "external_incident_id": "INC-001",
        "alert_id": "ALERT-001",
        "endpoint": "workstation-7",
        "username": "analyst",
        "source_ip": IPv4Address("192.0.2.10"),
        "alert_status": "open",
        "remote_ip": IPv4Address("203.0.113.7"),
        "remote_port": 443,
        "process_name": "powershell.exe",
        "parent_process_name": "outlook.exe",
        "command_summary": "downloaded a suspicious payload",
        "threat_label": "phishing",
        "connection_status": "active",
        "firewall_status": "allowed",
        "fail_block_consumed": False,
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(changes)
    return PhishingScenarioState(**values)  # type: ignore[arg-type]


def test_string_enums_have_exact_values() -> None:
    assert [status.value for status in InvestigationStatus] == [
        "pending",
        "collecting",
        "analyzing",
        "action_planned",
        "executing",
        "verifying",
        "needs_review",
        "failed",
        "interrupted",
        "closed",
    ]
    assert [status.value for status in StepStatus] == [
        "pending",
        "running",
        "succeeded",
        "failed",
        "skipped",
    ]
    assert [value.value for value in Conclusion] == [
        "confirmed_threat",
        "insufficient_evidence",
    ]
    assert [value.value for value in RiskLevel] == ["high", "unknown"]
    assert [value.value for value in ToolCallStatus] == [
        "blocked",
        "already_blocked",
        "failed",
    ]
    assert [value.value for value in RunMode] == ["normal", "fail_block_once"]
    assert str(InvestigationStatus.PENDING) == "pending"


def test_happy_path_transitions_are_explicit() -> None:
    status = InvestigationStatus.PENDING
    for target in (
        InvestigationStatus.COLLECTING,
        InvestigationStatus.ANALYZING,
        InvestigationStatus.ACTION_PLANNED,
        InvestigationStatus.EXECUTING,
        InvestigationStatus.VERIFYING,
        InvestigationStatus.CLOSED,
    ):
        status = transition(status, target)
    assert status is InvestigationStatus.CLOSED


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (InvestigationStatus.COLLECTING, InvestigationStatus.NEEDS_REVIEW),
        (InvestigationStatus.COLLECTING, InvestigationStatus.INTERRUPTED),
        (InvestigationStatus.ANALYZING, InvestigationStatus.NEEDS_REVIEW),
        (InvestigationStatus.ANALYZING, InvestigationStatus.INTERRUPTED),
        (InvestigationStatus.ACTION_PLANNED, InvestigationStatus.INTERRUPTED),
        (InvestigationStatus.EXECUTING, InvestigationStatus.FAILED),
        (InvestigationStatus.EXECUTING, InvestigationStatus.INTERRUPTED),
        (InvestigationStatus.VERIFYING, InvestigationStatus.FAILED),
        (InvestigationStatus.VERIFYING, InvestigationStatus.INTERRUPTED),
    ],
)
def test_all_explicit_exception_transitions_are_allowed(
    current: InvestigationStatus, target: InvestigationStatus
) -> None:
    assert transition(current, target) is target


def test_closed_cannot_transition_back_to_executing() -> None:
    with pytest.raises(InvalidInvestigationTransition) as exc_info:
        transition(InvestigationStatus.CLOSED, InvestigationStatus.EXECUTING)

    assert exc_info.value.current is InvestigationStatus.CLOSED
    assert exc_info.value.target is InvestigationStatus.EXECUTING
    assert str(exc_info.value) == "invalid investigation transition: closed -> executing"


@pytest.mark.parametrize("status", list(InvestigationStatus))
def test_only_declared_states_are_terminal_or_active(status: InvestigationStatus) -> None:
    terminal = {
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.FAILED,
        InvestigationStatus.INTERRUPTED,
        InvestigationStatus.CLOSED,
    }
    active = set(InvestigationStatus) - terminal
    assert is_terminal(status) is (status in terminal)
    assert is_active(status) is (status in active)


def test_evidence_is_immutable() -> None:
    evidence = make_evidence()
    with pytest.raises(FrozenInstanceError):
        evidence.summary = "changed"


@pytest.mark.parametrize("field", ["evidence_type", "source", "summary", "raw_reference"])
@pytest.mark.parametrize("value", ["", "   "])
def test_evidence_rejects_empty_required_text(field: str, value: str) -> None:
    with pytest.raises(ValueError):
        make_evidence(**{field: value})


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_evidence_rejects_confidence_outside_closed_unit_interval(confidence: float) -> None:
    with pytest.raises(ValueError):
        make_evidence(confidence=confidence)


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_evidence_accepts_confidence_boundaries(confidence: float) -> None:
    assert make_evidence(confidence=confidence).confidence == confidence


@pytest.mark.parametrize(
    "integrity_sha256",
    ["a" * 63, "a" * 65, "A" * 64, "g" * 64],
)
def test_evidence_rejects_invalid_sha256(integrity_sha256: str) -> None:
    with pytest.raises(ValueError):
        make_evidence(integrity_sha256=integrity_sha256)


@pytest.mark.parametrize(
    "observed_at",
    [datetime(2026, 7, 13, 10, 0), NOW.replace(tzinfo=timezone(timedelta(hours=8)))],
)
def test_evidence_rejects_non_utc_datetime(observed_at: datetime) -> None:
    with pytest.raises(ValueError):
        make_evidence(observed_at=observed_at)


def test_value_objects_preserve_the_exact_contract() -> None:
    evidence = make_evidence()
    assessment = Assessment(
        conclusion=Conclusion.CONFIRMED_THREAT,
        risk_level=RiskLevel.HIGH,
        rule_ids=("rule-1",),
        evidence_ids=(evidence.id,),
        recommended_action="block remote IP",
        explanation="confirmed by deterministic rules",
    )
    tool_result = make_tool_result()
    verification = VerificationResult(
        blocked=True,
        connection_stopped=True,
        observed_at=NOW,
        evidence_ids=(evidence.id,),
    )
    scenario = make_scenario_state()
    outcome = BlockOutcome(state=scenario, result=tool_result)
    run = InvestigationRun(
        id=uuid4(),
        incident_id=scenario.incident_id,
        simulation_instance_id=scenario.simulation_id,
        status=InvestigationStatus.CLOSED,
        mode=RunMode.NORMAL,
        created_at=NOW,
        updated_at=NOW,
        completed_at=NOW,
    )
    detail = IncidentDetail(
        id=scenario.incident_id,
        external_id=scenario.external_incident_id,
        simulation_instance_id=scenario.simulation_id,
        alert_id=scenario.alert_id,
        endpoint=scenario.endpoint,
        username=scenario.username,
        source_ip=scenario.source_ip,
        remote_ip=scenario.remote_ip,
        remote_port=scenario.remote_port,
        process_name=scenario.process_name,
        parent_process_name=scenario.parent_process_name,
        threat_label=scenario.threat_label,
        created_at=NOW,
    )
    audit = AuditEvent(
        id=uuid4(),
        incident_id=scenario.incident_id,
        run_id=run.id,
        event_type="investigation.closed",
        request_id="request-1",
        occurred_at=NOW,
        payload={"status": "closed"},
    )

    assert outcome.result is tool_result
    assert assessment.evidence_ids == verification.evidence_ids
    assert run.completed_at == NOW
    assert detail.remote_port == scenario.remote_port
    assert audit.payload == {"status": "closed"}


@pytest.mark.parametrize(
    "factory",
    [
        lambda value: VerificationResult(False, False, value, ()),
        lambda value: make_scenario_state(created_at=value),
        lambda value: make_scenario_state(updated_at=value),
        lambda value: InvestigationRun(
            uuid4(),
            uuid4(),
            uuid4(),
            InvestigationStatus.PENDING,
            RunMode.NORMAL,
            value,
            NOW,
        ),
        lambda value: IncidentDetail(
            uuid4(),
            "INC-1",
            uuid4(),
            "ALERT-1",
            "host-1",
            "user-1",
            IPv4Address("192.0.2.1"),
            IPv4Address("203.0.113.1"),
            443,
            "child.exe",
            "parent.exe",
            "phishing",
            value,
        ),
        lambda value: AuditEvent(
            uuid4(), uuid4(), None, "created", "request-1", value, {}
        ),
    ],
)
def test_all_dataclass_datetimes_require_aware_utc(
    factory: Callable[[datetime], object],
) -> None:
    with pytest.raises(ValueError):
        factory(datetime(2026, 7, 13, 10, 0))


@pytest.mark.parametrize("generation", [0, -1])
def test_scenario_generation_starts_at_one(generation: int) -> None:
    with pytest.raises(ValueError):
        make_scenario_state(generation=generation)


@pytest.mark.parametrize("remote_port", [0, 65536])
def test_scenario_remote_port_is_valid(remote_port: int) -> None:
    with pytest.raises(ValueError):
        make_scenario_state(remote_port=remote_port)


@pytest.mark.parametrize("remote_port", [1, 65535])
def test_scenario_accepts_remote_port_boundaries(remote_port: int) -> None:
    assert make_scenario_state(remote_port=remote_port).remote_port == remote_port


def test_investigation_run_accepts_absent_completion_time() -> None:
    run = InvestigationRun(
        id=uuid4(),
        incident_id=uuid4(),
        simulation_instance_id=uuid4(),
        status=InvestigationStatus.PENDING,
        mode=RunMode.NORMAL,
        created_at=NOW,
        updated_at=NOW,
    )
    assert run.completed_at is None


def test_all_value_objects_are_frozen() -> None:
    result = make_tool_result()
    with pytest.raises(FrozenInstanceError):
        result.target = "changed"


def test_ids_are_uuid_values() -> None:
    evidence = make_evidence()
    assert isinstance(evidence.id, UUID)


def test_assessment_rejects_empty_rule_identifier() -> None:
    with pytest.raises(ValueError):
        Assessment(
            conclusion=Conclusion.CONFIRMED_THREAT,
            risk_level=RiskLevel.HIGH,
            rule_ids=("   ",),
            evidence_ids=(uuid4(),),
            recommended_action=None,
            explanation="rule matched",
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Assessment(
            conclusion=Conclusion.CONFIRMED_THREAT,
            risk_level=RiskLevel.HIGH,
            rule_ids=("rule-1",),
            evidence_ids=("not-a-uuid",),  # type: ignore[arg-type]
            recommended_action=None,
            explanation="rule matched",
        ),
        lambda: VerificationResult(
            blocked=False,
            connection_stopped=False,
            observed_at=NOW,
            evidence_ids=("not-a-uuid",),  # type: ignore[arg-type]
        ),
    ],
)
def test_evidence_identifier_references_must_be_uuids(factory: Callable[[], object]) -> None:
    with pytest.raises(TypeError):
        factory()
