from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, update

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.domain import (
    Assessment,
    Conclusion,
    InvestigationStatus,
    RiskLevel,
    RunMode,
    VerificationResult,
)
from shieldchain.incidents.persistence import (
    AuditEventRow,
    EvidenceRecordRow,
    InvestigationRunRow,
    InvestigationStepRow,
    SimulationToolCallRow,
)
from shieldchain.incidents.ports import (
    InvalidInvestigationState,
    InvestigationNotFound,
)
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository
from shieldchain.incidents.rules import assess
from shieldchain.incidents.scenario import collect_evidence, seed_phishing_scenario
from shieldchain.incidents.tools import SimulatedFirewall, verify_block
from shieldchain.incidents.workflow import InvestigationWorkflow

NOW = datetime(2026, 7, 14, 9, 0, tzinfo=UTC)


class RecordingClock:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> datetime:
        value = NOW + timedelta(milliseconds=self.calls)
        self.calls += 1
        return value


class RecordingFirewall(SimulatedFirewall):
    def __init__(self) -> None:
        self.calls = 0

    def block_ip(self, *args, **kwargs):
        self.calls += 1
        return super().block_ip(*args, **kwargs)


@pytest.fixture
def environment(tmp_path: Path):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'workflow.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    repository = SqlAlchemyIncidentRepository(seed_phishing_scenario)
    with factory.begin() as session:
        state = repository.reset_phishing_scenario(session, now=NOW)
        run = repository.create_run(
            session,
            simulation_id=state.simulation_id,
            mode=RunMode.NORMAL,
            request_id="create-run",
            now=NOW,
        )
    yield engine, factory, repository, state, run
    engine.dispose()


def _workflow(repository, *, firewall=None, sleeper=None, clock=None, **kwargs):
    return InvestigationWorkflow(
        repository,
        firewall or RecordingFirewall(),
        clock or RecordingClock(),
        sleeper or (lambda _delay: None),
        0,
        **kwargs,
    )


def _run_rows(factory, run_id: UUID):
    with factory() as session:
        run = session.get(InvestigationRunRow, str(run_id))
        steps = tuple(
            session.execute(
                select(InvestigationStepRow)
                .where(InvestigationStepRow.run_id == str(run_id))
                .order_by(InvestigationStepRow.started_at)
            ).scalars()
        )
        audits = tuple(
            session.execute(
                select(AuditEventRow)
                .where(AuditEventRow.run_id == str(run_id))
                .order_by(AuditEventRow.sequence)
            ).scalars()
        )
        return run, steps, audits


def test_workflow_closes_only_after_verified_state(environment) -> None:
    _engine, factory, repository, state, run = environment
    sleeps: list[float] = []
    workflow = _workflow(repository, sleeper=sleeps.append)

    result = workflow.run(factory, run.id, request_id="workflow")

    stored, steps, audits = _run_rows(factory, run.id)
    with factory() as session:
        simulation = repository.get_simulation(session, state.simulation_id)
    assert result is InvestigationStatus.CLOSED
    assert stored.status == "closed"
    assert simulation.connection_status == "blocked"
    assert [row.step_key for row in steps] == ["collect", "analyze", "block_ip", "verify"]
    assert [row.status for row in steps] == ["succeeded"] * 4
    assert [event.event_type for event in audits if event.event_type != "status_changed"] == [
        "run_created",
        "evidence_collected",
        "assessment_completed",
        "tool_called",
        "verification_completed",
    ]
    assert [
        event.payload_json["to_status"] for event in audits if event.event_type == "status_changed"
    ] == ["collecting", "analyzing", "action_planned", "executing", "verifying", "closed"]
    assert sleeps == [0, 0, 0]
    assert steps[0].detail_json["evidence_count"] == 5
    assert set(steps[0].detail_json) == {"evidence_count", "evidence_types"}
    assert set(steps[1].detail_json) == {"conclusion", "risk_level", "rule_ids"}
    assert set(steps[2].detail_json) == {"tool_name", "target", "result_status"}
    assert set(steps[3].detail_json) == {"blocked", "connection_stopped"}


def test_insufficient_evidence_needs_review_without_tool_call(environment) -> None:
    _engine, factory, repository, state, run = environment
    sleeps: list[float] = []
    insufficient = Assessment(
        conclusion=Conclusion.INSUFFICIENT_EVIDENCE,
        risk_level=RiskLevel.UNKNOWN,
        rule_ids=(),
        evidence_ids=(),
        recommended_action=None,
        explanation="not enough",
    )
    workflow = _workflow(
        repository,
        sleeper=sleeps.append,
        evidence_collector=lambda _state, _now: (),
        assessor=lambda _evidence: insufficient,
    )

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.NEEDS_REVIEW
    stored, steps, _audits = _run_rows(factory, run.id)
    with factory() as session:
        tool_count = session.scalar(select(func.count()).select_from(SimulationToolCallRow))
    assert stored.status == "needs_review"
    assert [row.step_key for row in steps] == ["collect", "analyze"]
    assert tool_count == 0
    assert sleeps == [0]


def test_tool_failure_never_verifies_or_records_closed(environment) -> None:
    _engine, factory, repository, state, run = environment
    sleeps: list[float] = []
    verifier_calls: list[object] = []
    workflow = _workflow(
        repository,
        sleeper=sleeps.append,
        verifier=lambda *args: verifier_calls.append(args),
    )

    result = workflow.run(factory, run.id, request_id="workflow", fail_block_once=True)

    stored, steps, audits = _run_rows(factory, run.id)
    with factory() as session:
        simulation = repository.get_simulation(session, state.simulation_id)
    assert result is InvestigationStatus.FAILED
    assert stored.status == "failed"
    assert simulation.connection_status == "active"
    assert verifier_calls == []
    assert sleeps == [0, 0]
    assert [row.step_key for row in steps] == ["collect", "analyze", "block_ip"]
    assert steps[-1].status == "failed"
    assert steps[-1].detail_json == {"error_code": "simulated_block_failure"}
    assert "closed" not in [event.payload_json.get("to_status") for event in audits]


@pytest.mark.parametrize(
    "terminal",
    [
        InvestigationStatus.CLOSED,
        InvestigationStatus.FAILED,
        InvestigationStatus.NEEDS_REVIEW,
        InvestigationStatus.INTERRUPTED,
    ],
)
def test_terminal_run_returns_without_side_effects(environment, terminal) -> None:
    _engine, factory, repository, _state, run = environment
    with factory.begin() as session:
        session.execute(
            update(InvestigationRunRow)
            .where(InvestigationRunRow.id == str(run.id))
            .values(status=terminal.value)
        )
    clock = RecordingClock()
    firewall = RecordingFirewall()
    sleeps: list[float] = []
    workflow = _workflow(repository, clock=clock, firewall=firewall, sleeper=sleeps.append)
    before = _run_rows(factory, run.id)
    with factory() as session:
        tool_count_before = session.scalar(
            select(func.count()).select_from(SimulationToolCallRow)
        )

    assert workflow.run(factory, run.id, request_id="workflow") is terminal

    after = _run_rows(factory, run.id)
    with factory() as session:
        tool_count_after = session.scalar(
            select(func.count()).select_from(SimulationToolCallRow)
        )
    assert len(after[1]) == len(before[1]) == 0
    assert len(after[2]) == len(before[2])
    assert tool_count_after == tool_count_before
    assert clock.calls == firewall.calls == 0
    assert sleeps == []


def test_correctly_owned_retry_returns_original_result_without_second_audit(environment) -> None:
    _engine, factory, repository, state, run = environment
    key = f"block-ip:{run.id}:{state.remote_ip}"
    with factory.begin() as session:
        outcome = SimulatedFirewall().block_ip(state, state.remote_ip, key, fail_once=True)
        repository.apply_tool_outcome(session, run.id, outcome, request_id="seed-tool", now=NOW)
    with factory() as session:
        audit_count_before = session.scalar(
            select(func.count())
            .select_from(AuditEventRow)
            .where(
                AuditEventRow.run_id == str(run.id),
                AuditEventRow.event_type == "tool_called",
            )
        )
    firewall = RecordingFirewall()
    workflow = _workflow(repository, firewall=firewall)

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.FAILED
    with factory() as session:
        stored_tool = session.scalar(
            select(SimulationToolCallRow).where(
                SimulationToolCallRow.idempotency_key == key
            )
        )
        audit_count_after = session.scalar(
            select(func.count())
            .select_from(AuditEventRow)
            .where(
                AuditEventRow.run_id == str(run.id),
                AuditEventRow.event_type == "tool_called",
            )
        )
    assert firewall.calls == 1
    assert stored_tool.status == "failed"
    assert stored_tool.error_code == "simulated_block_failure"
    assert audit_count_after == audit_count_before == 1


def test_misowned_idempotency_row_cannot_advance_execution(environment) -> None:
    _engine, factory, repository, state, run = environment
    key = f"block-ip:{run.id}:{state.remote_ip}"
    with factory.begin() as session:
        session.add(
            SimulationToolCallRow(
                id=str(uuid4()),
                run_id=str(run.id),
                simulation_instance_id=str(state.simulation_id),
                tool_name="block_ip",
                target="203.0.113.99",
                idempotency_key=key,
                status="blocked",
                before_state_json={"firewall_status": "not_blocked"},
                after_state_json={"firewall_status": "blocked"},
                error_code=None,
                requested_at=NOW,
                completed_at=NOW,
            )
        )

    firewall = RecordingFirewall()
    workflow = _workflow(repository, firewall=firewall)

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.FAILED

    stored, steps, audits = _run_rows(factory, run.id)
    with factory() as session:
        simulation = repository.get_simulation(session, state.simulation_id)
    assert stored.status == InvestigationStatus.FAILED.value
    assert simulation.connection_status == "active"
    assert simulation.firewall_status == "not_blocked"
    block_step = next(step for step in steps if step.step_key == "block_ip")
    assert block_step.status == "failed"
    assert block_step.error_code == "workflow_step_failed"
    transitions = [
        event.payload_json.get("to_status")
        for event in audits
        if event.event_type == "status_changed"
    ]
    assert InvestigationStatus.VERIFYING.value not in transitions
    assert InvestigationStatus.CLOSED.value not in transitions


def test_each_pause_observes_committed_phase_state(environment) -> None:
    _engine, factory, repository, _state, run = environment
    observed: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    def inspect(_delay: float) -> None:
        stored, steps, _audits = _run_rows(factory, run.id)
        observed.append((stored.status, tuple((row.step_key, row.status) for row in steps)))

    workflow = _workflow(repository, sleeper=inspect)
    workflow.run(factory, run.id, request_id="workflow")

    assert [item[0] for item in observed] == ["analyzing", "action_planned", "verifying"]
    assert observed[0][1] == (("collect", "succeeded"),)
    assert observed[1][1][-1] == ("analyze", "succeeded")
    assert observed[2][1][-1] == ("block_ip", "succeeded")


def test_each_phase_body_observes_its_committed_running_state(environment) -> None:
    _engine, factory, repository, _state, run = environment
    observed: list[tuple[str, str, str]] = []

    def inspect(step_key: str) -> None:
        stored, steps, _audits = _run_rows(factory, run.id)
        step = next(row for row in steps if row.step_key == step_key)
        observed.append((step_key, stored.status, step.status))

    def collecting(state, now):
        inspect("collect")
        return collect_evidence(state, now)

    def analyzing(evidence):
        inspect("analyze")
        return assess(evidence)

    class InspectingFirewall(SimulatedFirewall):
        def block_ip(self, *args, **kwargs):
            inspect("block_ip")
            return super().block_ip(*args, **kwargs)

    def verifying(state, ip, now):
        inspect("verify")
        return verify_block(state, ip, now)

    workflow = _workflow(
        repository,
        firewall=InspectingFirewall(),
        evidence_collector=collecting,
        assessor=analyzing,
        verifier=verifying,
    )

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.CLOSED
    assert observed == [
        ("collect", "collecting", "running"),
        ("analyze", "analyzing", "running"),
        ("block_ip", "executing", "running"),
        ("verify", "verifying", "running"),
    ]


def test_failed_verification_persists_safe_failure_and_never_closes(environment) -> None:
    _engine, factory, repository, _state, run = environment

    def fail_verification(_state, _ip, now):
        return VerificationResult(
            blocked=True,
            connection_stopped=False,
            observed_at=now,
            evidence_ids=(),
        )

    workflow = _workflow(repository, verifier=fail_verification)

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.FAILED
    stored, steps, audits = _run_rows(factory, run.id)
    verify = next(row for row in steps if row.step_key == "verify")
    assert stored.status == "failed"
    assert verify.status == "failed"
    assert verify.error_code == "verification_failed"
    assert verify.detail_json == {"error_code": "verification_failed"}
    assert "closed" not in [event.payload_json.get("to_status") for event in audits]


@pytest.mark.parametrize(
    ("failing_dependency", "expected_status", "step_key"),
    [
        ("collector", InvestigationStatus.INTERRUPTED, "collect"),
        ("assessor", InvestigationStatus.INTERRUPTED, "analyze"),
        ("firewall", InvestigationStatus.FAILED, "block_ip"),
        ("verifier", InvestigationStatus.FAILED, "verify"),
    ],
)
def test_unexpected_exception_records_only_sanitized_failure(
    environment, failing_dependency, expected_status, step_key
) -> None:
    _engine, factory, repository, _state, run = environment
    secret = "do-not-persist-this-secret"

    def explode(*_args, **_kwargs):
        raise RuntimeError(secret)

    kwargs = {}
    firewall = RecordingFirewall()
    if failing_dependency == "collector":
        kwargs["evidence_collector"] = explode
    elif failing_dependency == "assessor":
        kwargs["assessor"] = explode
    elif failing_dependency == "firewall":
        firewall.block_ip = explode
    else:
        kwargs["verifier"] = explode
    workflow = _workflow(repository, firewall=firewall, **kwargs)

    assert workflow.run(factory, run.id, request_id="workflow") is expected_status

    stored, steps, audits = _run_rows(factory, run.id)
    failed = next(row for row in steps if row.step_key == step_key)
    assert stored.status == expected_status.value
    assert failed.status == "failed"
    assert failed.error_code == "workflow_step_failed"
    assert failed.detail_json == {"error_code": "workflow_step_failed"}
    assert secret not in str([row.detail_json for row in steps])
    assert secret not in str([event.payload_json for event in audits])
    with factory() as session:
        evidence_count = session.scalar(
            select(func.count())
            .select_from(EvidenceRecordRow)
            .where(EvidenceRecordRow.run_id == str(run.id))
        )
        tool_count = session.scalar(
            select(func.count())
            .select_from(SimulationToolCallRow)
            .where(SimulationToolCallRow.run_id == str(run.id))
        )
    if failing_dependency == "collector":
        assert evidence_count == 0
    if failing_dependency == "assessor":
        assert stored.assessment_json is None
    if failing_dependency == "firewall":
        assert tool_count == 0
    if failing_dependency == "verifier":
        assert stored.verification_json is None


def test_non_pending_active_run_is_rejected_without_mutation(environment) -> None:
    _engine, factory, repository, _state, run = environment
    with factory.begin() as session:
        repository.transition_run(
            session,
            run.id,
            InvestigationStatus.COLLECTING,
            request_id="orphan",
            now=NOW,
        )
    workflow = _workflow(repository)
    before = _run_rows(factory, run.id)

    with pytest.raises(InvalidInvestigationState) as caught:
        workflow.run(factory, run.id, request_id="workflow")

    after = _run_rows(factory, run.id)
    assert caught.value.run_id == run.id
    assert caught.value.status is InvestigationStatus.COLLECTING
    assert str(caught.value) == f"invalid investigation state for {run.id}: collecting"
    assert len(after[1]) == len(before[1]) == 0
    assert len(after[2]) == len(before[2])


def test_terminal_race_after_pause_returns_without_next_phase_side_effects(
    environment,
) -> None:
    _engine, factory, repository, _state, run = environment
    clock = RecordingClock()
    firewall = RecordingFirewall()
    collector_calls: list[object] = []
    assessor_calls: list[object] = []
    snapshots: list[tuple[int, int]] = []

    def collecting(state, now):
        collector_calls.append(state)
        return collect_evidence(state, now)

    def analyzing(evidence):
        assessor_calls.append(evidence)
        return assess(evidence)

    def mutate_to_terminal(_delay: float) -> None:
        with factory.begin() as session:
            session.execute(
                update(InvestigationRunRow)
                .where(InvestigationRunRow.id == str(run.id))
                .values(status=InvestigationStatus.FAILED.value)
            )
        _stored, steps, audits = _run_rows(factory, run.id)
        snapshots.append((len(steps), len(audits)))

    workflow = _workflow(
        repository,
        firewall=firewall,
        clock=clock,
        sleeper=mutate_to_terminal,
        evidence_collector=collecting,
        assessor=analyzing,
    )

    assert workflow.run(factory, run.id, request_id="workflow") is InvestigationStatus.FAILED

    stored, steps, audits = _run_rows(factory, run.id)
    assert stored.status == "failed"
    assert (len(steps), len(audits)) == snapshots[0]
    assert len(collector_calls) == 1
    assert assessor_calls == []
    assert firewall.calls == 0
    assert clock.calls == 2
    assert len(snapshots) == 1


def test_active_race_after_pause_raises_original_state_without_rewrite(
    environment,
) -> None:
    _engine, factory, repository, _state, run = environment
    clock = RecordingClock()
    firewall = RecordingFirewall()
    collector_calls: list[object] = []
    assessor_calls: list[object] = []
    snapshots: list[tuple[int, int]] = []

    def mutate_to_other_active(_delay: float) -> None:
        with factory.begin() as session:
            session.execute(
                update(InvestigationRunRow)
                .where(InvestigationRunRow.id == str(run.id))
                .values(status=InvestigationStatus.EXECUTING.value)
            )
        _stored, steps, audits = _run_rows(factory, run.id)
        snapshots.append((len(steps), len(audits)))

    def collecting(state, now):
        collector_calls.append(state)
        return collect_evidence(state, now)

    workflow = _workflow(
        repository,
        firewall=firewall,
        clock=clock,
        sleeper=mutate_to_other_active,
        evidence_collector=collecting,
        assessor=lambda evidence: assessor_calls.append(evidence),
    )

    with pytest.raises(InvalidInvestigationState) as caught:
        workflow.run(factory, run.id, request_id="workflow")

    stored, steps, audits = _run_rows(factory, run.id)
    assert caught.value.run_id == run.id
    assert caught.value.status is InvestigationStatus.EXECUTING
    assert stored.status == "executing"
    assert (len(steps), len(audits)) == snapshots[0]
    assert len(collector_calls) == 1
    assert assessor_calls == []
    assert firewall.calls == 0
    assert clock.calls == 2
    assert len(snapshots) == 1


def test_initial_missing_run_propagates_safe_not_found(environment) -> None:
    _engine, factory, repository, _state, _run = environment
    missing = UUID(int=999)
    workflow = _workflow(repository)

    with pytest.raises(InvestigationNotFound) as caught:
        workflow.run(factory, missing, request_id="workflow")

    assert caught.value.run_id == missing


@pytest.mark.parametrize("delay", [-0.1, 2.1])
def test_delay_must_be_within_allowed_range(environment, delay) -> None:
    _engine, _factory, repository, _state, _run = environment
    with pytest.raises(ValueError, match="step_delay_seconds"):
        InvestigationWorkflow(
            repository,
            RecordingFirewall(),
            RecordingClock(),
            lambda _delay: None,
            delay,
        )
