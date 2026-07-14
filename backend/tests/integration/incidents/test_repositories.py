from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.domain import (
    Assessment,
    BlockOutcome,
    Conclusion,
    Evidence,
    InvestigationStatus,
    PhishingScenarioState,
    RiskLevel,
    RunMode,
    StepStatus,
    ToolCallStatus,
    ToolResult,
    VerificationResult,
)
from shieldchain.incidents.integrity import create_evidence
from shieldchain.incidents.persistence import (
    AuditEventRow,
    EvidenceRecordRow,
    InvestigationStepRow,
)
from shieldchain.incidents.ports import (
    ActiveInvestigationExists,
    DuplicateEvidence,
    DuplicateIdempotencyKey,
    EvidenceIntegrityMismatch,
    IdempotencyConflict,
    IncidentRepository,
    InvalidInvestigationState,
    RunSimulationMismatch,
    SimulationNotFound,
)
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository

NOW = datetime(2026, 7, 14, 8, 30, tzinfo=UTC)


class ScenarioFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, now: datetime) -> PhishingScenarioState:
        self.calls += 1
        suffix = self.calls
        return PhishingScenarioState(
            simulation_id=UUID(int=100 + suffix),
            generation=1,
            environment="simulation",
            incident_id=UUID(int=200 + suffix),
            external_incident_id="INC-2026-0001",
            alert_id=f"ALT-{suffix}",
            endpoint="workstation-23",
            username="alice",
            source_ip=IPv4Address("10.0.0.23"),
            alert_status=f"triaged-{suffix}",
            remote_ip=IPv4Address("203.0.113.44"),
            remote_port=443,
            process_name="powershell.exe",
            parent_process_name="outlook.exe",
            command_summary="download payload",
            threat_label="credential-phishing",
            connection_status="active",
            firewall_status="not_blocked",
            fail_block_consumed=False,
            created_at=now,
            updated_at=now,
        )


@pytest.fixture
def session(tmp_path: Path) -> Session:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'repository.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as value:
        yield value
    engine.dispose()


@pytest.fixture
def repository() -> SqlAlchemyIncidentRepository:
    return SqlAlchemyIncidentRepository(ScenarioFactory())


@pytest.fixture
def simulation(session: Session, repository: SqlAlchemyIncidentRepository) -> PhishingScenarioState:
    state = repository.reset_phishing_scenario(session, now=NOW)
    session.commit()
    return state


def _create_run(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation_id: UUID,
    *,
    request_id: str = "req-create",
):
    return repository.create_run(
        session,
        simulation_id=simulation_id,
        mode=RunMode.NORMAL,
        request_id=request_id,
        now=NOW,
    )


def _evidence(evidence_id: int = 301, digest: str = "a" * 64) -> Evidence:
    return create_evidence(
        evidence_type="network_connection",
        source="simulation",
        observed_at=NOW,
        summary=f"sensitive evidence summary {digest}",
        raw_reference=f"memory://secret-packet/{evidence_id}",
        confidence=0.95,
        confirmed=True,
        payload={"remote_ip": "203.0.113.44", "remote_port": 443, "active": True},
    )


def _tool_outcome(state: PhishingScenarioState, key: str = "block-1") -> BlockOutcome:
    updated = replace(
        state,
        connection_status="blocked",
        firewall_status="blocked",
        updated_at=NOW + timedelta(seconds=10),
    )
    return BlockOutcome(
        state=updated,
        result=ToolResult(
            status=ToolCallStatus.BLOCKED,
            tool_name="block_ip",
            target=str(state.remote_ip),
            idempotency_key=key,
            before_state={"firewall_status": "not_blocked"},
            after_state={"firewall_status": "blocked"},
        ),
    )


def test_repository_implements_protocol(repository: SqlAlchemyIncidentRepository) -> None:
    assert isinstance(repository, IncidentRepository)
    assert not hasattr(repository, "update_evidence")
    assert not hasattr(repository, "delete_evidence")


def test_record_step_inserts_then_updates_the_same_row(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    started = NOW + timedelta(seconds=1)
    repository.record_step(
        session,
        run.id,
        step_key="collect",
        status=StepStatus.RUNNING,
        detail={"evidence_count": 0, "evidence_types": []},
        error_code=None,
        started_at=started,
        completed_at=None,
    )
    repository.record_step(
        session,
        run.id,
        step_key="collect",
        status=StepStatus.SUCCEEDED,
        detail={"evidence_count": 5, "evidence_types": ["alert"]},
        error_code=None,
        started_at=started,
        completed_at=NOW + timedelta(seconds=2),
    )

    rows = tuple(
        session.execute(
            select(InvestigationStepRow).where(InvestigationStepRow.run_id == str(run.id))
        ).scalars()
    )
    assert len(rows) == 1
    assert rows[0].status == "succeeded"
    assert rows[0].detail_json == {
        "evidence_count": 5,
        "evidence_types": ["alert"],
    }
    assert rows[0].started_at == started.replace(tzinfo=None)
    assert rows[0].completed_at == (NOW + timedelta(seconds=2)).replace(tzinfo=None)


def test_record_step_only_flushes_and_leaves_rollback_to_caller(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()

    repository.record_step(
        session,
        run.id,
        step_key="analyze",
        status=StepStatus.FAILED,
        detail={"error_code": "workflow_step_failed"},
        error_code="workflow_step_failed",
        started_at=NOW,
        completed_at=NOW,
    )
    session.rollback()

    assert (
        session.execute(
            select(InvestigationStepRow).where(InvestigationStepRow.run_id == str(run.id))
        ).scalar_one_or_none()
        is None
    )


def test_sqlite_engine_enables_foreign_keys(session: Session) -> None:
    assert session.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


def test_sqlite_allows_two_simultaneous_read_transactions(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'readers.db'}")
    session_factory = create_session_factory(engine)
    with session_factory() as first, session_factory() as second:
        assert first.execute(text("SELECT 1")).scalar_one() == 1
        assert second.execute(text("SELECT 1")).scalar_one() == 1
    engine.dispose()


def test_reset_persists_generations_and_fixed_incident_number(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    first = repository.reset_phishing_scenario(session, now=NOW)
    session.commit()
    second = repository.reset_phishing_scenario(session, now=NOW + timedelta(minutes=1))
    session.commit()

    assert (first.generation, second.generation) == (1, 2)
    assert first.external_incident_id == second.external_incident_id == "INC-2026-0001"
    assert repository.get_simulation(session, first.simulation_id) == first
    assert repository.get_incident(session, first.incident_id) is not None
    assert [event.event_type for event in repository.list_audit(session, second.incident_id)] == [
        "simulation_reset"
    ]


def test_reset_refuses_while_an_investigation_is_active(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    _create_run(session, repository, simulation.simulation_id)
    session.commit()

    with pytest.raises(ActiveInvestigationExists) as caught:
        repository.reset_phishing_scenario(session, now=NOW + timedelta(minutes=1))

    assert caught.value.simulation_id == simulation.simulation_id
    assert "SELECT" not in str(caught.value)


def test_cancel_pending_run_removes_only_run_owned_rows(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    reset_event = session.scalar(
        select(AuditEventRow).where(AuditEventRow.event_type == "simulation_reset")
    )
    run_event = session.scalar(
        select(AuditEventRow).where(AuditEventRow.run_id == str(run.id))
    )

    repository.cancel_pending_run(session, run.id)
    session.commit()

    assert repository.get_run(session, run.id) is None
    assert session.get(AuditEventRow, reset_event.id) is not None
    assert session.get(AuditEventRow, run_event.id) is None
    assert reset_event.sequence < run_event.sequence

    replacement = _create_run(
        session, repository, simulation.simulation_id, request_id="req-replacement"
    )
    session.commit()
    sequences = list(
        session.scalars(
            select(AuditEventRow.sequence)
            .where(AuditEventRow.incident_id == str(replacement.incident_id))
            .order_by(AuditEventRow.sequence)
        )
    )
    assert sequences == [reset_event.sequence, run_event.sequence + 1]


def test_cancel_pending_run_rejects_non_pending_status(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    repository.transition_run(
        session,
        run.id,
        InvestigationStatus.COLLECTING,
        request_id="req-transition",
        now=NOW + timedelta(seconds=1),
    )
    session.commit()

    with pytest.raises(InvalidInvestigationState):
        repository.cancel_pending_run(session, run.id)


def test_transition_and_audit_commit_atomically(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    changed = repository.transition_run(
        session,
        run.id,
        InvestigationStatus.COLLECTING,
        request_id="req-transition",
        now=NOW + timedelta(seconds=1),
    )
    assert changed.status is InvestigationStatus.COLLECTING
    session.commit()

    restored = repository.get_run(session, run.id)
    assert restored is not None and restored.status is InvestigationStatus.COLLECTING
    events = repository.list_audit(session, run.incident_id)
    assert [event.event_type for event in events] == [
        "simulation_reset",
        "run_created",
        "status_changed",
    ]
    assert [event.payload for event in events[1:]] == [
        {"run_id": str(run.id), "status": "pending"},
        {"from_status": "pending", "to_status": "collecting"},
    ]


def test_outer_rollback_removes_both_transition_and_audit(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    before = len(repository.list_audit(session, run.incident_id))

    repository.transition_run(
        session,
        run.id,
        InvestigationStatus.COLLECTING,
        request_id="req-rollback",
        now=NOW + timedelta(seconds=1),
    )
    session.rollback()

    restored = repository.get_run(session, run.id)
    assert restored is not None and restored.status is InvestigationStatus.PENDING
    assert len(repository.list_audit(session, run.incident_id)) == before


def test_second_active_run_is_rejected_without_poisoning_session(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    first = _create_run(session, repository, simulation.simulation_id)
    session.commit()

    with pytest.raises(ActiveInvestigationExists) as caught:
        _create_run(session, repository, simulation.simulation_id, request_id="req-duplicate")

    assert caught.value.simulation_id == simulation.simulation_id
    assert "UNIQUE" not in str(caught.value)
    assert repository.get_run(session, first.id) == first
    assert session.execute(text("SELECT 1")).scalar_one() == 1


def test_concurrent_active_run_attempts_have_exactly_one_winner(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'concurrent.db'}")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyIncidentRepository(ScenarioFactory())
    with session_factory() as setup_session:
        state = repository.reset_phishing_scenario(setup_session, now=NOW)
        setup_session.commit()

    barrier = Barrier(2)

    def attempt(request_id: str) -> str:
        with session_factory() as worker_session:
            barrier.wait()
            try:
                repository.create_run(
                    worker_session,
                    simulation_id=state.simulation_id,
                    mode=RunMode.NORMAL,
                    request_id=request_id,
                    now=NOW,
                )
                worker_session.commit()
            except ActiveInvestigationExists:
                assert worker_session.execute(text("SELECT 1")).scalar_one() == 1
                return "rejected"
            return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(executor.map(attempt, ("concurrent-1", "concurrent-2")))
    engine.dispose()

    assert results == ["created", "rejected"]


def test_concurrent_evidence_appends_allocate_distinct_audit_sequences(
    tmp_path: Path,
) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'audit-concurrent.db'}")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyIncidentRepository(ScenarioFactory())
    with session_factory() as setup_session:
        state = repository.reset_phishing_scenario(setup_session, now=NOW)
        run = _create_run(setup_session, repository, state.simulation_id)
        setup_session.commit()

    barrier = Barrier(2)

    def append(item: Evidence, request_id: str) -> None:
        with session_factory() as worker_session:
            barrier.wait()
            repository.append_evidence(
                worker_session, run.id, [item], request_id=request_id
            )
            worker_session.commit()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(append, _evidence(401, "b" * 64), "audit-1"),
            executor.submit(append, _evidence(402, "c" * 64), "audit-2"),
        ]
        for future in futures:
            future.result()

    with session_factory() as verify_session:
        sequences = tuple(
            verify_session.execute(
                select(AuditEventRow.sequence)
                .where(AuditEventRow.incident_id == str(run.incident_id))
                .order_by(AuditEventRow.sequence)
            ).scalars()
        )
    engine.dispose()

    assert sequences == tuple(range(1, len(sequences) + 1))
    assert len(sequences) == len(set(sequences)) == 4


def test_missing_simulation_uses_safe_domain_exception(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    missing = UUID(int=999)
    with pytest.raises(SimulationNotFound) as caught:
        _create_run(session, repository, missing)
    assert caught.value.simulation_id == missing
    assert str(missing) in str(caught.value)


def test_create_run_does_not_mislabel_unrelated_integrity_error(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_audit(*_args, **_kwargs) -> None:
        raise IntegrityError("audit insert", {}, Exception("unrelated audit constraint"))

    monkeypatch.setattr(repository, "_append_audit", fail_audit)
    with pytest.raises(IntegrityError):
        _create_run(session, repository, simulation.simulation_id)


def test_duplicate_evidence_rolls_back_savepoint_and_keeps_session_usable(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    evidence = _evidence()
    repository.append_evidence(session, run.id, [evidence], request_id="req-evidence")
    session.commit()

    with pytest.raises(DuplicateEvidence) as caught:
        repository.append_evidence(session, run.id, [evidence], request_id="req-duplicate")

    assert caught.value.evidence_id == evidence.id
    repository.transition_run(
        session,
        run.id,
        InvestigationStatus.COLLECTING,
        request_id="req-still-usable",
        now=NOW + timedelta(seconds=1),
    )
    session.commit()
    assert repository.get_run(session, run.id).status is InvestigationStatus.COLLECTING


def test_duplicate_evidence_reports_the_actual_offending_uuid(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    first = _evidence(501, "d" * 64)
    with pytest.raises(DuplicateEvidence) as caught:
        repository.append_evidence(
            session, run.id, [first, first], request_id="duplicate-batch"
        )

    assert caught.value.evidence_id == first.id


def test_cross_run_id_conflict_does_not_create_a_false_digest_conflict(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    state_a = repository.reset_phishing_scenario(session, now=NOW)
    state_b = repository.reset_phishing_scenario(session, now=NOW + timedelta(minutes=1))
    run_a = _create_run(session, repository, state_a.simulation_id, request_id="run-a")
    run_b = _create_run(session, repository, state_b.simulation_id, request_id="run-b")
    evidence_x = _evidence(601, "6" * 64)
    repository.append_evidence(
        session, run_a.id, [evidence_x], request_id="evidence-run-a"
    )
    session.commit()

    with pytest.raises(DuplicateEvidence) as caught:
        repository.append_evidence(
            session,
            run_b.id,
            [evidence_x],
            request_id="evidence-run-b",
        )

    assert caught.value.evidence_id == evidence_x.id


def test_evidence_does_not_mislabel_unrelated_integrity_error(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)

    def fail_audit(*_args, **_kwargs) -> None:
        raise IntegrityError("audit insert", {}, Exception("unrelated audit constraint"))

    monkeypatch.setattr(repository, "_append_audit", fail_audit)
    with pytest.raises(IntegrityError):
        repository.append_evidence(
            session, run.id, [_evidence(504, "1" * 64)], request_id="unrelated"
        )


def test_evidence_audit_contains_only_ids_and_count(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    evidence = _evidence()
    repository.append_evidence(session, run.id, [evidence], request_id="req-evidence")
    session.commit()

    event = repository.list_audit(session, run.incident_id)[-1]
    assert event.event_type == "evidence_collected"
    assert event.payload == {"evidence_ids": [str(evidence.id)], "count": 1}
    assert "sensitive" not in str(event.payload)
    assert "secret-packet" not in str(event.payload)


def test_evidence_structured_payload_is_persisted(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    evidence = _evidence()
    repository.append_evidence(session, run.id, [evidence], request_id="req-evidence")
    session.commit()

    stored = session.execute(
        select(EvidenceRecordRow).where(EvidenceRecordRow.id == str(evidence.id))
    ).scalar_one()
    assert stored.payload_json == dict(evidence.payload)


def test_mismatched_evidence_is_rejected_without_evidence_or_audit_side_effects(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    audit_before = repository.list_audit(session, run.incident_id)
    mismatched = replace(_evidence(), summary="tampered after digest")

    with pytest.raises(EvidenceIntegrityMismatch):
        repository.append_evidence(
            session, run.id, [mismatched], request_id="tampered-evidence"
        )

    assert session.scalar(select(EvidenceRecordRow)) is None
    assert repository.list_audit(session, run.incident_id) == audit_before


def test_assessment_tool_and_verification_are_persisted_and_audited(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    evidence = _evidence()
    repository.append_evidence(session, run.id, [evidence], request_id="req-evidence")
    assessment = Assessment(
        conclusion=Conclusion.CONFIRMED_THREAT,
        risk_level=RiskLevel.HIGH,
        rule_ids=("rule-phishing",),
        evidence_ids=(evidence.id,),
        recommended_action="block source",
        explanation="contains sensitive reasoning",
    )
    repository.save_assessment(
        session, run.id, assessment, request_id="req-assess", now=NOW
    )
    outcome = _tool_outcome(simulation)
    result = repository.apply_tool_outcome(
        session, run.id, outcome, request_id="req-tool", now=NOW
    )
    verification = VerificationResult(
        blocked=True,
        connection_stopped=True,
        observed_at=NOW,
        evidence_ids=(evidence.id,),
    )
    repository.save_verification(
        session, run.id, verification, request_id="req-verify"
    )
    session.commit()

    assert result == outcome.result
    assert repository.get_tool_result(session, "block-1") == outcome.result
    assert repository.get_simulation(session, simulation.simulation_id) == outcome.state
    events = repository.list_audit(session, run.incident_id)
    assert [event.event_type for event in events][-4:] == [
        "evidence_collected",
        "assessment_completed",
        "tool_called",
        "verification_completed",
    ]
    assert "sensitive reasoning" not in str([event.payload for event in events])


def test_tool_outcome_is_idempotent_and_does_not_add_a_second_audit(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    first = _tool_outcome(simulation)
    stored = repository.apply_tool_outcome(
        session, run.id, first, request_id="req-tool", now=NOW
    )
    replacement = BlockOutcome(
        state=simulation,
        result=replace(first.result, status=ToolCallStatus.FAILED, error_code="retry"),
    )
    repeated = repository.apply_tool_outcome(
        session, run.id, replacement, request_id="req-tool-repeat", now=NOW
    )

    assert repeated == stored
    assert [event.event_type for event in repository.list_audit(session, run.incident_id)].count(
        "tool_called"
    ) == 1


def test_idempotency_key_cannot_be_reused_by_another_run(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    state_a = repository.reset_phishing_scenario(session, now=NOW)
    state_b = repository.reset_phishing_scenario(session, now=NOW + timedelta(minutes=1))
    run_a = _create_run(session, repository, state_a.simulation_id, request_id="run-a")
    run_b = _create_run(session, repository, state_b.simulation_id, request_id="run-b")
    first = _tool_outcome(state_a, "shared-key")
    repository.apply_tool_outcome(
        session, run_a.id, first, request_id="tool-a", now=NOW
    )
    session.commit()
    audit_before = repository.list_audit(session, run_b.incident_id)

    with pytest.raises(IdempotencyConflict):
        repository.apply_tool_outcome(
            session,
            run_b.id,
            _tool_outcome(state_b, "shared-key"),
            request_id="tool-b",
            now=NOW,
        )

    assert repository.get_simulation(session, state_b.simulation_id) == state_b
    assert repository.list_audit(session, run_b.incident_id) == audit_before


@pytest.mark.parametrize(
    "change",
    [{"target": "203.0.113.99"}, {"tool_name": "different_tool"}],
)
def test_idempotency_key_rejects_a_different_operation_on_the_same_run(
    change: dict[str, str],
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    first = _tool_outcome(simulation, "same-run-key")
    repository.apply_tool_outcome(
        session, run.id, first, request_id="first-tool", now=NOW
    )
    session.commit()
    changed = replace(first, result=replace(first.result, **change))

    with pytest.raises(IdempotencyConflict):
        repository.apply_tool_outcome(
            session, run.id, changed, request_id="changed-tool", now=NOW
        )


@pytest.mark.parametrize(
    "mismatched_state",
    [
        lambda state: replace(state, simulation_id=UUID(int=900)),
        lambda state: replace(state, incident_id=UUID(int=901)),
    ],
)
def test_tool_outcome_rejects_run_ownership_mismatch_without_side_effects(
    mismatched_state,
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    audit_before = repository.list_audit(session, run.incident_id)
    outcome = _tool_outcome(simulation)
    outcome = replace(outcome, state=mismatched_state(outcome.state))

    with pytest.raises(RunSimulationMismatch) as caught:
        repository.apply_tool_outcome(
            session, run.id, outcome, request_id="mismatch", now=NOW
        )

    assert caught.value.run_id == run.id
    assert caught.value.simulation_id == outcome.state.simulation_id
    assert repository.get_simulation(session, simulation.simulation_id) == simulation
    assert repository.get_tool_result(session, outcome.result.idempotency_key) is None
    assert repository.list_audit(session, run.incident_id) == audit_before


def test_concurrent_tool_key_collision_is_safe_and_loser_session_is_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'tool-concurrent.db'}")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyIncidentRepository(ScenarioFactory())
    with session_factory() as setup_session:
        state = repository.reset_phishing_scenario(setup_session, now=NOW)
        run = _create_run(setup_session, repository, state.simulation_id)
        setup_session.commit()
    outcome = _tool_outcome(state, "concurrent-tool-key")
    query_barrier = Barrier(2)
    original_get = repository._get_tool_call_row

    def synchronized_get(worker_session: Session, key: str):
        result = original_get(worker_session, key)
        query_barrier.wait()
        return result

    monkeypatch.setattr(repository, "_get_tool_call_row", synchronized_get)

    def attempt(request_id: str) -> str:
        with session_factory() as worker_session:
            try:
                repository.apply_tool_outcome(
                    worker_session, run.id, outcome, request_id=request_id, now=NOW
                )
                worker_session.commit()
            except DuplicateIdempotencyKey:
                assert worker_session.execute(text("SELECT 1")).scalar_one() == 1
                return "rejected"
            return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(executor.map(attempt, ("tool-1", "tool-2")))
    engine.dispose()

    assert results == ["created", "rejected"]


def test_tool_does_not_mislabel_unrelated_integrity_error(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    invalid = _tool_outcome(simulation, "invalid-tool")
    invalid = replace(invalid, result=replace(invalid.result, tool_name="not_allowed"))

    with pytest.raises(IntegrityError):
        repository.apply_tool_outcome(
            session, run.id, invalid, request_id="invalid-tool", now=NOW
        )


def test_tool_state_and_result_roll_back_together(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    repository.apply_tool_outcome(
        session, run.id, _tool_outcome(simulation), request_id="req-tool", now=NOW
    )
    session.rollback()

    assert repository.get_tool_result(session, "block-1") is None
    assert repository.get_simulation(session, simulation.simulation_id) == simulation
    assert "tool_called" not in [
        event.event_type for event in repository.list_audit(session, run.incident_id)
    ]


def test_mappers_restore_naive_sqlite_datetimes_as_aware_utc(
    session: Session,
    repository: SqlAlchemyIncidentRepository,
    simulation: PhishingScenarioState,
) -> None:
    run = _create_run(session, repository, simulation.simulation_id)
    session.commit()
    session.expire_all()

    restored_simulation = repository.get_simulation(session, simulation.simulation_id)
    restored_run = repository.get_run(session, run.id)
    restored_incident = repository.get_incident(session, simulation.incident_id)
    restored_audit = repository.list_audit(session, simulation.incident_id)

    values = [
        restored_simulation.created_at,
        restored_simulation.updated_at,
        restored_run.created_at,
        restored_run.updated_at,
        restored_incident.created_at,
        restored_audit[0].occurred_at,
    ]
    assert all(value.tzinfo is UTC for value in values)


def test_recovery_interrupts_all_six_active_statuses_and_appends_ordered_audits(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    targets = [
        InvestigationStatus.PENDING,
        InvestigationStatus.COLLECTING,
        InvestigationStatus.ANALYZING,
        InvestigationStatus.ACTION_PLANNED,
        InvestigationStatus.EXECUTING,
        InvestigationStatus.VERIFYING,
    ]
    runs = []
    states = [
        repository.reset_phishing_scenario(
            session, now=NOW + timedelta(minutes=index)
        )
        for index in range(len(targets))
    ]
    session.commit()
    for index, target in enumerate(targets):
        state = states[index]
        run = _create_run(session, repository, state.simulation_id, request_id=f"create-{index}")
        current = InvestigationStatus.PENDING
        for step in (
            InvestigationStatus.COLLECTING,
            InvestigationStatus.ANALYZING,
            InvestigationStatus.ACTION_PLANNED,
            InvestigationStatus.EXECUTING,
            InvestigationStatus.VERIFYING,
        ):
            if current is target:
                break
            run = repository.transition_run(
                session,
                run.id,
                step,
                request_id=f"transition-{index}-{step.value}",
                now=NOW + timedelta(minutes=index, seconds=1),
            )
            current = step
        runs.append(run)
        session.commit()

    count = repository.mark_recoverable_runs_interrupted(
        session, request_id="req-recovery", now=NOW + timedelta(hours=1)
    )
    session.commit()

    assert count == 6
    expected = dict.fromkeys(targets, InvestigationStatus.INTERRUPTED)
    for original, run in zip(targets, runs, strict=True):
        restored = repository.get_run(session, run.id)
        assert restored.status is expected[original]
        if restored.status is InvestigationStatus.INTERRUPTED:
            assert restored.completed_at == NOW + timedelta(hours=1)
            recovery = repository.list_audit(session, run.incident_id)[-1]
            assert recovery.event_type == "status_changed"
            assert recovery.payload == {
                "from_status": original.value,
                "to_status": "interrupted",
            }
