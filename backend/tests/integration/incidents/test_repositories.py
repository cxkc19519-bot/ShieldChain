from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import text
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
    ToolCallStatus,
    ToolResult,
    VerificationResult,
)
from shieldchain.incidents.ports import (
    ActiveInvestigationExists,
    DuplicateEvidence,
    IncidentRepository,
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
            alert_status="open",
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
    return Evidence(
        id=UUID(int=evidence_id),
        evidence_type="network_connection",
        source="simulation",
        observed_at=NOW,
        summary="sensitive evidence summary",
        raw_reference="memory://secret-packet",
        integrity_sha256=digest,
        confidence=0.95,
        confirmed=True,
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


def test_sqlite_engine_enables_foreign_keys(session: Session) -> None:
    assert session.execute(text("PRAGMA foreign_keys")).scalar_one() == 1


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
                return "rejected"
            return "created"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = sorted(executor.map(attempt, ("concurrent-1", "concurrent-2")))
    engine.dispose()

    assert results == ["created", "rejected"]


def test_missing_simulation_uses_safe_domain_exception(
    session: Session, repository: SqlAlchemyIncidentRepository
) -> None:
    missing = UUID(int=999)
    with pytest.raises(SimulationNotFound) as caught:
        _create_run(session, repository, missing)
    assert caught.value.simulation_id == missing
    assert str(missing) in str(caught.value)


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


def test_recovery_interrupts_exactly_four_statuses_and_appends_ordered_audits(
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

    assert count == 4
    expected = {
        InvestigationStatus.PENDING: InvestigationStatus.PENDING,
        InvestigationStatus.COLLECTING: InvestigationStatus.INTERRUPTED,
        InvestigationStatus.ANALYZING: InvestigationStatus.INTERRUPTED,
        InvestigationStatus.ACTION_PLANNED: InvestigationStatus.ACTION_PLANNED,
        InvestigationStatus.EXECUTING: InvestigationStatus.INTERRUPTED,
        InvestigationStatus.VERIFYING: InvestigationStatus.INTERRUPTED,
    }
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
