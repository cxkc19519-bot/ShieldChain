from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from shieldchain.agents.domain import BudgetSnapshot
from shieldchain.db.base import Base
from shieldchain.incidents.persistence import (
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.react.api_service import ReactApiNotFound, ReactApiService, ReactControlConflict
from shieldchain.react.domain import ReactLoop, ReactLoopStatus
from shieldchain.react.persistence import ReactControlEventRow, ReactObservationRow
from shieldchain.react.repositories import SqlAlchemyReactRepository

NOW = datetime(2026, 7, 23, 22, tzinfo=UTC)
TENANT, OTHER, ACTOR = UUID(int=1), UUID(int=99), UUID(int=2)
CASE, RUN, SIM, LOOP = (UUID(int=value) for value in range(7701, 7705))
OBSERVATION, REFERENCE = UUID(int=7710), UUID(int=7711)


def budget() -> BudgetSnapshot:
    return BudgetSnapshot(10, 1, 3, 1, 60, 2, 1000, 10, 1, 0, 5, 1)


@pytest.fixture
def factory():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions.begin() as session:
        session.add(
            SimulationInstanceRow(
                id=str(SIM),
                scenario_key="react-api",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="REACT-API",
                simulation_instance_id=str(SIM),
                alert_id="A",
                alert_status="open",
                endpoint="host",
                username="analyst",
                source_ip="10.0.0.1",
                remote_ip="203.0.113.8",
                remote_port=443,
                process_name="p",
                parent_process_name="pp",
                command_summary="c",
                threat_label="t",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            InvestigationRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                incident_id=str(CASE),
                simulation_instance_id=str(SIM),
                status="action_planned",
                mode="normal",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        SqlAlchemyReactRepository().create(
            session,
            tenant_id=TENANT,
            loop=ReactLoop(
                LOOP, CASE, RUN, ReactLoopStatus.AWAITING_EXECUTION, 0, budget(), (), NOW, NOW
            ),
        )
        session.flush()
        session.add(
            ReactObservationRow(
                id=str(OBSERVATION),
                loop_id=str(LOOP),
                tenant_id=str(TENANT),
                case_id=str(CASE),
                run_id=str(RUN),
                iteration=1,
                source="evidence",
                status="insufficient",
                reason_code="evidence_insufficient",
                references_json=[
                    {
                        "id": str(REFERENCE),
                        "kind": "evidence",
                        "case_id": str(CASE),
                        "source_id": "siem:alert-1",
                        "observed_at": NOW.isoformat(),
                        "integrity_sha256": "a" * 64,
                        "raw_prompt": "must never be projected",
                    }
                ],
                observed_at=NOW,
            )
        )
    yield sessions
    engine.dispose()


def test_takeover_and_resume_are_cas_audited_but_public_projection_is_redacted(factory) -> None:
    service = ReactApiService(factory)
    takeover = service.control(
        tenant_id=TENANT,
        actor_id=ACTOR,
        loop_id=LOOP,
        action="takeover",
        reason="raw_prompt: private operator context",
        request_id="takeover-1",
        now=NOW + timedelta(seconds=1),
    )
    assert takeover.status == "awaiting_human"
    view = service.trajectory(tenant_id=TENANT, run_id=RUN)
    assert view.status == "awaiting_human"
    assert view.controls[0].reason_code == "operator_takeover"
    assert "private operator context" not in view.model_dump_json()
    assert view.observations[0].citations[0].source_id == "siem:alert-1"
    assert "must never be projected" not in view.model_dump_json()
    assert "case_id" in view.model_dump_json()
    assert str(ACTOR) not in view.model_dump_json()

    resumed = service.control(
        tenant_id=TENANT,
        actor_id=ACTOR,
        loop_id=LOOP,
        action="resume",
        reason="analysis complete",
        request_id="resume-1",
        now=NOW + timedelta(seconds=2),
    )
    assert resumed.status == "awaiting_execution"
    assert resumed.revision == 2
    with factory() as session:
        events = list(
            session.execute(
                select(ReactControlEventRow).order_by(ReactControlEventRow.revision)
            ).scalars()
        )
    assert [event.action for event in events] == ["takeover", "resume"]
    assert all(event.actor_subject_id == str(ACTOR) for event in events)


def test_trajectory_and_controls_are_tenant_bound_and_invalid_transitions_fail(factory) -> None:
    service = ReactApiService(factory)
    with pytest.raises(ReactApiNotFound):
        service.trajectory(tenant_id=OTHER, run_id=RUN)
    with pytest.raises(ReactApiNotFound):
        service.control(
            tenant_id=OTHER,
            actor_id=ACTOR,
            loop_id=LOOP,
            action="takeover",
            reason="cross tenant",
            request_id="cross-tenant",
            now=NOW,
        )
    with pytest.raises(ReactControlConflict):
        service.control(
            tenant_id=TENANT,
            actor_id=ACTOR,
            loop_id=LOOP,
            action="resume",
            reason="not taken over",
            request_id="invalid-resume",
            now=NOW,
        )
