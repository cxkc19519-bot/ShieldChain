from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from shieldchain.agents.domain import BudgetSnapshot, EvidenceReference
from shieldchain.agents.persistence import AgentRunRow
from shieldchain.db.base import Base
from shieldchain.incidents.persistence import (
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.react.domain import (
    FailureAssessment,
    FailureCategory,
    ObservationSource,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
    ReactStepDecision,
)
from shieldchain.react.persistence import ReactAssessmentRow, ReactDecisionRow, ReactObservationRow
from shieldchain.react.repositories import (
    ReactStepBundle,
    SqlAlchemyReactRepository,
    StaleReactLoop,
)
from shieldchain.wazuh.persistence import WazuhCaseRunRow

NOW = datetime(2026, 7, 23, 19, tzinfo=UTC)
TENANT, OTHER = UUID(int=1), UUID(int=99)
CASE, RUN, SIM, LOOP = (UUID(int=x) for x in range(6501, 6505))


def budget():
    return BudgetSnapshot(10, 1, 4, 1, 60, 1, 1000, 10, 1, 0, 5, 1)


def loop():
    return ReactLoop(LOOP, CASE, RUN, ReactLoopStatus.RUNNING, 0, budget(), (), NOW, NOW)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as value:
        value.add(
            SimulationInstanceRow(
                id=str(SIM),
                scenario_key="react",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        value.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="REACT",
                simulation_instance_id=str(SIM),
                alert_id="A",
                alert_status="open",
                endpoint="e",
                username="u",
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
        value.flush()
        value.add(
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
        value.commit()
        yield value
    engine.dispose()


def bundle(current):
    ref = EvidenceReference(uuid4(), CASE, "siem:react", NOW, "d" * 64)
    seen = ReactObservation(
        uuid4(),
        LOOP,
        CASE,
        RUN,
        1,
        ObservationSource.EVIDENCE,
        "insufficient",
        "evidence_insufficient",
        (ref,),
        NOW,
    )
    assessed = FailureAssessment(
        uuid4(),
        seen.id,
        FailureCategory.EVIDENCE_INSUFFICIENT,
        True,
        1,
        "classified_evidence_insufficient",
        NOW,
    )
    changed = replace(
        current,
        revision=1,
        budget=replace(current.budget, steps_used=2, loops_used=2),
        observation_fingerprints=("a" * 64,),
    )
    decision = ReactStepDecision(
        uuid4(),
        LOOP,
        seen.id,
        assessed.id,
        ReactDecision.MANUAL_REVIEW,
        "operator_required",
        changed.budget,
        NOW,
    )
    return ReactStepBundle(current, changed, seen, assessed, decision)


def test_create_get_is_tenant_bound_and_step_is_atomic(session) -> None:
    repo = SqlAlchemyReactRepository()
    current = repo.create(session, tenant_id=TENANT, loop=loop())
    session.commit()
    assert repo.get(session, tenant_id=TENANT, loop_id=LOOP) == current
    assert repo.get(session, tenant_id=OTHER, loop_id=LOOP) is None
    repo.commit_step(session, tenant_id=TENANT, bundle=bundle(current))
    session.commit()
    assert repo.get(session, tenant_id=TENANT, loop_id=LOOP).revision == 1
    for row in (ReactObservationRow, ReactAssessmentRow, ReactDecisionRow):
        assert session.scalar(select(func.count()).select_from(row)) == 1


def test_create_accepts_explicit_wazuh_case_run_binding() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(UUID(int=2)),
                run_kind="incident_investigation",
                status="awaiting_approval",
                goal="Investigate a confirmed Wazuh review case.",
                catalog_revision="test-catalog-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            WazuhCaseRunRow(
                run_id=str(RUN),
                case_id=str(CASE),
                tenant_id=str(TENANT),
                alert_id=str(UUID(int=6506)),
                created_at=NOW,
            )
        )
        session.flush()

        created = SqlAlchemyReactRepository().create(
            session, tenant_id=TENANT, loop=loop()
        )

        assert created.run_id == RUN
        assert created.case_id == CASE
    engine.dispose()


def test_stale_step_rolls_back_all_append_records(session) -> None:
    repo = SqlAlchemyReactRepository()
    current = repo.create(session, tenant_id=TENANT, loop=loop())
    session.commit()
    first = bundle(current)
    repo.commit_step(session, tenant_id=TENANT, bundle=first)
    session.commit()
    with pytest.raises(StaleReactLoop):
        repo.commit_step(session, tenant_id=TENANT, bundle=bundle(current))
    session.rollback()
    assert session.scalar(select(func.count()).select_from(ReactObservationRow)) == 1


def test_stale_scan_is_tenant_bound_and_recovery_claim_is_cas(session) -> None:
    from datetime import timedelta

    repo = SqlAlchemyReactRepository()
    current = repo.create(session, tenant_id=TENANT, loop=loop())
    session.commit()
    assert repo.stale_running(
        session,
        tenant_id=TENANT,
        now=NOW + timedelta(seconds=10),
        stale_after=timedelta(seconds=5),
    ) == (current,)
    assert (
        repo.stale_running(
            session,
            tenant_id=OTHER,
            now=NOW + timedelta(seconds=10),
            stale_after=timedelta(seconds=5),
        )
        == ()
    )
    claimed = repo.claim_recovery(
        session, tenant_id=TENANT, current=current, now=NOW + timedelta(seconds=10)
    )
    session.commit()
    assert claimed.revision == 1
    with pytest.raises(StaleReactLoop):
        repo.claim_recovery(
            session, tenant_id=TENANT, current=current, now=NOW + timedelta(seconds=11)
        )
