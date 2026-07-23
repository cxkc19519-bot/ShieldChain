from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shieldchain.agents.persistence import (
    AgentExecutionRow,
    AgentHandoffRow,
    AgentPrivateContextRow,
    CaseContextRow,
    ConfirmedCaseFactRow,
)
from shieldchain.agents.trajectory import (
    CollaborationTrajectoryNotFound,
    CollaborationTrajectoryQuery,
)
from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.incidents.persistence import (
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.main import create_app

NOW = datetime(2026, 7, 23, 3, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000099")
CASE = UUID(int=701)
RUN = UUID(int=702)
SIMULATION = UUID(int=703)
REFERENCE = UUID(int=704)
HANDOFF = UUID(int=705)
SHA = "a" * 64


def reference() -> dict[str, object]:
    return {
        "id": str(REFERENCE),
        "kind": "evidence",
        "case_id": str(CASE),
        "source_id": "siem:alert-1",
        "observed_at": NOW.isoformat(),
        "integrity_sha256": SHA,
    }


@pytest.fixture
def database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as session:
        session.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="phishing",
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
                external_id="INC-AGENT",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALT-1",
                alert_status="open",
                endpoint="host",
                username="analyst",
                source_ip="10.0.0.1",
                remote_ip="203.0.113.10",
                remote_port=443,
                process_name="powershell.exe",
                parent_process_name="explorer.exe",
                command_summary="download",
                threat_label="phishing",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            InvestigationRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                incident_id=str(CASE),
                simulation_instance_id=str(SIMULATION),
                status="analyzing",
                mode="normal",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            CaseContextRow(
                id=str(RUN),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                revision=2,
                phase="investigation",
                user_goal="private operator goal",
                hypotheses_json=[],
                risks_json=[],
                plan_json=["investigate"],
                step_status_json={"threat_investigation": "running"},
                disposition_status="Phishing investigation in progress",
                budget_json={
                    "step_limit": 10,
                    "steps_used": 2,
                    "loop_limit": 2,
                    "loops_used": 0,
                    "time_limit_seconds": 60,
                    "time_used_seconds": 5,
                    "token_limit": 1000,
                    "tokens_used": 200,
                    "cost_limit_usd": 1.0,
                    "cost_used_usd": 0.0,
                    "tool_call_limit": 5,
                    "tool_calls_used": 0,
                },
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            ConfirmedCaseFactRow(
                id=str(UUID(int=706)),
                case_context_id=str(RUN),
                tenant_id=str(TENANT),
                statement="Outbound connection was confirmed",
                confirmed=True,
                references_json=[reference()],
                confidence=0.99,
                confirmed_at=NOW,
                created_at=NOW,
            )
        )
        session.add(
            AgentExecutionRow(
                id=str(UUID(int=707)),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                role="alert_triage",
                summary="Alert requires investigation",
                references_json=[reference()],
                hypotheses_json=[],
                risks_json=[],
                recommended_actions_json=[],
                termination_reason="completed",
                created_at=NOW,
            )
        )
        session.add(
            AgentHandoffRow(
                id=str(HANDOFF),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                sender_role="alert_triage",
                receiver_role="threat_investigation",
                conclusion="Investigate confirmed outbound activity",
                references_json=[reference()],
                confidence=0.8,
                open_questions_json=["Was a payload executed?"],
                recommended_actions_json=["Review endpoint telemetry"],
                created_at=NOW,
            )
        )
        session.add(
            AgentPrivateContextRow(
                id=str(UUID(int=708)),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                role="alert_triage",
                revision=0,
                working_items_json={"raw_prompt": ["do not expose this secret"]},
                references_json=[],
                created_at=NOW,
                updated_at=NOW,
            )
        )
    yield engine, factory
    engine.dispose()


def test_query_is_tenant_scoped_and_never_projects_private_context(database) -> None:
    _engine, factory = database
    query = CollaborationTrajectoryQuery(factory)
    view = query.get(tenant_id=TENANT, run_id=RUN)
    payload = view.model_dump_json()
    assert view.shared_summary == "Phishing investigation in progress"
    assert view.handoffs[0].citations[0].source_id == "siem:alert-1"
    assert view.budget.steps_used == 2
    assert "private operator goal" not in payload
    assert "raw_prompt" not in payload
    assert "do not expose this secret" not in payload
    with pytest.raises(CollaborationTrajectoryNotFound):
        query.get(tenant_id=OTHER, run_id=RUN)


def test_read_only_trajectory_api_uses_server_tenant_and_strict_public_schema(database) -> None:
    engine, factory = database
    app = create_app(
        database_engine=engine,
        settings=Settings(simulation_step_delay_ms=0),
        agent_trajectory_query=CollaborationTrajectoryQuery(factory),
    )
    with TestClient(app) as client:
        response = client.get(f"/api/v1/agents/runs/{RUN}/trajectory")
        assert response.status_code == 200
        assert client.post(f"/api/v1/agents/runs/{RUN}/trajectory").status_code == 405
    payload = response.json()
    assert payload["case_id"] == str(CASE)
    assert payload["role_statuses"][0]["role"] == "superagent"
    serialized = response.text
    for forbidden in (
        "tenant_id",
        "principal_id",
        "private_context",
        "raw_prompt",
        "chain_of_thought",
        "private operator goal",
    ):
        assert forbidden not in serialized
