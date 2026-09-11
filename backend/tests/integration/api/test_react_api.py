from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from shieldchain.agents.schemas import BudgetView
from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.main import create_app
from shieldchain.react.schemas import ReactMutationView, ReactTrajectoryView

NOW = datetime(2026, 7, 23, 22, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
RUN, CASE, LOOP = (UUID(int=value) for value in range(7601, 7604))


def budget() -> BudgetView:
    return BudgetView(
        step_limit=10,
        steps_used=1,
        loop_limit=3,
        loops_used=1,
        time_limit_seconds=60,
        time_used_seconds=2,
        token_limit=1000,
        tokens_used=10,
        cost_limit_usd=1,
        cost_used_usd=0,
        tool_call_limit=5,
        tool_calls_used=1,
    )


class Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def trajectory(self, **values) -> ReactTrajectoryView:
        self.calls.append(("trajectory", values))
        return ReactTrajectoryView(
            loop_id=LOOP,
            run_id=RUN,
            case_id=CASE,
            status="running",
            revision=1,
            budget=budget(),
            observations=[],
            assessments=[],
            plan_revisions=[],
            decisions=[],
            controls=[],
            updated_at=NOW,
        )

    def control(self, **values) -> ReactMutationView:
        self.calls.append(("control", values))
        return ReactMutationView(loop_id=LOOP, status="awaiting_human", revision=2)


def client(service: Service, settings: Settings | None = None) -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return TestClient(
        create_app(
            database_engine=engine,
            settings=settings or Settings(simulation_step_delay_ms=0),
            react_api_service=service,
        )
    )


def test_trajectory_is_server_tenant_bound_and_public_safe() -> None:
    service = Service()
    with client(service) as value:
        response = value.get(f"/api/v1/react/runs/{RUN}/trajectory")
    assert response.status_code == 200
    assert service.calls == [("trajectory", {"tenant_id": TENANT, "run_id": RUN})]
    for forbidden in (
        "tenant_id",
        "actor_subject_id",
        "reason_summary",
        "request_id",
        "raw_prompt",
        "chain_of_thought",
        "adapter_result",
    ):
        assert forbidden not in response.text


def test_control_uses_server_authority_request_id_and_rejects_extra_fields() -> None:
    service = Service()
    with client(service) as value:
        rejected = value.post(
            f"/api/v1/react/loops/{LOOP}/takeover",
            json={"reason": "operator review", "tenant_id": str(UUID(int=9999))},
        )
        accepted = value.post(
            f"/api/v1/react/loops/{LOOP}/takeover",
            json={"reason": "operator review"},
            headers={"X-Request-ID": "react-control-1"},
        )
    assert rejected.status_code == 422
    assert accepted.status_code == 200
    _, values = service.calls[-1]
    assert values["tenant_id"] == TENANT
    assert values["actor_id"] == ACTOR
    assert values["request_id"] == "react-control-1"
    assert "actor_id" not in accepted.text


def test_control_only_exposes_takeover_and_resume() -> None:
    service = Service()
    with client(service) as value:
        response = value.post(
            f"/api/v1/react/loops/{LOOP}/complete", json={"reason": "not allowed"}
        )
    assert response.status_code == 404
    assert service.calls == []


def test_production_react_control_requires_real_admin_auth_boundary() -> None:
    service = Service()
    with client(
        service,
        Settings(environment="production", simulation_step_delay_ms=0),
    ) as value:
        response = value.post(
            f"/api/v1/react/loops/{LOOP}/takeover",
            json={"reason": "not authenticated"},
        )
    assert response.status_code == 403
    assert service.calls == []
