from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.main import create_app
from shieldchain.tools.schemas import ToolMutationView, ToolTraceItem, ToolTraceView

NOW = datetime(2026, 7, 23, 14, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
RUN, CALL, EVIDENCE = (UUID(int=value) for value in range(1901, 1904))


class Service:
    def __init__(self):
        self.calls = []

    def trace(self, **values):
        self.calls.append(("trace", values))
        return ToolTraceView(
            run_id=RUN,
            calls=[
                ToolTraceItem(
                    id=CALL,
                    tool_name="block_ip",
                    tool_version="1",
                    status="awaiting_approval",
                    reason="approval_required",
                    target="203.0.113.8",
                    policy_outcome="approval_required",
                    approval_outcome=None,
                    attempt_outcomes=[],
                    verification_outcome=None,
                    evidence_ids=[EVIDENCE],
                    created_at=NOW,
                    updated_at=NOW,
                )
            ],
        )

    def decide(self, **values):
        self.calls.append(("decide", values))
        return ToolMutationView(call_id=CALL, status="awaiting_approval", revision=2)

    def control_call(self, **values):
        self.calls.append(("control", values))
        return ToolMutationView(call_id=CALL, status="cancelled", revision=3)

    def emergency(self, **values):
        self.calls.append(("emergency", values))
        return ToolMutationView(status="emergency_stopped", revision=1)


def client(service: Service) -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return TestClient(
        create_app(
            database_engine=engine,
            settings=Settings(simulation_step_delay_ms=0),
            trusted_tool_api_service=service,
        )
    )


def test_trace_is_server_tenant_bound_and_has_no_private_fields() -> None:
    service = Service()
    with client(service) as value:
        response = value.get(f"/api/v1/tools/runs/{RUN}/calls")
    assert response.status_code == 200
    assert service.calls[0][1]["tenant_id"] == TENANT
    for forbidden in (
        "tenant_id",
        "principal_id",
        "raw_prompt",
        "chain_of_thought",
        "token_digest",
        "result_summary",
    ):
        assert forbidden not in response.text


def test_mutations_ignore_client_authority_and_reject_extra_fields() -> None:
    service = Service()
    with client(service) as value:
        rejected = value.post(
            f"/api/v1/tools/calls/{CALL}/approval",
            json={
                "outcome": "approved",
                "reason": "reviewed",
                "tenant_id": str(UUID(int=9999)),
            },
        )
        approved = value.post(
            f"/api/v1/tools/calls/{CALL}/approval",
            json={"outcome": "approved", "reason": "reviewed"},
        )
        cancelled = value.post(
            f"/api/v1/tools/calls/{CALL}/cancel",
            json={"reason": "no longer required"},
        )
        emergency = value.post(
            "/api/v1/tools/emergency-stop",
            json={"active": True, "reason": "incident containment"},
        )
    assert rejected.status_code == 422
    assert approved.status_code == cancelled.status_code == emergency.status_code == 200
    for _, values in service.calls:
        assert values["tenant_id"] == TENANT
        if "actor_id" in values:
            assert values["actor_id"] == ACTOR
