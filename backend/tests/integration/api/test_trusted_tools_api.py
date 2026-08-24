from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.main import create_app
from shieldchain.tools.schemas import (
    ResponsePlanMutationView,
    ResponsePlanRevisionView,
    ResponsePlanToolCallView,
    ResponsePlanView,
    ToolMutationView,
    ToolTraceItem,
    ToolTraceView,
)

NOW = datetime(2026, 7, 23, 14, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
RUN, CALL, EVIDENCE = (UUID(int=value) for value in range(1901, 1904))
PLAN, ACTION = (UUID(int=value) for value in range(1904, 1906))


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
                    plan_id=PLAN,
                    plan_revision_id=None,
                    plan_action_id=None,
                    tool_name="block_ip",
                    tool_version="1",
                    status="awaiting_approval",
                    reason="approval_required",
                    target="203.0.113.8",
                    policy_outcome="approval_required",
                    risk="high",
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

    def decide_plan(self, **values):
        self.calls.append(("decide_plan", values))
        return ResponsePlanMutationView(
            plan_id=PLAN,
            status="awaiting_execution",
            revision=0,
            calls=[
                ResponsePlanToolCallView(
                    action_id=ACTION,
                    call_id=CALL,
                    tool_name="block_ip",
                    tool_version="1",
                    status="awaiting_approval",
                    request_digest="a" * 64,
                )
            ],
        )

    def plan_by_id(self, **values):
        self.calls.append(("plan_by_id", values))
        return self._plan()

    def plan_by_run(self, **values):
        self.calls.append(("plan_by_run", values))
        return self._plan()

    @staticmethod
    def _plan():
        return ResponsePlanView(
            plan_id=PLAN,
            run_id=RUN,
            case_id=None,
            status="proposed",
            current_revision=0,
            revisions=[
                ResponsePlanRevisionView(
                    id=UUID(int=1906),
                    revision=0,
                    parent_revision=None,
                    public_summary="Review the bounded response proposal.",
                    reason_code=None,
                    actions=[],
                    created_at=NOW,
                )
            ],
            events=[],
            created_at=NOW,
            updated_at=NOW,
        )


def client(service: Service, settings: Settings | None = None) -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return TestClient(
        create_app(
            database_engine=engine,
            settings=settings or Settings(simulation_step_delay_ms=0),
            trusted_tool_api_service=service,
        )
    )


def test_trace_is_server_tenant_bound_and_has_no_private_fields() -> None:
    service = Service()
    with client(service) as value:
        response = value.get(f"/api/v1/tools/runs/{RUN}/calls")
    assert response.status_code == 200
    assert service.calls[0][1]["tenant_id"] == TENANT
    assert response.json()["calls"][0]["risk"] == "high"
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
        plan_rejected = value.post(
            f"/api/v1/tools/plans/{PLAN}/decision",
            json={
                "outcome": "accepted",
                "reason": "reviewed fixed plan",
                "tenant_id": str(UUID(int=9999)),
            },
        )
        plan_accepted = value.post(
            f"/api/v1/tools/plans/{PLAN}/decision",
            json={"outcome": "accepted", "reason": "reviewed fixed plan"},
        )
        public_plan_accepted = value.post(
            f"/api/v1/response-plans/{PLAN}/accept",
            json={"current_revision": 0, "reason": "reviewed current revision"},
            headers={"X-Request-ID": "plan-accept-1"},
        )
    assert rejected.status_code == 422
    assert plan_rejected.status_code == 422
    assert (
        approved.status_code
        == cancelled.status_code
        == emergency.status_code
        == plan_accepted.status_code
        == public_plan_accepted.status_code
        == 200
    )
    assert plan_accepted.json()["calls"][0]["status"] == "awaiting_approval"
    for _, values in service.calls:
        assert values["tenant_id"] == TENANT
        if "actor_id" in values:
            assert values["actor_id"] == ACTOR


def test_public_plan_queries_are_tenant_bound_and_exclude_private_material() -> None:
    service = Service()
    with client(service) as value:
        by_run = value.get(f"/api/v1/response-plans/runs/{RUN}")
        by_id = value.get(f"/api/v1/response-plans/{PLAN}")
    assert by_run.status_code == by_id.status_code == 200
    assert service.calls == [
        ("plan_by_run", {"tenant_id": TENANT, "run_id": RUN}),
        ("plan_by_id", {"tenant_id": TENANT, "plan_id": PLAN}),
    ]
    assert by_run.json()["revisions"][0]["public_summary"].startswith("Review")
    for forbidden in (
        "arguments_json",
        "expected_state_json",
        "operator_notes_json",
        "raw_prompt",
        "chain_of_thought",
        "endpoint",
        "token",
    ):
        assert forbidden not in by_run.text.casefold()


def test_public_plan_control_requires_revision_and_rejects_unknown_actions() -> None:
    service = Service()
    with client(service) as value:
        missing = value.post(
            f"/api/v1/response-plans/{PLAN}/accept",
            json={"reason": "missing revision"},
        )
        invalid = value.post(
            f"/api/v1/response-plans/{PLAN}/complete",
            json={"current_revision": 0, "reason": "not allowed"},
        )
    assert missing.status_code == 422
    assert invalid.status_code == 404


def test_production_keeps_rest_operator_controls_closed_without_admin_auth() -> None:
    service = Service()
    with client(
        service,
        Settings(environment="production", simulation_step_delay_ms=0),
    ) as value:
        readable = value.get(f"/api/v1/response-plans/runs/{RUN}")
        plan_write = value.post(
            f"/api/v1/response-plans/{PLAN}/accept",
            json={"current_revision": 0, "reason": "not authenticated"},
        )
        tool_write = value.post(
            f"/api/v1/tools/calls/{CALL}/approval",
            json={"outcome": "approved", "reason": "not authenticated"},
        )
    assert readable.status_code == 200
    assert plan_write.status_code == tool_write.status_code == 403
    assert [name for name, _ in service.calls] == ["plan_by_run"]
