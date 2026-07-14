from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.background import InvestigationRunnerUnavailable
from shieldchain.incidents.domain import InvestigationStatus
from shieldchain.incidents.persistence import AuditEventRow, InvestigationRunRow
from shieldchain.incidents.ports import InvalidInvestigationState
from shieldchain.main import create_app


class RecordingRunner:
    def __init__(self) -> None:
        self.started: list[tuple[UUID, str, bool]] = []
        self.shutdown_calls = 0
        self.recovery_calls = 0

    def start(self, run_id: UUID, request_id: str, fail_block_once: bool = False) -> None:
        self.started.append((run_id, request_id, fail_block_once))

    async def shutdown(self) -> None:
        self.shutdown_calls += 1

    def recover_interrupted(self) -> int:
        self.recovery_calls += 1
        return 0


@pytest.fixture
def incident_context(tmp_path: Path) -> Iterator[tuple[TestClient, object, RecordingRunner]]:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'incidents.db'}")
    Base.metadata.create_all(engine)
    runner = RecordingRunner()
    settings = Settings(_env_file=None, simulation_step_delay_ms=0)
    app = create_app(database_engine=engine, settings=settings, investigation_runner=runner)
    with TestClient(app) as client:
        yield client, create_session_factory(engine), runner
    engine.dispose()


def _reset(client: TestClient, request_id: str = "req-reset") -> dict[str, object]:
    response = client.post(
        "/api/v1/simulations/phishing/reset", headers={"X-Request-ID": request_id}
    )
    assert response.status_code == 201
    assert response.headers["X-Request-ID"] == request_id
    return response.json()


def _assert_error(response, status: int, code: str, message: str, request_id: str) -> None:
    assert response.status_code == status
    assert response.headers["X-Request-ID"] == request_id
    assert response.json() == {
        "error": {"code": code, "message": message, "request_id": request_id}
    }


def test_reset_returns_exact_shape_and_uses_incoming_request_id(incident_context) -> None:
    client, factory, _runner = incident_context
    body = _reset(client)

    assert set(body) == {"simulation", "incident"}
    assert set(body["simulation"]) == {
        "id", "generation", "environment", "connection_status", "firewall_status",
        "fail_block_consumed",
    }
    assert set(body["incident"]) == {
        "id", "external_id", "simulation_instance_id", "alert_id", "alert_status",
        "endpoint", "username", "source_ip", "remote_ip", "remote_port", "process_name",
        "parent_process_name", "command_summary", "threat_label", "created_at",
    }
    with factory() as session:
        event = session.scalar(select(AuditEventRow).order_by(AuditEventRow.sequence))
    assert event.request_id == "req-reset"
    assert event.event_type == "simulation_reset"


def test_reset_rejects_extra_fields(incident_context) -> None:
    client, _factory, _runner = incident_context
    response = client.post(
        "/api/v1/simulations/phishing/reset",
        json={"command": "arbitrary"},
        headers={"X-Request-ID": "req-reset-422"},
    )
    _assert_error(
        response, 422, "validation_error", "Request validation failed", "req-reset-422"
    )


def test_start_is_pending_202_exact_shape_and_schedules_after_commit(incident_context) -> None:
    client, factory, runner = incident_context
    reset = _reset(client)
    simulation_id = reset["simulation"]["id"]

    response = client.post(
        "/api/v1/investigations",
        json={"simulation_instance_id": simulation_id, "mode": "normal"},
        headers={"X-Request-ID": "req-start"},
    )

    assert response.status_code == 202
    assert response.headers["X-Request-ID"] == "req-start"
    body = response.json()
    assert set(body) == {
        "run_id", "incident_id", "simulation_instance_id", "status", "mode", "created_at",
        "updated_at", "completed_at", "simulation", "steps", "evidence", "assessment",
        "tool_result", "verification",
    }
    assert body["status"] == "pending"
    assert body["completed_at"] is None
    assert body["steps"] == [] and body["evidence"] == []
    assert body["assessment"] is None and body["tool_result"] is None
    assert body["verification"] is None
    run_id = UUID(body["run_id"])
    with factory() as session:
        assert session.get(InvestigationRunRow, str(run_id)).status == "pending"
    assert runner.started == [(run_id, "req-start", False)]


def test_lifespan_recovers_and_shuts_down_injected_runner(incident_context) -> None:
    _client, _factory, runner = incident_context
    assert runner.recovery_calls == 1
    assert runner.shutdown_calls == 0


def test_lifespan_calls_shutdown_after_exit(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'lifespan.db'}")
    Base.metadata.create_all(engine)
    runner = RecordingRunner()
    app = create_app(
        database_engine=engine,
        settings=Settings(_env_file=None, simulation_step_delay_ms=0),
        investigation_runner=runner,
    )

    with TestClient(app):
        assert runner.recovery_calls == 1
        assert runner.shutdown_calls == 0

    assert runner.shutdown_calls == 1
    engine.dispose()


@pytest.mark.parametrize(
    ("payload", "path"),
    [
        ({"simulation_instance_id": "bad", "mode": "normal"}, "/api/v1/investigations"),
        ({"simulation_instance_id": str(uuid4()), "mode": "unknown"}, "/api/v1/investigations"),
        (
            {
                "simulation_instance_id": str(uuid4()),
                "mode": "normal",
                "remote_ip": "1.2.3.4",
            },
            "/api/v1/investigations",
        ),
    ],
)
def test_start_rejects_invalid_or_extra_inputs(incident_context, payload, path) -> None:
    client, _factory, _runner = incident_context
    response = client.post(path, json=payload, headers={"X-Request-ID": "req-422"})
    _assert_error(response, 422, "validation_error", "Request validation failed", "req-422")


def test_production_rejects_failure_mode_before_writing(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'production.db'}")
    Base.metadata.create_all(engine)
    runner = RecordingRunner()
    settings = Settings(
        _env_file=None, environment="PrOdUcTiOn", simulation_step_delay_ms=0
    )
    with TestClient(
        create_app(database_engine=engine, settings=settings, investigation_runner=runner)
    ) as client:
        reset = _reset(client)
        response = client.post(
            "/api/v1/investigations",
            json={
                "simulation_instance_id": reset["simulation"]["id"],
                "mode": "fail_block_once",
            },
            headers={"X-Request-ID": "req-prod"},
        )
    _assert_error(
        response, 403, "simulation_mode_forbidden",
        "Simulation failure mode is disabled in production", "req-prod"
    )
    with create_session_factory(engine)() as session:
        assert session.scalar(select(InvestigationRunRow)) is None
    engine.dispose()


def test_not_found_active_conflict_reset_conflict_and_closed_repeat(incident_context) -> None:
    client, factory, runner = incident_context
    missing = str(uuid4())
    response = client.post(
        "/api/v1/investigations",
        json={"simulation_instance_id": missing},
        headers={"X-Request-ID": "req-missing-sim"},
    )
    _assert_error(response, 404, "simulation_not_found", "Simulation not found", "req-missing-sim")

    reset = _reset(client)
    payload = {"simulation_instance_id": reset["simulation"]["id"]}
    first = client.post("/api/v1/investigations", json=payload).json()
    conflict = client.post(
        "/api/v1/investigations", json=payload, headers={"X-Request-ID": "req-conflict"}
    )
    _assert_error(
        conflict, 409, "investigation_already_running",
        "An investigation is already running", "req-conflict"
    )
    reset_conflict = client.post(
        "/api/v1/simulations/phishing/reset", headers={"X-Request-ID": "req-reset-conflict"}
    )
    _assert_error(
        reset_conflict, 409, "investigation_already_running",
        "An investigation is already running", "req-reset-conflict"
    )
    with factory.begin() as session:
        session.execute(
            update(InvestigationRunRow)
            .where(InvestigationRunRow.id == first["run_id"])
            .values(status="closed", completed_at=datetime.now(UTC))
        )
    repeated = client.post("/api/v1/investigations", json=payload)
    assert repeated.status_code == 202
    assert repeated.json()["run_id"] == first["run_id"]
    assert repeated.json()["status"] == "closed"
    assert len(runner.started) == 1


def test_runner_unavailable_and_invalid_state_are_safe_errors(incident_context) -> None:
    client, _factory, runner = incident_context
    reset = _reset(client)
    payload = {"simulation_instance_id": reset["simulation"]["id"]}

    def unavailable(*_args, **_kwargs):
        raise InvestigationRunnerUnavailable

    available_start = runner.start
    runner.start = unavailable
    unavailable_response = client.post(
        "/api/v1/investigations",
        json=payload,
        headers={"X-Request-ID": "req-unavailable"},
    )
    _assert_error(
        unavailable_response,
        503,
        "investigation_runner_unavailable",
        "Investigation runner is unavailable",
        "req-unavailable",
    )
    with _factory() as session:
        assert session.scalar(select(func.count()).select_from(InvestigationRunRow)) == 0
        assert (
            session.scalar(select(func.count()).select_from(AuditEventRow)) == 1
        )
    runner.start = available_start
    retry = client.post(
        "/api/v1/investigations", json=payload, headers={"X-Request-ID": "req-retry"}
    )
    assert retry.status_code == 202
    assert len(runner.started) == 1

    class InvalidRepository:
        def create_run(self, *_args, **_kwargs):
            raise InvalidInvestigationState(uuid4(), InvestigationStatus.FAILED)

    client.app.state.incident_repository = InvalidRepository()
    with _factory.begin() as session:
        session.execute(
            update(InvestigationRunRow).values(
                status="failed", completed_at=datetime.now(UTC)
            )
        )
    invalid_response = client.post(
        "/api/v1/investigations",
        json=payload,
        headers={"X-Request-ID": "req-invalid-state"},
    )
    _assert_error(
        invalid_response,
        409,
        "invalid_investigation_state",
        "Investigation state does not allow this operation",
        "req-invalid-state",
    )


def test_concurrent_start_requests_have_one_database_winner(incident_context) -> None:
    client, factory, runner = incident_context
    reset = _reset(client)
    payload = {"simulation_instance_id": reset["simulation"]["id"]}
    delegate = client.app.state.incident_query_service
    barrier = Barrier(2)

    class BarrierQueryService:
        def latest_run_for_simulation(self, simulation_id):
            result = delegate.latest_run_for_simulation(simulation_id)
            barrier.wait(timeout=5)
            return result

        def __getattr__(self, name):
            return getattr(delegate, name)

    client.app.state.incident_query_service = BarrierQueryService()

    def start(request_id: str):
        return client.post(
            "/api/v1/investigations",
            json=payload,
            headers={"X-Request-ID": request_id},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = tuple(executor.map(start, ("req-race-1", "req-race-2")))

    assert sorted(response.status_code for response in responses) == [202, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["error"]["code"] == "investigation_already_running"
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(InvestigationRunRow)) == 1
    assert len(runner.started) == 1


@pytest.mark.parametrize(
    ("mode", "terminal"), [("normal", "closed"), ("fail_block_once", "failed")]
)
def test_real_runner_polling_reaches_expected_terminal_status(
    tmp_path: Path, mode: str, terminal: str
) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / f'{mode}.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, simulation_step_delay_ms=0)
    with TestClient(create_app(database_engine=engine, settings=settings)) as client:
        reset = _reset(client)
        started = client.post(
            "/api/v1/investigations",
            json={"simulation_instance_id": reset["simulation"]["id"], "mode": mode},
            headers={"X-Request-ID": f"req-{mode}"},
        )
        assert started.status_code == 202
        assert started.json()["status"] == "pending"
        run_id = started.json()["run_id"]
        for _ in range(100):
            polled = client.get(f"/api/v1/investigations/{run_id}")
            assert polled.status_code == 200
            if polled.json()["status"] == terminal:
                break
        assert polled.json()["status"] == terminal
        if terminal == "closed":
            assert polled.json()["verification"]["blocked"] is True
        else:
            assert polled.json()["tool_result"]["error_code"] == "simulated_block_failure"
    engine.dispose()


def test_get_investigation_incident_and_audit_contracts_ordered(incident_context) -> None:
    client, factory, _runner = incident_context
    reset = _reset(client)
    started = client.post(
        "/api/v1/investigations",
        json={"simulation_instance_id": reset["simulation"]["id"]},
        headers={"X-Request-ID": "req-start"},
    ).json()

    investigation = client.get(f"/api/v1/investigations/{started['run_id']}")
    assert investigation.status_code == 200
    assert investigation.json() == started

    incident = client.get(f"/api/v1/incidents/{started['incident_id']}")
    assert incident.status_code == 200
    assert set(incident.json()) == {"incident", "runs"}
    assert set(incident.json()["runs"][0]) == {
        "run_id", "status", "mode", "created_at", "updated_at", "completed_at"
    }

    audit = client.get(f"/api/v1/incidents/{started['incident_id']}/audit")
    assert audit.status_code == 200
    assert set(audit.json()) == {"incident_id", "events"}
    sequences = [event["sequence"] for event in audit.json()["events"]]
    assert sequences == sorted(sequences)
    assert all(event["occurred_at"].endswith("Z") for event in audit.json()["events"])
    with factory() as session:
        assert session.scalar(select(AuditEventRow).where(AuditEventRow.request_id == "req-start"))


@pytest.mark.parametrize(
    ("path", "code", "message"),
    [
        (f"/api/v1/investigations/{uuid4()}", "investigation_not_found", "Investigation not found"),
        (f"/api/v1/incidents/{uuid4()}", "incident_not_found", "Incident not found"),
        (f"/api/v1/incidents/{uuid4()}/audit", "incident_not_found", "Incident not found"),
    ],
)
def test_get_not_found_errors(incident_context, path, code, message) -> None:
    client, _factory, _runner = incident_context
    response = client.get(path, headers={"X-Request-ID": "req-404"})
    _assert_error(response, 404, code, message, "req-404")
