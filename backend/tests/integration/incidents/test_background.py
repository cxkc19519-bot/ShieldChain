import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import inspect, update

from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.background import (
    InvestigationRunner,
    InvestigationRunnerUnavailable,
)
from shieldchain.incidents.domain import InvestigationStatus, RunMode
from shieldchain.incidents.persistence import InvestigationRunRow
from shieldchain.incidents.repositories import SqlAlchemyIncidentRepository
from shieldchain.incidents.scenario import seed_phishing_scenario


class RecordingWorkflow:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls: list[tuple[object, object, str, bool]] = []
        self.error = error

    def run(self, session_factory, run_id, *, request_id, fail_block_once=False):
        self.calls.append((session_factory, run_id, request_id, fail_block_once))
        if self.error is not None:
            raise self.error


def _runner(workflow: RecordingWorkflow) -> InvestigationRunner:
    engine = create_engine_from_url("sqlite:///:memory:")
    factory = create_session_factory(engine)
    return InvestigationRunner(
        workflow,
        SqlAlchemyIncidentRepository(seed_phishing_scenario),
        factory,
        shutdown_timeout_seconds=1,
    )


def test_start_requires_running_event_loop() -> None:
    runner = _runner(RecordingWorkflow())

    with pytest.raises(RuntimeError):
        runner.start(uuid4(), "req-1")


def test_start_uses_to_thread_and_coalesces_duplicate(monkeypatch) -> None:
    workflow = RecordingWorkflow()
    runner = _runner(workflow)
    entered = asyncio.Event()
    release = asyncio.Event()
    calls: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

    async def controlled_to_thread(function, *args, **kwargs):
        calls.append((function, args, kwargs))
        entered.set()
        await release.wait()

    monkeypatch.setattr(asyncio, "to_thread", controlled_to_thread)

    async def exercise() -> None:
        run_id = uuid4()
        runner.start(run_id, "req-1", fail_block_once=True)
        runner.start(run_id, "req-2")
        await entered.wait()
        assert len(calls) == 1
        function, args, kwargs = calls[0]
        assert function == workflow.run
        assert args[1] == run_id
        assert kwargs == {"request_id": "req-1", "fail_block_once": True}
        release.set()
        await runner.shutdown()

    asyncio.run(exercise())


def test_wrapper_safely_consumes_unexpected_exception(monkeypatch, caplog) -> None:
    workflow = RecordingWorkflow(error=RuntimeError("do-not-log-secret"))
    runner = _runner(workflow)

    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)

    async def exercise() -> None:
        runner.start(uuid4(), "req-1")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await runner.shutdown()

    asyncio.run(exercise())
    assert "do-not-log-secret" not in caplog.text


def test_shutdown_is_idempotent_cancels_pending_and_rejects_new_work(monkeypatch) -> None:
    workflow = RecordingWorkflow()
    runner = _runner(workflow)
    cancelled = asyncio.Event()

    async def never_finishes(_function, *_args, **_kwargs):
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def immediate_wait(tasks, *, timeout):
        assert timeout == 1
        return set(), set(tasks)

    monkeypatch.setattr(asyncio, "to_thread", never_finishes)
    monkeypatch.setattr(asyncio, "wait", immediate_wait)

    async def exercise() -> None:
        runner.start(uuid4(), "req-1")
        await asyncio.sleep(0)
        await runner.shutdown()
        await runner.shutdown()
        assert cancelled.is_set()
        with pytest.raises(InvestigationRunnerUnavailable):
            runner.start(uuid4(), "req-2")

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("original_status", "expected_status", "expected_count"),
    [
        (
            status,
            (
                InvestigationStatus.INTERRUPTED
                if status
                in {
                    InvestigationStatus.PENDING,
                    InvestigationStatus.COLLECTING,
                    InvestigationStatus.ANALYZING,
                    InvestigationStatus.ACTION_PLANNED,
                    InvestigationStatus.EXECUTING,
                    InvestigationStatus.VERIFYING,
                }
                else status
            ),
            int(
                status
                in {
                    InvestigationStatus.PENDING,
                    InvestigationStatus.COLLECTING,
                    InvestigationStatus.ANALYZING,
                    InvestigationStatus.ACTION_PLANNED,
                    InvestigationStatus.EXECUTING,
                    InvestigationStatus.VERIFYING,
                }
            ),
        )
        for status in InvestigationStatus
    ],
)
def test_recover_interrupted_marks_every_database_active_status(
    original_status, expected_status, expected_count
) -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    repository = SqlAlchemyIncidentRepository(seed_phishing_scenario)
    with factory.begin() as session:
        state = repository.reset_phishing_scenario(
            session, request_id="seed", now=datetime.now(UTC)
        )
    with factory.begin() as session:
        run = repository.create_run(
            session,
            simulation_id=state.simulation_id,
            mode=RunMode.NORMAL,
            request_id=f"seed-{original_status.value}",
            now=datetime.now(UTC),
        )
        session.execute(
            update(InvestigationRunRow)
            .where(InvestigationRunRow.id == str(run.id))
            .values(status=original_status.value)
        )

    runner = InvestigationRunner(RecordingWorkflow(), repository, factory)
    assert runner.recover_interrupted() == expected_count

    with factory() as session:
        loaded = session.get(InvestigationRunRow, str(run.id)).status
    assert loaded == expected_status.value


def test_recover_skips_missing_migration_without_creating_tables() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    runner = InvestigationRunner(
        RecordingWorkflow(),
        SqlAlchemyIncidentRepository(seed_phishing_scenario),
        create_session_factory(engine),
    )

    assert runner.recover_interrupted() == 0
    assert "investigation_runs" not in inspect(engine).get_table_names()
