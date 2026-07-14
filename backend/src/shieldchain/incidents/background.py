import asyncio
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import inspect
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.incidents.ports import IncidentRepository

logger = structlog.get_logger(__name__)


class InvestigationRunnerUnavailable(RuntimeError):
    pass


class InvestigationRunner:
    def __init__(
        self,
        workflow,
        repository: IncidentRepository,
        session_factory: sessionmaker[Session],
        *,
        shutdown_timeout_seconds: float = 5.0,
    ) -> None:
        if not 1.0 <= shutdown_timeout_seconds <= 30.0:
            raise ValueError("shutdown_timeout_seconds must be between 1 and 30")
        self._workflow = workflow
        self._repository = repository
        self._session_factory = session_factory
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._accepting = True
        self._tasks: dict[UUID, asyncio.Task[None]] = {}

    def start(
        self, run_id: UUID, request_id: str, fail_block_once: bool = False
    ) -> None:
        asyncio.get_running_loop()
        if not self._accepting:
            raise InvestigationRunnerUnavailable
        if run_id in self._tasks:
            return
        task = asyncio.create_task(
            self._run(run_id, request_id=request_id, fail_block_once=fail_block_once)
        )
        self._tasks[run_id] = task
        task.add_done_callback(lambda completed, value=run_id: self._finished(value, completed))

    async def _run(
        self, run_id: UUID, *, request_id: str, fail_block_once: bool
    ) -> None:
        try:
            await asyncio.to_thread(
                self._workflow.run,
                self._session_factory,
                run_id,
                request_id=request_id,
                fail_block_once=fail_block_once,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.error(
                "investigation_runner_failed",
                run_id=str(run_id),
                error_type=type(error).__name__,
            )

    def _finished(self, run_id: UUID, task: asyncio.Task[None]) -> None:
        self._tasks.pop(run_id, None)
        if task.cancelled():
            return
        task.exception()

    async def shutdown(self) -> None:
        self._accepting = False
        tasks = tuple(self._tasks.values())
        if not tasks:
            return
        done, pending = await asyncio.wait(
            tasks, timeout=self._shutdown_timeout_seconds
        )
        for task in done:
            if not task.cancelled():
                task.exception()
        # Cancelling this wrapper cannot stop an already-running Python thread.
        # Workflow steps are short; startup recovery protects the next process.
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def recover_interrupted(self) -> int:
        with self._session_factory.begin() as session:
            if not inspect(session.connection()).has_table("investigation_runs"):
                return 0
            return self._repository.mark_recoverable_runs_interrupted(
                session,
                request_id="system-startup-recovery",
                now=datetime.now(UTC),
            )
