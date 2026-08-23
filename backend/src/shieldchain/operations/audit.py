from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.persistence import AgentRunRow
from shieldchain.operations.mcp_tools import ReadOnlyAgentTool
from shieldchain.operations.persistence import AgentToolCallRow
from shieldchain.operations.schemas import AgentToolCallAuditView, McpToolCallView

AgentToolDirection = Literal["internal", "mcp_inbound", "mcp_outbound"]


class AgentToolRunNotFound(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class AgentToolAuditContext:
    tenant_id: UUID
    principal_id: UUID
    direction: AgentToolDirection
    request_id: str
    run_id: UUID | None = None
    case_id: UUID | None = None


class AgentToolAuditStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def start(
        self,
        context: AgentToolAuditContext,
        tool: ReadOnlyAgentTool,
        *,
        role: str | None,
        arguments: dict[str, str | int],
        now: datetime,
    ) -> UUID:
        call_id = uuid4()
        with self._session_factory.begin() as session:
            session.add(
                AgentToolCallRow(
                    id=str(call_id),
                    tenant_id=str(context.tenant_id),
                    principal_id=str(context.principal_id),
                    run_id=str(context.run_id) if context.run_id else None,
                    case_id=str(context.case_id) if context.case_id else None,
                    role=role,
                    direction=context.direction,
                    provider_kind=tool.provider_kind,
                    provider_id=tool.provider_id,
                    tool_identity=str(tool.identity),
                    tool_alias=tool.name,
                    catalog_revision=tool.catalog_revision,
                    schema_revision=tool.schema_revision,
                    arguments_json=self._public_arguments(arguments),
                    status="running",
                    reason_code=None,
                    result_count=0,
                    summary=None,
                    references_json=[],
                    duration_ms=None,
                    attempt=1,
                    result_bytes=None,
                    truncated=False,
                    request_id=context.request_id[:64],
                    created_at=now,
                    finished_at=None,
                )
            )
        return call_id

    def finish(
        self,
        call_id: UUID,
        result: McpToolCallView,
        *,
        duration_ms: int,
        now: datetime,
    ) -> None:
        result_bytes = len(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
        )
        with self._session_factory.begin() as session:
            row = self._require(session, call_id)
            row.status = result.status
            row.reason_code = result.reason_code
            row.result_count = result.result_count
            row.summary = result.summary[:1000]
            row.duration_ms = max(duration_ms, 0)
            row.result_bytes = result_bytes
            row.finished_at = now

    def cancel(self, call_id: UUID, *, duration_ms: int, now: datetime) -> None:
        with self._session_factory.begin() as session:
            row = self._require(session, call_id)
            row.status = "cancelled"
            row.reason_code = "caller_cancelled"
            row.summary = "工具调用已取消，未取得可信结果。"
            row.duration_ms = max(duration_ms, 0)
            row.result_bytes = 0
            row.finished_at = now

    def recover_interrupted(self, *, now: datetime) -> int:
        with self._session_factory.begin() as session:
            if not inspect(session.connection()).has_table("agent_tool_calls"):
                return 0
            rows = tuple(
                session.scalars(
                    select(AgentToolCallRow)
                    .where(AgentToolCallRow.status == "running")
                    .with_for_update()
                )
            )
            for row in rows:
                row.status = "unknown"
                row.reason_code = "process_interrupted"
                row.summary = "工具调用在服务恢复时没有可信终态，结果未知，需人工复核。"
                row.result_count = 0
                row.duration_ms = None
                row.result_bytes = None
                row.finished_at = now
            return len(rows)

    def list_for_run(self, *, tenant_id: UUID, run_id: UUID) -> list[AgentToolCallAuditView]:
        with self._session_factory() as session:
            run = session.scalar(
                select(AgentRunRow).where(
                    AgentRunRow.id == str(run_id), AgentRunRow.tenant_id == str(tenant_id)
                )
            )
            if run is None:
                raise AgentToolRunNotFound(run_id)
            rows = session.scalars(
                select(AgentToolCallRow)
                .where(
                    AgentToolCallRow.run_id == str(run_id),
                    AgentToolCallRow.tenant_id == str(tenant_id),
                )
                .order_by(AgentToolCallRow.created_at, AgentToolCallRow.id)
            )
            return [self._view(row) for row in rows]

    @staticmethod
    def _public_arguments(arguments: dict[str, str | int]) -> dict[str, str | int]:
        return {
            key: value
            for key, value in arguments.items()
            if key in {"start_at", "end_at", "limit"} and isinstance(value, (str, int))
        }

    @staticmethod
    def _require(session: Session, call_id: UUID) -> AgentToolCallRow:
        row = session.get(AgentToolCallRow, str(call_id))
        if row is None:
            raise RuntimeError("agent tool audit call is missing")
        if row.status != "running":
            raise RuntimeError("agent tool audit call is already terminal")
        return row

    @staticmethod
    def _view(row: AgentToolCallRow) -> AgentToolCallAuditView:
        return AgentToolCallAuditView(
            id=UUID(row.id),
            run_id=UUID(row.run_id) if row.run_id else None,
            case_id=UUID(row.case_id) if row.case_id else None,
            role=row.role,
            direction=row.direction,
            provider_kind=row.provider_kind,
            provider_id=row.provider_id,
            tool_identity=UUID(row.tool_identity),
            tool_alias=row.tool_alias,
            catalog_revision=row.catalog_revision,
            schema_revision=row.schema_revision,
            arguments=dict(row.arguments_json),
            status=row.status,
            reason_code=row.reason_code,
            result_count=row.result_count,
            summary=row.summary,
            duration_ms=row.duration_ms,
            attempt=row.attempt,
            result_bytes=row.result_bytes,
            truncated=row.truncated,
            request_id=row.request_id,
            created_at=row.created_at,
            finished_at=row.finished_at,
        )
