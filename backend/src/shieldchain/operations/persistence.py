from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base


class OperationsRunRow(Base):
    __tablename__ = "operations_runs"
    __table_args__ = (
        UniqueConstraint("run_id", "tenant_id", name="uq_operations_run_id_tenant"),
        UniqueConstraint("report_id", name="uq_operations_run_report"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_operations_run_agent_tenant",
        ),
        CheckConstraint("end_at >= start_at", name="ck_operations_run_time_window"),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_operations_run_tenant_created",
    OperationsRunRow.tenant_id,
    OperationsRunRow.created_at,
    OperationsRunRow.run_id,
)


_TOOL_DIRECTIONS = "'internal','mcp_inbound','mcp_outbound'"
_TOOL_PROVIDER_KINDS = "'builtin','rag','remote_mcp'"
_TOOL_STATUSES = (
    "'running','succeeded','empty','failed','timed_out','cancelled','rejected','unknown'"
)
_TOOL_ROLES = (
    "'superagent','alert_triage','threat_investigation','knowledge_retrieval',"
    "'response_planning','verification','reporting'"
)


class AgentToolCallRow(Base):
    __tablename__ = "agent_tool_calls"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_agent_tool_call_id_tenant"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_agent_tool_call_run_tenant",
        ),
        ForeignKeyConstraint(
            ["case_id", "tenant_id"],
            ["case_contexts.id", "case_contexts.tenant_id"],
            name="fk_agent_tool_call_case_tenant",
        ),
        CheckConstraint(f"direction IN ({_TOOL_DIRECTIONS})", name="ck_agent_tool_call_direction"),
        CheckConstraint(
            f"provider_kind IN ({_TOOL_PROVIDER_KINDS})",
            name="ck_agent_tool_call_provider_kind",
        ),
        CheckConstraint(f"status IN ({_TOOL_STATUSES})", name="ck_agent_tool_call_status"),
        CheckConstraint(f"role IS NULL OR role IN ({_TOOL_ROLES})", name="ck_agent_tool_call_role"),
        CheckConstraint(
            "(status = 'running' AND finished_at IS NULL) OR "
            "(status <> 'running' AND finished_at IS NOT NULL)",
            name="ck_agent_tool_call_terminal_time",
        ),
        CheckConstraint("result_count BETWEEN 0 AND 50", name="ck_agent_tool_call_result_count"),
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="ck_agent_tool_duration"),
        CheckConstraint("attempt BETWEEN 1 AND 4", name="ck_agent_tool_attempt"),
        CheckConstraint(
            "result_bytes IS NULL OR result_bytes >= 0", name="ck_agent_tool_result_bytes"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_identity: Mapped[str] = mapped_column(String(36), nullable=False)
    tool_alias: Mapped[str] = mapped_column(String(128), nullable=False)
    catalog_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    arguments_json: Mapped[dict[str, str | int]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_count: Mapped[int] = mapped_column(Integer, nullable=False)
    summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    result_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "ix_agent_tool_call_tenant_run_created",
    AgentToolCallRow.tenant_id,
    AgentToolCallRow.run_id,
    AgentToolCallRow.created_at,
    AgentToolCallRow.id,
)
Index(
    "ix_agent_tool_call_direction_status_created",
    AgentToolCallRow.direction,
    AgentToolCallRow.status,
    AgentToolCallRow.created_at,
)
