"""Tenant-bounded SQLAlchemy rows for multi-agent case context."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base

_ROLES = (
    "'superagent','alert_triage','threat_investigation','knowledge_retrieval',"
    "'response_planning','verification','reporting'"
)
_PHASES = (
    "'triage','investigation','retrieval','response_planning','awaiting_execution',"
    "'verification','reporting','needs_review','closed'"
)
_TERMINATIONS = (
    "'completed','needs_review','budget_exhausted','unsafe',"
    "'dependency_unavailable','failed'"
)


class CaseContextRow(Base):
    __tablename__ = "case_contexts"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_case_context_run"),
        UniqueConstraint("id", "tenant_id", name="uq_case_context_id_tenant"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_case_context_run_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_case_context_revision_nonnegative"),
        CheckConstraint(f"phase IN ({_PHASES})", name="ck_case_context_phase"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    user_goal: Mapped[str] = mapped_column(String(4096), nullable=False)
    hypotheses_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    risks_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    plan_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    step_status_json: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    disposition_status: Mapped[str] = mapped_column(String(128), nullable=False)
    budget_json: Mapped[dict[str, int | float]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_case_context_tenant_phase", CaseContextRow.tenant_id, CaseContextRow.phase)


class ConfirmedCaseFactRow(Base):
    __tablename__ = "confirmed_case_facts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["case_context_id", "tenant_id"],
            ["case_contexts.id", "case_contexts.tenant_id"],
            name="fk_confirmed_fact_case_tenant",
        ),
        CheckConstraint("confirmed = 1", name="ck_confirmed_fact_confirmed"),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_confirmed_fact_confidence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    statement: Mapped[str] = mapped_column(String(4096), nullable=False)
    confirmed: Mapped[bool] = mapped_column(nullable=False)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_confirmed_fact_case_created",
    ConfirmedCaseFactRow.case_context_id,
    ConfirmedCaseFactRow.created_at,
)


class AgentPrivateContextRow(Base):
    __tablename__ = "agent_private_contexts"
    __table_args__ = (
        UniqueConstraint("run_id", "role", name="uq_private_context_run_role"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_private_context_run_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_private_context_revision_nonnegative"),
        CheckConstraint(f"role IN ({_ROLES})", name="ck_private_context_role"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    working_items_json: Mapped[dict[str, list[str]]] = mapped_column(JSON, nullable=False)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_private_context_tenant_role",
    AgentPrivateContextRow.tenant_id,
    AgentPrivateContextRow.role,
)


class AgentHandoffRow(Base):
    __tablename__ = "agent_handoffs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_agent_handoff_run_tenant",
        ),
        CheckConstraint(f"sender_role IN ({_ROLES})", name="ck_handoff_sender_role"),
        CheckConstraint(f"receiver_role IN ({_ROLES})", name="ck_handoff_receiver_role"),
        CheckConstraint("sender_role <> receiver_role", name="ck_handoff_distinct_roles"),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_handoff_confidence"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sender_role: Mapped[str] = mapped_column(String(32), nullable=False)
    receiver_role: Mapped[str] = mapped_column(String(32), nullable=False)
    conclusion: Mapped[str] = mapped_column(String(4096), nullable=False)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    open_questions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    recommended_actions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_handoff_run_created", AgentHandoffRow.run_id, AgentHandoffRow.created_at)
Index("ix_handoff_tenant_receiver", AgentHandoffRow.tenant_id, AgentHandoffRow.receiver_role)


class AgentExecutionRow(Base):
    __tablename__ = "agent_executions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_agent_execution_run_tenant",
        ),
        CheckConstraint(f"role IN ({_ROLES})", name="ck_agent_execution_role"),
        CheckConstraint(
            f"termination_reason IN ({_TERMINATIONS})",
            name="ck_agent_execution_termination",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(String(4096), nullable=False)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    hypotheses_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    risks_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    recommended_actions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    termination_reason: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_agent_execution_run_created", AgentExecutionRow.run_id, AgentExecutionRow.created_at)
Index("ix_agent_execution_tenant_role", AgentExecutionRow.tenant_id, AgentExecutionRow.role)
