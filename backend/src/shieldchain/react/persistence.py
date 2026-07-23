"""Tenant-bounded SQLAlchemy rows for controlled ReAct loops."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
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

_LOOP_STATUSES = "'running','awaiting_execution','awaiting_human','completed','terminated'"
_SOURCES = "'role','tool_call','tool_verification','control','evidence'"
_CATEGORIES = (
    "'verification_failed','verification_inconclusive','execution_failed',"
    "'execution_outcome_unknown','approval_rejected','emergency_stopped','automation_disabled',"
    "'dependency_unavailable','evidence_insufficient','evidence_conflict','budget_exhausted','loop_detected','unclassified_failure'"
)
_DECISIONS = (
    "'continue_verification','query_status','retry_read_only','replan','manual_review','complete'"
)


class ReactLoopRow(Base):
    __tablename__ = "react_loops"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_react_loop_id_tenant"),
        UniqueConstraint("run_id", name="uq_react_loop_run"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_react_loop_run_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_react_loop_revision"),
        CheckConstraint(f"status IN ({_LOOP_STATUSES})", name="ck_react_loop_status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    budget_json: Mapped[dict[str, int | float]] = mapped_column(JSON, nullable=False)
    observation_fingerprints_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_react_loop_tenant_status", ReactLoopRow.tenant_id, ReactLoopRow.status)


class ReactObservationRow(Base):
    __tablename__ = "react_observations"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_react_observation_id_tenant"),
        ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_observation_loop_tenant",
        ),
        CheckConstraint("iteration >= 0", name="ck_react_observation_iteration"),
        CheckConstraint(f"source IN ({_SOURCES})", name="ck_react_observation_source"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    loop_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    verification_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_react_observation_loop_iteration",
    ReactObservationRow.loop_id,
    ReactObservationRow.iteration,
)


class ReactAssessmentRow(Base):
    __tablename__ = "react_assessments"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_react_assessment_id_tenant"),
        ForeignKeyConstraint(
            ["observation_id", "tenant_id"],
            ["react_observations.id", "react_observations.tenant_id"],
            name="fk_react_assessment_observation_tenant",
        ),
        CheckConstraint(f"category IN ({_CATEGORIES})", name="ck_react_assessment_category"),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_react_assessment_confidence"
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    recoverable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReactPlanRevisionRow(Base):
    __tablename__ = "react_plan_revisions"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_react_plan_revision_id_tenant"),
        UniqueConstraint("loop_id", "revision", name="uq_react_plan_revision_number"),
        ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_plan_loop_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_react_plan_revision"),
        CheckConstraint(f"reason IN ({_CATEGORIES})", name="ck_react_plan_reason"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    loop_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    retained_action_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    removed_action_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    added_actions_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReactDecisionRow(Base):
    __tablename__ = "react_decisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_decision_loop_tenant",
        ),
        ForeignKeyConstraint(
            ["observation_id", "tenant_id"],
            ["react_observations.id", "react_observations.tenant_id"],
            name="fk_react_decision_observation_tenant",
        ),
        ForeignKeyConstraint(
            ["assessment_id", "tenant_id"],
            ["react_assessments.id", "react_assessments.tenant_id"],
            name="fk_react_decision_assessment_tenant",
        ),
        CheckConstraint(f"decision IN ({_DECISIONS})", name="ck_react_decision_value"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    loop_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assessment_id: Mapped[str] = mapped_column(String(36), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    budget_json: Mapped[dict[str, int | float]] = mapped_column(JSON, nullable=False)
    plan_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_react_decision_loop_time", ReactDecisionRow.loop_id, ReactDecisionRow.decided_at)


class ReactControlEventRow(Base):
    __tablename__ = "react_control_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_control_loop_tenant",
        ),
        UniqueConstraint("tenant_id", "request_id", name="uq_react_control_request"),
        CheckConstraint("action IN ('takeover','resume')", name="ck_react_control_action"),
        CheckConstraint("revision > 0", name="ck_react_control_revision"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    loop_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_subject_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_summary: Mapped[str] = mapped_column(String(512), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_react_control_loop_time", ReactControlEventRow.loop_id, ReactControlEventRow.created_at)
