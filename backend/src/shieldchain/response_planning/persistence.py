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

_PLAN_STATUSES = (
    "'draft','proposed','needs_review','rejected','completed_advisory',"
    "'awaiting_execution','executing','verifying','replanning','cancelled','completed',"
    "'legacy_imported'"
)


class ResponsePlanRow(Base):
    __tablename__ = "response_plans"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_response_plan_id_tenant"),
        UniqueConstraint("run_id", "tenant_id", name="uq_response_plan_run_tenant"),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_response_plan_run_tenant",
        ),
        CheckConstraint(f"status IN ({_PLAN_STATUSES})", name="ck_response_plan_status"),
        CheckConstraint("current_revision >= 0", name="ck_response_plan_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    created_by_role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_response_plan_tenant_status_updated",
    ResponsePlanRow.tenant_id,
    ResponsePlanRow.status,
    ResponsePlanRow.updated_at,
)


class ResponsePlanRevisionRow(Base):
    __tablename__ = "response_plan_revisions"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_response_plan_revision_id_tenant"),
        UniqueConstraint("plan_id", "revision", name="uq_response_plan_revision_number"),
        ForeignKeyConstraint(
            ["plan_id", "tenant_id"],
            ["response_plans.id", "response_plans.tenant_id"],
            name="fk_response_plan_revision_plan_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_response_plan_revision_number"),
        CheckConstraint(
            "parent_revision IS NULL OR parent_revision < revision",
            name="ck_response_plan_parent_revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    public_summary: Mapped[str] = mapped_column(String(2000), nullable=False)
    assumptions_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    stop_conditions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    operator_notes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_response_plan_revision_plan_created",
    ResponsePlanRevisionRow.plan_id,
    ResponsePlanRevisionRow.created_at,
)


class ResponsePlanActionRow(Base):
    __tablename__ = "response_plan_actions"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_response_plan_action_id_tenant"),
        UniqueConstraint("plan_revision_id", "sequence", name="uq_response_plan_action_sequence"),
        UniqueConstraint(
            "plan_revision_id", "client_action_id", name="uq_response_plan_client_action"
        ),
        ForeignKeyConstraint(
            ["plan_revision_id", "tenant_id"],
            ["response_plan_revisions.id", "response_plan_revisions.tenant_id"],
            name="fk_response_plan_action_revision_tenant",
        ),
        CheckConstraint("sequence BETWEEN 1 AND 8", name="ck_response_plan_action_sequence"),
        CheckConstraint(
            "assessed_risk IN ('read_only','low','medium','high','critical')",
            name="ck_response_plan_action_risk",
        ),
        CheckConstraint("status = 'proposed'", name="ck_response_plan_action_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_revision_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    client_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(16), nullable=False)
    target_reference_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    arguments_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    expected_state_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    depends_on_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    evidence_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    public_reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    verification_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rollback_strategy: Mapped[str] = mapped_column(String(512), nullable=False)
    assessed_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_response_plan_action_revision_sequence",
    ResponsePlanActionRow.plan_revision_id,
    ResponsePlanActionRow.sequence,
)


class ResponsePlanEventRow(Base):
    __tablename__ = "response_plan_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["plan_id", "tenant_id"],
            ["response_plans.id", "response_plans.tenant_id"],
            name="fk_response_plan_event_plan_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_response_plan_event_revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    public_summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    actor_subject_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_response_plan_event_plan_created",
    ResponsePlanEventRow.plan_id,
    ResponsePlanEventRow.created_at,
)
