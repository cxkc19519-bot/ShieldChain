"""Tenant-bounded SQLAlchemy rows for trusted tool calling."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
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

_STATUSES = (
    "'proposed','policy_checked','awaiting_approval','approved','executing','verifying',"
    "'succeeded','failed','needs_review','rejected','cancelled','emergency_stopped'"
)
_RISKS = "'read_only','low','medium','high','critical'"


class TrustedToolCallRow(Base):
    __tablename__ = "trusted_tool_calls"
    __table_args__ = (
        UniqueConstraint("id", "tenant_id", name="uq_trusted_tool_call_id_tenant"),
        UniqueConstraint(
            "tenant_id",
            "run_id",
            "tool_name",
            "idempotency_key",
            name="uq_trusted_tool_idempotency",
        ),
        ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_trusted_tool_call_run_tenant",
        ),
        CheckConstraint("revision >= 0", name="ck_trusted_tool_call_revision"),
        CheckConstraint(f"status IN ({_STATUSES})", name="ck_trusted_tool_call_status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    caller_role: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(16), nullable=False)
    arguments_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    expected_state_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    rollback_strategy: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_trusted_tool_call_tenant_run", TrustedToolCallRow.tenant_id, TrustedToolCallRow.run_id)


class ToolPolicyDecisionRow(Base):
    __tablename__ = "tool_policy_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_call_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assessed_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_policy_call_tenant",
        ),
        CheckConstraint(f"assessed_risk IN ({_RISKS})", name="ck_tool_policy_risk"),
    )


class ToolApprovalRow(Base):
    __tablename__ = "tool_approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_call_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    approver_subject_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_summary: Mapped[str] = mapped_column(String(512), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_approval_call_tenant",
        ),
    )


class ToolExecutionAttemptRow(Base):
    __tablename__ = "tool_execution_attempts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_attempt_call_tenant",
        ),
        UniqueConstraint("tool_call_id", "attempt_number", name="uq_tool_attempt_number"),
        CheckConstraint("attempt_number BETWEEN 1 AND 4", name="ck_tool_attempt_number"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_call_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    result_summary: Mapped[str] = mapped_column(String(1024), nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ToolExecutionLeaseRow(Base):
    __tablename__ = "tool_execution_leases"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_execution_lease_call_tenant",
        ),
        UniqueConstraint("tool_call_id", "attempt_number", name="uq_tool_execution_lease_attempt"),
        CheckConstraint("attempt_number BETWEEN 1 AND 4", name="ck_tool_execution_lease_attempt"),
        CheckConstraint(
            "(released_at IS NULL AND release_reason IS NULL) OR "
            "(released_at IS NOT NULL AND release_reason IS NOT NULL)",
            name="ck_tool_execution_lease_release",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_call_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    holder_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    release_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)


Index(
    "ix_tool_execution_lease_tenant_expiry",
    ToolExecutionLeaseRow.tenant_id,
    ToolExecutionLeaseRow.expires_at,
)


class ToolVerificationRow(Base):
    __tablename__ = "tool_verifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool_call_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    observed_state_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    evidence_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_verification_call_tenant",
        ),
    )


Index(
    "ix_tool_policy_call_created",
    ToolPolicyDecisionRow.tool_call_id,
    ToolPolicyDecisionRow.created_at,
)
Index("ix_tool_approval_call_decided", ToolApprovalRow.tool_call_id, ToolApprovalRow.decided_at)
Index(
    "ix_tool_attempt_call_started",
    ToolExecutionAttemptRow.tool_call_id,
    ToolExecutionAttemptRow.started_at,
)
Index(
    "ix_tool_verification_call_time",
    ToolVerificationRow.tool_call_id,
    ToolVerificationRow.verified_at,
)
