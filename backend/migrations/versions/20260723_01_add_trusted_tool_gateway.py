"""add trusted tool gateway persistence

Revision ID: 20260723_01
Revises: 20260720_01
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_01"
down_revision: str | Sequence[str] | None = "20260720_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CALL_FK = (
    ["tool_call_id", "tenant_id"],
    ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
)


def upgrade() -> None:
    op.create_table(
        "trusted_tool_calls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("caller_role", sa.String(32), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(16), nullable=False),
        sa.Column("arguments_json", sa.JSON(), nullable=False),
        sa.Column("expected_state_json", sa.JSON(), nullable=False),
        sa.Column("rollback_strategy", sa.String(512), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision >= 0", name="ck_trusted_tool_call_revision"),
        sa.CheckConstraint(
            "status IN ('proposed','policy_checked','awaiting_approval','approved',"
            "'executing','verifying','succeeded','failed','needs_review','rejected',"
            "'cancelled','emergency_stopped')",
            name="ck_trusted_tool_call_status",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_trusted_tool_call_run_tenant",
        ),
        sa.UniqueConstraint("id", "tenant_id", name="uq_trusted_tool_call_id_tenant"),
        sa.UniqueConstraint(
            "tenant_id",
            "run_id",
            "tool_name",
            "idempotency_key",
            name="uq_trusted_tool_idempotency",
        ),
    )
    op.create_index(
        "ix_trusted_tool_call_tenant_run", "trusted_tool_calls", ["tenant_id", "run_id"]
    )
    op.create_table(
        "tool_policy_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool_call_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("assessed_risk", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(*_CALL_FK, name="fk_tool_policy_call_tenant"),
        sa.CheckConstraint(
            "assessed_risk IN ('read_only','low','medium','high','critical')",
            name="ck_tool_policy_risk",
        ),
    )
    op.create_table(
        "tool_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool_call_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("approver_subject_id", sa.String(36), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("reason_summary", sa.String(512), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(*_CALL_FK, name="fk_tool_approval_call_tenant"),
    )
    op.create_table(
        "tool_execution_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool_call_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("result_summary", sa.String(1024), nullable=False),
        sa.Column("error_category", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(*_CALL_FK, name="fk_tool_attempt_call_tenant"),
        sa.UniqueConstraint("tool_call_id", "attempt_number", name="uq_tool_attempt_number"),
        sa.CheckConstraint("attempt_number BETWEEN 1 AND 4", name="ck_tool_attempt_number"),
    )
    op.create_table(
        "tool_verifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool_call_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("observed_state_json", sa.JSON(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(*_CALL_FK, name="fk_tool_verification_call_tenant"),
    )
    op.create_index(
        "ix_tool_policy_call_created", "tool_policy_decisions", ["tool_call_id", "created_at"]
    )
    op.create_index(
        "ix_tool_approval_call_decided", "tool_approvals", ["tool_call_id", "decided_at"]
    )
    op.create_index(
        "ix_tool_attempt_call_started", "tool_execution_attempts", ["tool_call_id", "started_at"]
    )
    op.create_index(
        "ix_tool_verification_call_time", "tool_verifications", ["tool_call_id", "verified_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_tool_verification_call_time", table_name="tool_verifications")
    op.drop_table("tool_verifications")
    op.drop_index("ix_tool_attempt_call_started", table_name="tool_execution_attempts")
    op.drop_table("tool_execution_attempts")
    op.drop_index("ix_tool_approval_call_decided", table_name="tool_approvals")
    op.drop_table("tool_approvals")
    op.drop_index("ix_tool_policy_call_created", table_name="tool_policy_decisions")
    op.drop_table("tool_policy_decisions")
    op.drop_index("ix_trusted_tool_call_tenant_run", table_name="trusted_tool_calls")
    op.drop_table("trusted_tool_calls")
