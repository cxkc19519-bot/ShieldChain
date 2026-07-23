"""add controlled react loops

Revision ID: 20260723_04
Revises: 20260723_03
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_04"
down_revision: str | Sequence[str] | None = "20260723_03"
branch_labels = None
depends_on = None

LOOP = "'running','awaiting_execution','awaiting_human','completed','terminated'"
SOURCE = "'role','tool_call','tool_verification','control','evidence'"
CATEGORY = (
    "'verification_failed','verification_inconclusive','execution_failed',"
    "'execution_outcome_unknown','approval_rejected','emergency_stopped','automation_disabled',"
    "'dependency_unavailable','evidence_insufficient','evidence_conflict','budget_exhausted','loop_detected','unclassified_failure'"
)
DECISION = (
    "'continue_verification','query_status','retry_read_only','replan','manual_review','complete'"
)


def upgrade() -> None:
    op.create_table(
        "react_loops",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("budget_json", sa.JSON(), nullable=False),
        sa.Column("observation_fingerprints_json", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_react_loop_id_tenant"),
        sa.UniqueConstraint("run_id", name="uq_react_loop_run"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_react_loop_run_tenant",
        ),
        sa.CheckConstraint("revision >= 0", name="ck_react_loop_revision"),
        sa.CheckConstraint(f"status IN ({LOOP})", name="ck_react_loop_status"),
    )
    op.create_index("ix_react_loop_tenant_status", "react_loops", ["tenant_id", "status"])
    op.create_table(
        "react_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("loop_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("tool_call_id", sa.String(36)),
        sa.Column("verification_id", sa.String(36)),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_react_observation_id_tenant"),
        sa.ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_observation_loop_tenant",
        ),
        sa.CheckConstraint("iteration >= 0", name="ck_react_observation_iteration"),
        sa.CheckConstraint(f"source IN ({SOURCE})", name="ck_react_observation_source"),
    )
    op.create_index(
        "ix_react_observation_loop_iteration", "react_observations", ["loop_id", "iteration"]
    )
    op.create_table(
        "react_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("recoverable", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_react_assessment_id_tenant"),
        sa.ForeignKeyConstraint(
            ["observation_id", "tenant_id"],
            ["react_observations.id", "react_observations.tenant_id"],
            name="fk_react_assessment_observation_tenant",
        ),
        sa.CheckConstraint(f"category IN ({CATEGORY})", name="ck_react_assessment_category"),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_react_assessment_confidence"
        ),
    )
    op.create_table(
        "react_plan_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("loop_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("parent_revision", sa.Integer()),
        sa.Column("retained_action_ids_json", sa.JSON(), nullable=False),
        sa.Column("removed_action_ids_json", sa.JSON(), nullable=False),
        sa.Column("added_actions_json", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_react_plan_revision_id_tenant"),
        sa.UniqueConstraint("loop_id", "revision", name="uq_react_plan_revision_number"),
        sa.ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_plan_loop_tenant",
        ),
        sa.CheckConstraint("revision >= 0", name="ck_react_plan_revision"),
        sa.CheckConstraint(f"reason IN ({CATEGORY})", name="ck_react_plan_reason"),
    )
    op.create_table(
        "react_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("loop_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("budget_json", sa.JSON(), nullable=False),
        sa.Column("plan_revision_id", sa.String(36)),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_decision_loop_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id", "tenant_id"],
            ["react_observations.id", "react_observations.tenant_id"],
            name="fk_react_decision_observation_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "tenant_id"],
            ["react_assessments.id", "react_assessments.tenant_id"],
            name="fk_react_decision_assessment_tenant",
        ),
        sa.CheckConstraint(f"decision IN ({DECISION})", name="ck_react_decision_value"),
    )
    op.create_index("ix_react_decision_loop_time", "react_decisions", ["loop_id", "decided_at"])


def downgrade() -> None:
    op.drop_index("ix_react_decision_loop_time", table_name="react_decisions")
    op.drop_table("react_decisions")
    op.drop_table("react_plan_revisions")
    op.drop_table("react_assessments")
    op.drop_index("ix_react_observation_loop_iteration", table_name="react_observations")
    op.drop_table("react_observations")
    op.drop_index("ix_react_loop_tenant_status", table_name="react_loops")
    op.drop_table("react_loops")
