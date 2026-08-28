"""add compiled and versioned response plans

Revision ID: 20260823_05
Revises: 20260823_04
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_05"
down_revision: str | Sequence[str] | None = "20260823_04"
branch_labels = None
depends_on = None

_PLAN_STATUSES = (
    "'draft','proposed','needs_review','rejected','completed_advisory',"
    "'awaiting_execution','executing','verifying','replanning','cancelled','completed',"
    "'legacy_imported'"
)


def upgrade() -> None:
    inconsistent = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM ("
                "SELECT tenant_id,run_id FROM trusted_tool_calls "
                "GROUP BY tenant_id,run_id HAVING count(DISTINCT case_id) > 1"
                ") AS inconsistent_runs"
            )
        )
        .scalar_one()
    )
    if inconsistent:
        raise RuntimeError("cannot backfill response plans from cross-case historical runs")

    op.create_table(
        "response_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column("created_by_role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_response_plan_id_tenant"),
        sa.UniqueConstraint("run_id", "tenant_id", name="uq_response_plan_run_tenant"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_response_plan_run_tenant",
        ),
        sa.CheckConstraint(f"status IN ({_PLAN_STATUSES})", name="ck_response_plan_status"),
        sa.CheckConstraint("current_revision >= 0", name="ck_response_plan_revision"),
    )
    op.create_index(
        "ix_response_plan_tenant_status_updated",
        "response_plans",
        ["tenant_id", "status", "updated_at"],
    )
    op.create_table(
        "response_plan_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("parent_revision", sa.Integer(), nullable=True),
        sa.Column("public_summary", sa.String(2000), nullable=False),
        sa.Column("assumptions_json", sa.JSON(), nullable=False),
        sa.Column("stop_conditions_json", sa.JSON(), nullable=False),
        sa.Column("operator_notes_json", sa.JSON(), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=True),
        sa.Column("model_id", sa.String(128), nullable=True),
        sa.Column("prompt_policy_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_response_plan_revision_id_tenant"),
        sa.UniqueConstraint("plan_id", "revision", name="uq_response_plan_revision_number"),
        sa.ForeignKeyConstraint(
            ["plan_id", "tenant_id"],
            ["response_plans.id", "response_plans.tenant_id"],
            name="fk_response_plan_revision_plan_tenant",
        ),
        sa.CheckConstraint("revision >= 0", name="ck_response_plan_revision_number"),
        sa.CheckConstraint(
            "parent_revision IS NULL OR parent_revision < revision",
            name="ck_response_plan_parent_revision",
        ),
    )
    op.create_index(
        "ix_response_plan_revision_plan_created",
        "response_plan_revisions",
        ["plan_id", "created_at"],
    )
    op.create_table(
        "response_plan_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_revision_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("client_action_id", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(16), nullable=False),
        sa.Column("target_reference_id", sa.String(36), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_identifier", sa.String(256), nullable=False),
        sa.Column("arguments_json", sa.JSON(), nullable=False),
        sa.Column("expected_state_json", sa.JSON(), nullable=False),
        sa.Column("depends_on_json", sa.JSON(), nullable=False),
        sa.Column("evidence_ids_json", sa.JSON(), nullable=False),
        sa.Column("public_reason", sa.String(1000), nullable=False),
        sa.Column("verification_tool", sa.String(64), nullable=True),
        sa.Column("verification_version", sa.String(16), nullable=True),
        sa.Column("rollback_strategy", sa.String(512), nullable=False),
        sa.Column("assessed_risk", sa.String(16), nullable=False),
        sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "tenant_id", name="uq_response_plan_action_id_tenant"),
        sa.UniqueConstraint(
            "plan_revision_id", "sequence", name="uq_response_plan_action_sequence"
        ),
        sa.UniqueConstraint(
            "plan_revision_id", "client_action_id", name="uq_response_plan_client_action"
        ),
        sa.ForeignKeyConstraint(
            ["plan_revision_id", "tenant_id"],
            ["response_plan_revisions.id", "response_plan_revisions.tenant_id"],
            name="fk_response_plan_action_revision_tenant",
        ),
        sa.CheckConstraint("sequence BETWEEN 1 AND 8", name="ck_response_plan_action_sequence"),
        sa.CheckConstraint(
            "assessed_risk IN ('read_only','low','medium','high','critical')",
            name="ck_response_plan_action_risk",
        ),
        sa.CheckConstraint("status = 'proposed'", name="ck_response_plan_action_status"),
    )
    op.create_index(
        "ix_response_plan_action_revision_sequence",
        "response_plan_actions",
        ["plan_revision_id", "sequence"],
    )
    op.create_table(
        "response_plan_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=True),
        sa.Column("public_summary", sa.String(1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["plan_id", "tenant_id"],
            ["response_plans.id", "response_plans.tenant_id"],
            name="fk_response_plan_event_plan_tenant",
        ),
        sa.CheckConstraint("revision >= 0", name="ck_response_plan_event_revision"),
    )
    op.create_index(
        "ix_response_plan_event_plan_created",
        "response_plan_events",
        ["plan_id", "created_at"],
    )

    with op.batch_alter_table("trusted_tool_calls") as batch_op:
        batch_op.add_column(sa.Column("plan_revision_id", sa.String(36), nullable=True))
        batch_op.add_column(sa.Column("plan_action_id", sa.String(36), nullable=True))

    op.execute(
        sa.text(
            "INSERT INTO response_plans "
            "(id,tenant_id,run_id,case_id,status,current_revision,created_by_role,"
            "created_at,updated_at) "
            "SELECT min(id),tenant_id,run_id,min(case_id),'legacy_imported',0,'legacy',"
            "min(created_at),max(updated_at) FROM trusted_tool_calls GROUP BY tenant_id,run_id"
        )
    )
    op.execute(
        sa.text(
            "INSERT INTO response_plan_revisions "
            "(id,plan_id,tenant_id,revision,parent_revision,public_summary,assumptions_json,"
            "stop_conditions_json,operator_notes_json,reason_code,model_id,"
            "prompt_policy_version,created_at) "
            "SELECT id,id,tenant_id,0,NULL,'Historical trusted tool call association.',"
            "'[]','[]','[]','legacy_tool_plan',NULL,'legacy-import-v1',created_at "
            "FROM response_plans WHERE status='legacy_imported'"
        )
    )
    op.execute(
        sa.text(
            "INSERT INTO response_plan_events "
            "(id,plan_id,tenant_id,revision,event_type,reason_code,public_summary,created_at) "
            "SELECT id,id,tenant_id,0,'legacy_plan_imported','legacy_tool_plan',"
            "'Historical trusted tool call association imported without inferred intent.',"
            "created_at "
            "FROM response_plans WHERE status='legacy_imported'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE trusted_tool_calls SET plan_revision_id=("
            "SELECT response_plans.id FROM response_plans "
            "WHERE response_plans.tenant_id=trusted_tool_calls.tenant_id "
            "AND response_plans.run_id=trusted_tool_calls.run_id)"
        )
    )
    with op.batch_alter_table("trusted_tool_calls") as batch_op:
        batch_op.create_foreign_key(
            "fk_trusted_tool_call_plan_revision_tenant",
            "response_plan_revisions",
            ["plan_revision_id", "tenant_id"],
            ["id", "tenant_id"],
        )
        batch_op.create_foreign_key(
            "fk_trusted_tool_call_plan_action_tenant",
            "response_plan_actions",
            ["plan_action_id", "tenant_id"],
            ["id", "tenant_id"],
        )


def downgrade() -> None:
    nonlegacy = (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM response_plans WHERE status <> 'legacy_imported'"))
        .scalar_one()
    )
    if nonlegacy:
        raise RuntimeError("cannot downgrade while compiled response plans exist")
    with op.batch_alter_table("trusted_tool_calls") as batch_op:
        batch_op.drop_constraint("fk_trusted_tool_call_plan_action_tenant", type_="foreignkey")
        batch_op.drop_constraint("fk_trusted_tool_call_plan_revision_tenant", type_="foreignkey")
        batch_op.drop_column("plan_action_id")
        batch_op.drop_column("plan_revision_id")
    op.drop_index("ix_response_plan_event_plan_created", table_name="response_plan_events")
    op.drop_table("response_plan_events")
    op.drop_index("ix_response_plan_action_revision_sequence", table_name="response_plan_actions")
    op.drop_table("response_plan_actions")
    op.drop_index("ix_response_plan_revision_plan_created", table_name="response_plan_revisions")
    op.drop_table("response_plan_revisions")
    op.drop_index("ix_response_plan_tenant_status_updated", table_name="response_plans")
    op.drop_table("response_plans")
