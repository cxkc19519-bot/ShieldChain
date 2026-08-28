"""add generic agent and operations runs

Revision ID: 20260823_01
Revises: 20260729_01
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_01"
down_revision: str | Sequence[str] | None = "20260729_01"
branch_labels = None
depends_on = None

_SYSTEM_PRINCIPAL = "00000000-0000-4000-8000-000000000000"
_RUN_KINDS = "'incident_investigation','operations_report'"
_RUN_STATUSES = (
    "'pending','running','awaiting_approval','awaiting_execution','verifying',"
    "'needs_review','completed','failed','cancelled'"
)
_RUN_FOREIGN_KEYS = (
    ("case_contexts", "fk_case_context_run_tenant"),
    ("agent_private_contexts", "fk_private_context_run_tenant"),
    ("agent_handoffs", "fk_agent_handoff_run_tenant"),
    ("agent_executions", "fk_agent_execution_run_tenant"),
    ("trusted_tool_calls", "fk_trusted_tool_call_run_tenant"),
    ("react_loops", "fk_react_loop_run_tenant"),
)


def _retarget_run_foreign_keys(target_table: str) -> None:
    for table_name, constraint_name in _RUN_FOREIGN_KEYS:
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.drop_constraint(constraint_name, type_="foreignkey")
            batch_op.create_foreign_key(
                constraint_name,
                target_table,
                ["run_id", "tenant_id"],
                ["id", "tenant_id"],
            )


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("run_kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("goal", sa.String(4096), nullable=False),
        sa.Column("catalog_revision", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("id", "tenant_id", name="uq_agent_run_id_tenant"),
        sa.CheckConstraint(f"run_kind IN ({_RUN_KINDS})", name="ck_agent_run_kind"),
        sa.CheckConstraint(f"status IN ({_RUN_STATUSES})", name="ck_agent_run_status"),
        sa.CheckConstraint("revision >= 0", name="ck_agent_run_revision"),
    )
    op.create_index(
        "ix_agent_run_tenant_status_created",
        "agent_runs",
        ["tenant_id", "status", "created_at", "id"],
    )
    op.execute(
        sa.text(
            "INSERT INTO agent_runs "
            "(id,tenant_id,principal_id,run_kind,status,goal,catalog_revision,revision,"
            "created_at,updated_at,completed_at) "
            "SELECT id,tenant_id,:principal,'incident_investigation',"
            "CASE "
            "WHEN status = 'pending' THEN 'pending' "
            "WHEN status IN ('collecting','analyzing','action_planned','executing') THEN 'running' "
            "WHEN status = 'verifying' THEN 'verifying' "
            "WHEN status IN ('needs_review','interrupted') THEN 'needs_review' "
            "WHEN status = 'failed' THEN 'failed' "
            "ELSE 'completed' END,"
            "'Legacy incident investigation.','legacy-investigation-v1',0,"
            "created_at,updated_at,completed_at FROM investigation_runs"
        ).bindparams(principal=_SYSTEM_PRINCIPAL)
    )
    op.create_table(
        "operations_runs",
        sa.Column("run_id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("start_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("report_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "tenant_id", name="uq_operations_run_id_tenant"),
        sa.UniqueConstraint("report_id", name="uq_operations_run_report"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_operations_run_agent_tenant",
        ),
        sa.CheckConstraint("end_at >= start_at", name="ck_operations_run_time_window"),
    )
    op.create_index(
        "ix_operations_run_tenant_created",
        "operations_runs",
        ["tenant_id", "created_at", "run_id"],
    )
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.create_foreign_key(
            "fk_investigation_agent_run_tenant",
            "agent_runs",
            ["id", "tenant_id"],
            ["id", "tenant_id"],
        )
    _retarget_run_foreign_keys("agent_runs")


def downgrade() -> None:
    operations_count = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM operations_runs")).scalar_one()
    )
    generic_only_count = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM agent_runs AS a "
                "LEFT JOIN investigation_runs AS i "
                "ON i.id = a.id AND i.tenant_id = a.tenant_id "
                "WHERE a.run_kind <> 'incident_investigation' OR i.id IS NULL"
            )
        )
        .scalar_one()
    )
    if operations_count or generic_only_count:
        raise RuntimeError("cannot downgrade while operations runs exist")
    _retarget_run_foreign_keys("investigation_runs")
    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.drop_constraint("fk_investigation_agent_run_tenant", type_="foreignkey")
    op.drop_index("ix_operations_run_tenant_created", table_name="operations_runs")
    op.drop_table("operations_runs")
    op.drop_index("ix_agent_run_tenant_status_created", table_name="agent_runs")
    op.drop_table("agent_runs")
