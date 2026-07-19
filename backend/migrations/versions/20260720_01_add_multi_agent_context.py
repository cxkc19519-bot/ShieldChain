"""add tenant-bounded multi-agent case context

Revision ID: 20260720_01
Revises: 20260718_03
Create Date: 2026-07-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260720_01"
down_revision: str | Sequence[str] | None = "20260718_03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEMO_TENANT_ID = "00000000-0000-4000-8000-000000000001"
_TENANT_DEFAULT = sa.text(f"'{_DEMO_TENANT_ID}'")
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


def upgrade() -> None:
    # The literal is intentionally migration-owned: historical simulation rows must
    # never depend on a mutable application setting or a client-supplied identity.
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                server_default=_TENANT_DEFAULT,
                nullable=False,
            )
        )
        batch_op.create_unique_constraint("uq_incident_id_tenant", ["id", "tenant_id"])

    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                server_default=_TENANT_DEFAULT,
                nullable=False,
            )
        )
        batch_op.drop_constraint("fk_investigation_run_incident", type_="foreignkey")
        batch_op.create_unique_constraint(
            "uq_investigation_run_id_tenant", ["id", "tenant_id"]
        )
        batch_op.create_foreign_key(
            "fk_investigation_run_incident_tenant",
            "incidents",
            ["incident_id", "tenant_id"],
            ["id", "tenant_id"],
        )

    op.create_table(
        "case_contexts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("user_goal", sa.String(length=4096), nullable=False),
        sa.Column("hypotheses_json", sa.JSON(), nullable=False),
        sa.Column("risks_json", sa.JSON(), nullable=False),
        sa.Column("plan_json", sa.JSON(), nullable=False),
        sa.Column("step_status_json", sa.JSON(), nullable=False),
        sa.Column("disposition_status", sa.String(length=128), nullable=False),
        sa.Column("budget_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision >= 0", name="ck_case_context_revision_nonnegative"),
        sa.CheckConstraint(f"phase IN ({_PHASES})", name="ck_case_context_phase"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_case_context_run_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", name="uq_case_context_run"),
        sa.UniqueConstraint("id", "tenant_id", name="uq_case_context_id_tenant"),
    )
    op.create_index("ix_case_context_tenant_phase", "case_contexts", ["tenant_id", "phase"])

    op.create_table(
        "confirmed_case_facts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_context_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("statement", sa.String(length=4096), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("confirmed = 1", name="ck_confirmed_fact_confirmed"),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_confirmed_fact_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["case_context_id", "tenant_id"],
            ["case_contexts.id", "case_contexts.tenant_id"],
            name="fk_confirmed_fact_case_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_confirmed_fact_case_created",
        "confirmed_case_facts",
        ["case_context_id", "created_at"],
    )

    op.create_table(
        "agent_private_contexts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("working_items_json", sa.JSON(), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision >= 0", name="ck_private_context_revision_nonnegative"),
        sa.CheckConstraint(f"role IN ({_ROLES})", name="ck_private_context_role"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_private_context_run_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "role", name="uq_private_context_run_role"),
    )
    op.create_index(
        "ix_private_context_tenant_role",
        "agent_private_contexts",
        ["tenant_id", "role"],
    )

    op.create_table(
        "agent_handoffs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("sender_role", sa.String(length=32), nullable=False),
        sa.Column("receiver_role", sa.String(length=32), nullable=False),
        sa.Column("conclusion", sa.String(length=4096), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("open_questions_json", sa.JSON(), nullable=False),
        sa.Column("recommended_actions_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"sender_role IN ({_ROLES})", name="ck_handoff_sender_role"),
        sa.CheckConstraint(f"receiver_role IN ({_ROLES})", name="ck_handoff_receiver_role"),
        sa.CheckConstraint("sender_role <> receiver_role", name="ck_handoff_distinct_roles"),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_handoff_confidence"
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_agent_handoff_run_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_handoff_run_created", "agent_handoffs", ["run_id", "created_at"])
    op.create_index(
        "ix_handoff_tenant_receiver", "agent_handoffs", ["tenant_id", "receiver_role"]
    )

    op.create_table(
        "agent_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("summary", sa.String(length=4096), nullable=False),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("hypotheses_json", sa.JSON(), nullable=False),
        sa.Column("risks_json", sa.JSON(), nullable=False),
        sa.Column("recommended_actions_json", sa.JSON(), nullable=False),
        sa.Column("termination_reason", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"role IN ({_ROLES})", name="ck_agent_execution_role"),
        sa.CheckConstraint(
            f"termination_reason IN ({_TERMINATIONS})",
            name="ck_agent_execution_termination",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["investigation_runs.id", "investigation_runs.tenant_id"],
            name="fk_agent_execution_run_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_execution_run_created", "agent_executions", ["run_id", "created_at"]
    )
    op.create_index(
        "ix_agent_execution_tenant_role", "agent_executions", ["tenant_id", "role"]
    )


def downgrade() -> None:
    op.drop_index("ix_agent_execution_tenant_role", table_name="agent_executions")
    op.drop_index("ix_agent_execution_run_created", table_name="agent_executions")
    op.drop_table("agent_executions")
    op.drop_index("ix_handoff_tenant_receiver", table_name="agent_handoffs")
    op.drop_index("ix_handoff_run_created", table_name="agent_handoffs")
    op.drop_table("agent_handoffs")
    op.drop_index("ix_private_context_tenant_role", table_name="agent_private_contexts")
    op.drop_table("agent_private_contexts")
    op.drop_index("ix_confirmed_fact_case_created", table_name="confirmed_case_facts")
    op.drop_table("confirmed_case_facts")
    op.drop_index("ix_case_context_tenant_phase", table_name="case_contexts")
    op.drop_table("case_contexts")

    with op.batch_alter_table("investigation_runs") as batch_op:
        batch_op.drop_constraint("fk_investigation_run_incident_tenant", type_="foreignkey")
        batch_op.drop_constraint("uq_investigation_run_id_tenant", type_="unique")
        batch_op.create_foreign_key(
            "fk_investigation_run_incident", "incidents", ["incident_id"], ["id"]
        )
        batch_op.drop_column("tenant_id")
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_constraint("uq_incident_id_tenant", type_="unique")
        batch_op.drop_column("tenant_id")
