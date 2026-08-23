"""add bounded agent tool call audit

Revision ID: 20260823_02
Revises: 20260823_01
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_02"
down_revision: str | Sequence[str] | None = "20260823_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_tool_calls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=True),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("role", sa.String(32), nullable=True),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("provider_kind", sa.String(16), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("tool_identity", sa.String(36), nullable=False),
        sa.Column("tool_alias", sa.String(128), nullable=False),
        sa.Column("catalog_revision", sa.String(64), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.Column("arguments_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=True),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=True),
        sa.Column("references_json", sa.JSON(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("result_bytes", sa.Integer(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("id", "tenant_id", name="uq_agent_tool_call_id_tenant"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_agent_tool_call_run_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["case_id", "tenant_id"],
            ["case_contexts.id", "case_contexts.tenant_id"],
            name="fk_agent_tool_call_case_tenant",
        ),
        sa.CheckConstraint(
            "direction IN ('internal','mcp_inbound','mcp_outbound')",
            name="ck_agent_tool_call_direction",
        ),
        sa.CheckConstraint(
            "provider_kind IN ('builtin','rag','remote_mcp')",
            name="ck_agent_tool_call_provider_kind",
        ),
        sa.CheckConstraint(
            "status IN ('running','succeeded','empty','failed','timed_out','cancelled',"
            "'rejected','unknown')",
            name="ck_agent_tool_call_status",
        ),
        sa.CheckConstraint(
            "role IS NULL OR role IN ('superagent','alert_triage','threat_investigation',"
            "'knowledge_retrieval','response_planning','verification','reporting')",
            name="ck_agent_tool_call_role",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND finished_at IS NULL) OR "
            "(status <> 'running' AND finished_at IS NOT NULL)",
            name="ck_agent_tool_call_terminal_time",
        ),
        sa.CheckConstraint("result_count BETWEEN 0 AND 50", name="ck_agent_tool_call_result_count"),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0", name="ck_agent_tool_duration"
        ),
        sa.CheckConstraint("attempt BETWEEN 1 AND 4", name="ck_agent_tool_attempt"),
        sa.CheckConstraint(
            "result_bytes IS NULL OR result_bytes >= 0", name="ck_agent_tool_result_bytes"
        ),
    )
    op.create_index(
        "ix_agent_tool_call_tenant_run_created",
        "agent_tool_calls",
        ["tenant_id", "run_id", "created_at", "id"],
    )
    op.create_index(
        "ix_agent_tool_call_direction_status_created",
        "agent_tool_calls",
        ["direction", "status", "created_at"],
    )


def downgrade() -> None:
    count = op.get_bind().execute(sa.text("SELECT count(*) FROM agent_tool_calls")).scalar_one()
    if count:
        raise RuntimeError("cannot downgrade while agent tool call audits exist")
    op.drop_index("ix_agent_tool_call_direction_status_created", table_name="agent_tool_calls")
    op.drop_index("ix_agent_tool_call_tenant_run_created", table_name="agent_tool_calls")
    op.drop_table("agent_tool_calls")
