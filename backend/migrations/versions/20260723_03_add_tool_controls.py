"""add trusted tool controls

Revision ID: 20260723_03
Revises: 20260723_02
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_03"
down_revision: str | Sequence[str] | None = "20260723_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS_WITH_PAUSED = (
    "status IN ('proposed','policy_checked','awaiting_approval','approved','paused',"
    "'executing','verifying','succeeded','failed','needs_review','rejected','cancelled',"
    "'emergency_stopped')"
)
_STATUS_WITHOUT_PAUSED = _STATUS_WITH_PAUSED.replace(",'paused'", "")


def upgrade() -> None:
    with op.batch_alter_table("trusted_tool_calls", recreate="always") as batch:
        batch.drop_constraint("ck_trusted_tool_call_status", type_="check")
        batch.create_check_constraint("ck_trusted_tool_call_status", _STATUS_WITH_PAUSED)
    op.create_table(
        "tool_automation_controls",
        sa.Column("tenant_id", sa.String(36), primary_key=True),
        sa.Column("automation_enabled", sa.Boolean(), nullable=False),
        sa.Column("emergency_stop_active", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("actor_subject_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("revision >= 0", name="ck_tool_automation_control_revision"),
    )
    op.create_table(
        "tool_control_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("tool_call_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_subject_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("previous_status", sa.String(32), nullable=True),
        sa.Column("new_status", sa.String(32), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_control_event_call_tenant",
        ),
    )
    op.create_index(
        "ix_tool_control_event_tenant_time",
        "tool_control_events",
        ["tenant_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_tool_control_event_tenant_time", table_name="tool_control_events")
    op.drop_table("tool_control_events")
    op.drop_table("tool_automation_controls")
    with op.batch_alter_table("trusted_tool_calls", recreate="always") as batch:
        batch.drop_constraint("ck_trusted_tool_call_status", type_="check")
        batch.create_check_constraint("ck_trusted_tool_call_status", _STATUS_WITHOUT_PAUSED)
