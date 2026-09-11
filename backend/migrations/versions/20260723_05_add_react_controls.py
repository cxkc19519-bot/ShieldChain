"""add controlled react human controls

Revision ID: 20260723_05
Revises: 20260723_04
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_05"
down_revision: str | Sequence[str] | None = "20260723_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "react_control_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("loop_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("from_status", sa.String(32), nullable=False),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("actor_subject_id", sa.String(36), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("reason_summary", sa.String(512), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["loop_id", "tenant_id"],
            ["react_loops.id", "react_loops.tenant_id"],
            name="fk_react_control_loop_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "request_id", name="uq_react_control_request"),
        sa.CheckConstraint("action IN ('takeover','resume')", name="ck_react_control_action"),
        sa.CheckConstraint("revision > 0", name="ck_react_control_revision"),
    )
    op.create_index("ix_react_control_loop_time", "react_control_events", ["loop_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_react_control_loop_time", table_name="react_control_events")
    op.drop_table("react_control_events")
