"""add trusted tool execution leases

Revision ID: 20260723_02
Revises: 20260723_01
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260723_02"
down_revision: str | Sequence[str] | None = "20260723_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_execution_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool_call_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("holder_id", sa.String(36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(
            ["tool_call_id", "tenant_id"],
            ["trusted_tool_calls.id", "trusted_tool_calls.tenant_id"],
            name="fk_tool_execution_lease_call_tenant",
        ),
        sa.UniqueConstraint(
            "tool_call_id", "attempt_number", name="uq_tool_execution_lease_attempt"
        ),
        sa.CheckConstraint(
            "attempt_number BETWEEN 1 AND 4", name="ck_tool_execution_lease_attempt"
        ),
        sa.CheckConstraint(
            "(released_at IS NULL AND release_reason IS NULL) OR "
            "(released_at IS NOT NULL AND release_reason IS NOT NULL)",
            name="ck_tool_execution_lease_release",
        ),
    )
    op.create_index(
        "ix_tool_execution_lease_tenant_expiry",
        "tool_execution_leases",
        ["tenant_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_tool_execution_lease_tenant_expiry", table_name="tool_execution_leases")
    op.drop_table("tool_execution_leases")
