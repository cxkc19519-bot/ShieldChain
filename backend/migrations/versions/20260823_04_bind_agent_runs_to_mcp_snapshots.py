"""bind agent runs to MCP snapshots

Revision ID: 20260823_04
Revises: 20260823_03
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_04"
down_revision: str | Sequence[str] | None = "20260823_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_run_mcp_snapshots",
        sa.Column("run_id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), primary_key=True),
        sa.Column("peer_id", sa.String(64), primary_key=True),
        sa.Column("peer_snapshot_id", sa.String(36), nullable=False),
        sa.Column("catalog_revision", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_agent_run_mcp_snapshot_run_tenant",
        ),
        sa.ForeignKeyConstraint(["peer_snapshot_id"], ["mcp_peer_snapshots.id"]),
        sa.UniqueConstraint("run_id", "peer_id", name="uq_agent_run_mcp_snapshot_peer"),
    )
    op.create_index(
        "ix_agent_run_mcp_snapshot_peer",
        "agent_run_mcp_snapshots",
        ["peer_id", "peer_snapshot_id"],
    )


def downgrade() -> None:
    count = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM agent_run_mcp_snapshots")).scalar_one()
    )
    if count:
        raise RuntimeError("cannot downgrade while agent runs reference MCP snapshots")
    op.drop_index("ix_agent_run_mcp_snapshot_peer", table_name="agent_run_mcp_snapshots")
    op.drop_table("agent_run_mcp_snapshots")
