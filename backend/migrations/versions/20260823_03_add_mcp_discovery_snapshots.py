"""add allowlisted MCP discovery snapshots

Revision ID: 20260823_03
Revises: 20260823_02
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_03"
down_revision: str | Sequence[str] | None = "20260823_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mcp_peer_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("peer_id", sa.String(64), nullable=False),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("transport", sa.String(32), nullable=False),
        sa.Column("network_policy", sa.String(32), nullable=False),
        sa.Column("protocol_version", sa.String(32), nullable=True),
        sa.Column("catalog_revision", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('accepted','rejected')", name="ck_mcp_peer_snapshot_status"),
        sa.CheckConstraint(
            "(status = 'accepted' AND error_code IS NULL) OR "
            "(status = 'rejected' AND error_code IS NOT NULL)",
            name="ck_mcp_peer_snapshot_error",
        ),
        sa.CheckConstraint("expires_at >= discovered_at", name="ck_mcp_peer_snapshot_expiry"),
    )
    op.create_index(
        "ix_mcp_peer_snapshot_peer_discovered",
        "mcp_peer_snapshots",
        ["peer_id", "discovered_at", "id"],
    )
    op.create_table(
        "mcp_tool_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "peer_snapshot_id",
            sa.String(36),
            sa.ForeignKey("mcp_peer_snapshots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool_identity", sa.String(36), nullable=False),
        sa.Column("remote_name", sa.String(128), nullable=False),
        sa.Column("alias", sa.String(128), nullable=False),
        sa.Column("label", sa.String(256), nullable=False),
        sa.Column("description", sa.String(4096), nullable=False),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("allowed_roles_json", sa.JSON(), nullable=False),
        sa.Column("input_schema_json", sa.JSON(), nullable=False),
        sa.Column("output_schema_json", sa.JSON(), nullable=True),
        sa.Column("remote_annotations_json", sa.JSON(), nullable=False),
        sa.Column("schema_revision", sa.String(64), nullable=False),
        sa.UniqueConstraint(
            "peer_snapshot_id", "remote_name", name="uq_mcp_tool_snapshot_remote_name"
        ),
        sa.UniqueConstraint("peer_snapshot_id", "alias", name="uq_mcp_tool_snapshot_alias"),
        sa.CheckConstraint("classification = 'read_only'", name="ck_mcp_tool_snapshot_read_only"),
    )
    op.create_index("ix_mcp_tool_snapshot_alias", "mcp_tool_snapshots", ["alias"])


def downgrade() -> None:
    count = op.get_bind().execute(sa.text("SELECT count(*) FROM mcp_peer_snapshots")).scalar_one()
    if count:
        raise RuntimeError("cannot downgrade while MCP discovery snapshots exist")
    op.drop_index("ix_mcp_tool_snapshot_alias", table_name="mcp_tool_snapshots")
    op.drop_table("mcp_tool_snapshots")
    op.drop_index("ix_mcp_peer_snapshot_peer_discovered", table_name="mcp_peer_snapshots")
    op.drop_table("mcp_peer_snapshots")
