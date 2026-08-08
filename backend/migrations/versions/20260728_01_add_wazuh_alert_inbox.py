"""add read-only Wazuh alert inbox

Revision ID: 20260728_01
Revises: 20260724_01
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260728_01"
down_revision: str | Sequence[str] | None = "20260724_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_alerts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=256), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=True),
        sa.Column("agent_name", sa.String(length=256), nullable=True),
        sa.Column("mitre_ids_json", sa.JSON(), nullable=False),
        sa.Column("process_name", sa.String(length=512), nullable=True),
        sa.Column("parent_process_name", sa.String(length=512), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("severity BETWEEN 0 AND 15", name="ck_wazuh_alert_severity"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "external_id", name="uq_wazuh_alert_tenant_external"),
    )
    op.create_index(
        "ix_wazuh_alert_tenant_received",
        "wazuh_alerts",
        ["tenant_id", "received_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_wazuh_alert_tenant_received", table_name="wazuh_alerts")
    op.drop_table("wazuh_alerts")
