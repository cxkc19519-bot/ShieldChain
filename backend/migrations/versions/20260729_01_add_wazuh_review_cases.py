"""add review-only cases for high-risk Wazuh alerts

Revision ID: 20260729_01
Revises: 20260728_01
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260729_01"
down_revision: str | Sequence[str] | None = "20260728_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_review_cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("tracking_year", sa.Integer(), nullable=False),
        sa.Column("tracking_sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("endpoint", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status = 'needs_review'", name="ck_wazuh_review_case_status"),
        sa.CheckConstraint("severity BETWEEN 0 AND 15", name="ck_wazuh_review_case_severity"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "alert_id", name="uq_wazuh_review_case_tenant_alert"),
        sa.UniqueConstraint(
            "tenant_id",
            "tracking_year",
            "tracking_sequence",
            name="uq_wazuh_review_case_tenant_tracking",
        ),
    )
    op.create_index(
        "ix_wazuh_review_case_tenant_updated",
        "wazuh_review_cases",
        ["tenant_id", "updated_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_wazuh_review_case_tenant_updated", table_name="wazuh_review_cases")
    op.drop_table("wazuh_review_cases")
