"""add approved Wazuh suppression policies and match audit

Revision ID: 20260909_01
Revises: 20260907_02
Create Date: 2026-09-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260909_01"
down_revision: str | Sequence[str] | None = "20260907_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_suppression_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("source_case_id", sa.String(36), nullable=False),
        sa.Column("source_disposition_id", sa.String(36), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("endpoint", sa.String(256), nullable=True),
        sa.Column("scope", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("rationale", sa.String(1000), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(36), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "tenant_id",
            "source_disposition_id",
            name="uq_wazuh_suppression_tenant_disposition",
        ),
        sa.CheckConstraint(
            "scope IN ('same_rule_endpoint','same_rule')",
            name="ck_wazuh_suppression_scope",
        ),
        sa.CheckConstraint(
            "status IN ('active','revoked')",
            name="ck_wazuh_suppression_status",
        ),
    )
    op.create_index(
        "ix_wazuh_suppression_tenant_active",
        "wazuh_suppression_policies",
        ["tenant_id", "status", "expires_at"],
    )
    op.create_table(
        "wazuh_suppression_matches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("alert_id", sa.String(36), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("endpoint", sa.String(256), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "alert_id", name="uq_wazuh_suppression_match_alert"
        ),
    )
    op.create_index(
        "ix_wazuh_suppression_match_tenant_time",
        "wazuh_suppression_matches",
        ["tenant_id", "matched_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_wazuh_suppression_match_tenant_time",
        table_name="wazuh_suppression_matches",
    )
    op.drop_table("wazuh_suppression_matches")
    op.drop_index(
        "ix_wazuh_suppression_tenant_active",
        table_name="wazuh_suppression_policies",
    )
    op.drop_table("wazuh_suppression_policies")
