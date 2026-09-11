"""add append-only Wazuh false-positive feedback

Revision ID: 20260907_01
Revises: 20260905_01
Create Date: 2026-09-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260907_01"
down_revision: str | Sequence[str] | None = "20260905_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_case_dispositions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("rationale", sa.String(1000), nullable=False),
        sa.Column("suppression_scope", sa.String(32), nullable=False),
        sa.Column("suppression_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewer_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["wazuh_case_runs.run_id", "wazuh_case_runs.tenant_id"],
            name="fk_wazuh_disposition_run_tenant",
        ),
        sa.CheckConstraint(
            "decision IN ('false_positive','true_positive','needs_more_evidence')",
            name="ck_wazuh_disposition_decision",
        ),
        sa.CheckConstraint(
            "suppression_scope IN ('none','same_rule_endpoint','same_rule')",
            name="ck_wazuh_disposition_scope",
        ),
    )
    op.create_index(
        "ix_wazuh_disposition_case_created",
        "wazuh_case_dispositions",
        ["tenant_id", "case_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_wazuh_disposition_case_created", table_name="wazuh_case_dispositions")
    op.drop_table("wazuh_case_dispositions")
