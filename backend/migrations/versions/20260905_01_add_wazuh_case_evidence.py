"""add live Wazuh case evidence

Revision ID: 20260905_01
Revises: 20260824_08
Create Date: 2026-09-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260905_01"
down_revision: str | Sequence[str] | None = "20260824_08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_case_runs",
        sa.Column("run_id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("alert_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "tenant_id", name="uq_wazuh_case_run_tenant"),
        sa.UniqueConstraint("case_id", "tenant_id", name="uq_wazuh_case_single_run"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_wazuh_case_run_agent_tenant",
        ),
    )
    op.create_table(
        "wazuh_case_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("evidence_type", sa.String(64), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("raw_reference", sa.String(512), nullable=False),
        sa.Column("integrity_sha256", sa.String(64), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "integrity_sha256", name="uq_wazuh_evidence_run_integrity"),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["agent_runs.id", "agent_runs.tenant_id"],
            name="fk_wazuh_evidence_run_tenant",
        ),
        sa.CheckConstraint("confirmed = 1", name="ck_wazuh_evidence_confirmed"),
        sa.CheckConstraint("length(integrity_sha256) = 64", name="ck_wazuh_evidence_sha256_length"),
    )
    op.create_index(
        "ix_wazuh_evidence_run_observed",
        "wazuh_case_evidence",
        ["run_id", "observed_at"],
    )
    op.create_table(
        "wazuh_case_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "tenant_id"],
            ["wazuh_case_runs.run_id", "wazuh_case_runs.tenant_id"],
            name="fk_wazuh_audit_run_tenant",
        ),
    )
    op.create_index(
        "ix_wazuh_case_audit_run_time",
        "wazuh_case_audit_events",
        ["run_id", "occurred_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_wazuh_case_audit_run_time", table_name="wazuh_case_audit_events")
    op.drop_table("wazuh_case_audit_events")
    op.drop_index("ix_wazuh_evidence_run_observed", table_name="wazuh_case_evidence")
    op.drop_table("wazuh_case_evidence")
    op.drop_table("wazuh_case_runs")
