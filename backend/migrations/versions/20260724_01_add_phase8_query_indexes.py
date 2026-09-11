"""add phase 8 query indexes

Revision ID: 20260724_01
Revises: 20260723_05
Create Date: 2026-07-24
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260724_01"
down_revision: str | Sequence[str] | None = "20260723_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_investigation_run_incident_created",
        "investigation_runs",
        ["incident_id", "created_at", "id"],
    )
    op.create_index(
        "ix_investigation_run_simulation_created",
        "investigation_runs",
        ["simulation_instance_id", "created_at", "id"],
    )
    op.drop_index(
        "ix_trusted_tool_call_tenant_run",
        table_name="trusted_tool_calls",
    )
    op.create_index(
        "ix_trusted_tool_call_tenant_run_created",
        "trusted_tool_calls",
        ["tenant_id", "run_id", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_trusted_tool_call_tenant_run_created",
        table_name="trusted_tool_calls",
    )
    op.create_index(
        "ix_trusted_tool_call_tenant_run",
        "trusted_tool_calls",
        ["tenant_id", "run_id"],
    )
    op.drop_index(
        "ix_investigation_run_simulation_created",
        table_name="investigation_runs",
    )
    op.drop_index(
        "ix_investigation_run_incident_created",
        table_name="investigation_runs",
    )
