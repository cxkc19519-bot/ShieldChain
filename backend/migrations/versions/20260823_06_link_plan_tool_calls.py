"""link accepted response plans to trusted tool calls

Revision ID: 20260823_06
Revises: 20260823_05
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_06"
down_revision: str | Sequence[str] | None = "20260823_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    duplicate_actions = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM ("
                "SELECT tenant_id,plan_action_id FROM trusted_tool_calls "
                "WHERE plan_action_id IS NOT NULL GROUP BY tenant_id,plan_action_id "
                "HAVING count(*) > 1"
                ") AS duplicate_plan_actions"
            )
        )
        .scalar_one()
    )
    if duplicate_actions:
        raise RuntimeError("cannot enforce one trusted tool call per response plan action")
    with op.batch_alter_table("response_plan_events") as batch_op:
        batch_op.add_column(sa.Column("actor_subject_id", sa.String(36), nullable=True))
    with op.batch_alter_table("trusted_tool_calls") as batch_op:
        batch_op.create_unique_constraint(
            "uq_trusted_tool_plan_action",
            ["tenant_id", "plan_action_id"],
        )


def downgrade() -> None:
    actor_events = (
        op.get_bind()
        .execute(
            sa.text("SELECT count(*) FROM response_plan_events WHERE actor_subject_id IS NOT NULL")
        )
        .scalar_one()
    )
    if actor_events:
        raise RuntimeError("cannot downgrade while operator response plan events exist")
    with op.batch_alter_table("trusted_tool_calls") as batch_op:
        batch_op.drop_constraint("uq_trusted_tool_plan_action", type_="unique")
    with op.batch_alter_table("response_plan_events") as batch_op:
        batch_op.drop_column("actor_subject_id")
