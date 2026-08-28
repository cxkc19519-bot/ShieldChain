"""add explicit approval-expired ReAct category

Revision ID: 20260824_08
Revises: 20260824_07
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_08"
down_revision: str | Sequence[str] | None = "20260824_07"
branch_labels = None
depends_on = None

_OLD_CATEGORIES = (
    "'plan_accepted','completed','verification_failed','verification_inconclusive',"
    "'execution_failed','execution_outcome_unknown','approval_rejected','emergency_stopped',"
    "'automation_disabled','dependency_unavailable','evidence_insufficient',"
    "'evidence_conflict','budget_exhausted','loop_detected','unclassified_failure'"
)
_NEW_CATEGORIES = f"'approval_expired',{_OLD_CATEGORIES}"


def _replace_constraints(categories: str) -> None:
    with op.batch_alter_table("react_assessments") as batch_op:
        batch_op.drop_constraint("ck_react_assessment_category", type_="check")
        batch_op.create_check_constraint(
            "ck_react_assessment_category",
            f"category IN ({categories})",
        )
    with op.batch_alter_table("react_plan_revisions") as batch_op:
        batch_op.drop_constraint("ck_react_plan_reason", type_="check")
        batch_op.create_check_constraint(
            "ck_react_plan_reason",
            f"reason IN ({categories})",
        )


def upgrade() -> None:
    _replace_constraints(_NEW_CATEGORIES)


def downgrade() -> None:
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT (SELECT count(*) FROM react_assessments "
                "WHERE category = 'approval_expired') + "
                "(SELECT count(*) FROM react_plan_revisions "
                "WHERE reason = 'approval_expired')"
            )
        )
        .scalar_one()
    )
    if rows:
        raise RuntimeError("cannot downgrade while approval-expired ReAct records exist")
    _replace_constraints(_OLD_CATEGORIES)
