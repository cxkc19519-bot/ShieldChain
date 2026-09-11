"""extend ReAct categories for accepted plans and verified completion

Revision ID: 20260824_07
Revises: 20260823_06
Create Date: 2026-08-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_07"
down_revision: str | Sequence[str] | None = "20260823_06"
branch_labels = None
depends_on = None

_OLD_CATEGORIES = (
    "'verification_failed','verification_inconclusive','execution_failed',"
    "'execution_outcome_unknown','approval_rejected','emergency_stopped',"
    "'automation_disabled','dependency_unavailable','evidence_insufficient',"
    "'evidence_conflict','budget_exhausted','loop_detected','unclassified_failure'"
)
_NEW_CATEGORIES = f"'plan_accepted','completed',{_OLD_CATEGORIES}"


def upgrade() -> None:
    with op.batch_alter_table("react_assessments") as batch_op:
        batch_op.drop_constraint("ck_react_assessment_category", type_="check")
        batch_op.create_check_constraint(
            "ck_react_assessment_category",
            f"category IN ({_NEW_CATEGORIES})",
        )
    with op.batch_alter_table("react_plan_revisions") as batch_op:
        batch_op.drop_constraint("ck_react_plan_reason", type_="check")
        batch_op.create_check_constraint(
            "ck_react_plan_reason",
            f"reason IN ({_NEW_CATEGORIES})",
        )


def downgrade() -> None:
    new_rows = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT (SELECT count(*) FROM react_assessments "
                "WHERE category IN ('plan_accepted','completed')) + "
                "(SELECT count(*) FROM react_plan_revisions "
                "WHERE reason IN ('plan_accepted','completed'))"
            )
        )
        .scalar_one()
    )
    if new_rows:
        raise RuntimeError("cannot downgrade while extended ReAct records exist")
    with op.batch_alter_table("react_assessments") as batch_op:
        batch_op.drop_constraint("ck_react_assessment_category", type_="check")
        batch_op.create_check_constraint(
            "ck_react_assessment_category",
            f"category IN ({_OLD_CATEGORIES})",
        )
    with op.batch_alter_table("react_plan_revisions") as batch_op:
        batch_op.drop_constraint("ck_react_plan_reason", type_="check")
        batch_op.create_check_constraint(
            "ck_react_plan_reason",
            f"reason IN ({_OLD_CATEGORIES})",
        )
