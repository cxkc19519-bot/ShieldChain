"""persist semantic chunking retry audit

Revision ID: 20260718_03
Revises: 20260718_02
Create Date: 2026-07-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260718_03"
down_revision: str | Sequence[str] | None = "20260718_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("document_versions") as batch_op:
        batch_op.add_column(
            sa.Column("chunking_failure_category", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(
            sa.Column("chunking_retry_key", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("chunking_requested_model", sa.String(length=128), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_document_version_retry_key_length",
            "chunking_retry_key IS NULL OR "
            "(length(chunking_retry_key) = 64 AND lower(chunking_retry_key) = chunking_retry_key)",
        )
        batch_op.create_check_constraint(
            "ck_document_version_chunking_failure_category",
            "chunking_failure_category IS NULL OR chunking_failure_category IN ("
            "'authentication','boundary_empty','boundary_limit','boundary_omission',"
            "'boundary_order','boundary_out_of_range','boundary_overlap','candidate_integrity',"
            "'candidate_limit','content_hash_collision','duplicate_output','empty_candidates',"
            "'llm_error','malformed_json','prompt_limit','rate_limit','response_error',"
            "'response_limit','schema_error','source_overlap','timeout','token_limit','unavailable')",
        )


def downgrade() -> None:
    with op.batch_alter_table("document_versions") as batch_op:
        batch_op.drop_constraint(
            "ck_document_version_retry_key_length", type_="check"
        )
        batch_op.drop_constraint(
            "ck_document_version_chunking_failure_category", type_="check"
        )
        batch_op.drop_column("chunking_retry_key")
        batch_op.drop_column("chunking_requested_model")
        batch_op.drop_column("chunking_failure_category")
