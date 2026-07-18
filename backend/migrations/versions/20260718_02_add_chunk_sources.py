"""persist source occurrences for deterministic RAG chunks

Revision ID: 20260718_02
Revises: 20260718_01
Create Date: 2026-07-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260718_02"
down_revision: str | Sequence[str] | None = "20260718_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "chunk_sources",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("chunk_id", sa.String(length=36), nullable=False),
        sa.Column("occurrence_ordinal", sa.Integer(), nullable=False),
        sa.Column("parsed_element_ordinal", sa.Integer(), nullable=False),
        sa.Column("start_offset", sa.Integer(), nullable=False),
        sa.Column("end_offset", sa.Integer(), nullable=False),
        sa.Column("heading_path_json", sa.JSON(), nullable=False),
        sa.Column("page_number", sa.Integer(), nullable=True),
        sa.Column("structural_location", sa.String(length=512), nullable=True),
        sa.CheckConstraint(
            "occurrence_ordinal >= 0", name="ck_chunk_source_occurrence_nonnegative"
        ),
        sa.CheckConstraint(
            "parsed_element_ordinal >= 0", name="ck_chunk_source_element_nonnegative"
        ),
        sa.CheckConstraint("start_offset >= 0", name="ck_chunk_source_start_nonnegative"),
        sa.CheckConstraint("end_offset > start_offset", name="ck_chunk_source_end_after_start"),
        sa.ForeignKeyConstraint(
            ["chunk_id"], ["knowledge_chunks.id"], name="fk_chunk_source_chunk"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chunk_id", "occurrence_ordinal", name="uq_chunk_source_occurrence"),
    )
    op.create_index("ix_chunk_source_chunk", "chunk_sources", ["chunk_id"])


def downgrade() -> None:
    op.drop_index("ix_chunk_source_chunk", table_name="chunk_sources")
    op.drop_table("chunk_sources")
