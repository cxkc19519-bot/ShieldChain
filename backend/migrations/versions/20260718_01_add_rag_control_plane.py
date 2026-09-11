"""add RAG control plane

Revision ID: 20260718_01
Revises: 20260713_01
Create Date: 2026-07-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260718_01"
down_revision: str | Sequence[str] | None = "20260713_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_bases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("default_sensitivity", sa.String(length=32), nullable=False),
        sa.Column("version_policy", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('draft','published','archived','deleted')", name="ck_knowledge_base_status"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_knowledge_base_tenant_name"),
    )
    op.create_index("ix_knowledge_base_tenant_status", "knowledge_bases", ["tenant_id", "status"])
    op.create_table(
        "knowledge_documents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("knowledge_base_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("original_filename", sa.String(length=512), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_version_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(content_sha256) = 64", name="ck_document_sha256_length"),
        sa.CheckConstraint(
            "status IN ('draft','published','delete_pending','deleted')",
            name="ck_knowledge_document_status",
        ),
        sa.ForeignKeyConstraint(
            ["knowledge_base_id"], ["knowledge_bases.id"], name="fk_document_knowledge_base"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("knowledge_base_id", "content_sha256", name="uq_document_content"),
    )
    op.create_index("ix_document_tenant_status", "knowledge_documents", ["tenant_id", "status"])
    op.create_index(
        "ix_document_base_tenant", "knowledge_documents", ["knowledge_base_id", "tenant_id"]
    )
    op.create_table(
        "document_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("document_id", sa.String(length=36), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("parsing_status", sa.String(length=32), nullable=False),
        sa.Column("chunking_status", sa.String(length=32), nullable=False),
        sa.Column("index_status", sa.String(length=32), nullable=False),
        sa.Column("parser_name", sa.String(length=128), nullable=False),
        sa.Column("parser_version", sa.String(length=128), nullable=False),
        sa.Column("chunking_strategy", sa.String(length=128), nullable=False),
        sa.Column("chunking_prompt_version", sa.String(length=128), nullable=True),
        sa.Column("chunking_model", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("version_number >= 1", name="ck_document_version_number_positive"),
        sa.CheckConstraint(
            "parsing_status IN ('pending','processing','succeeded','failed','ocr_required')",
            name="ck_document_version_parsing_status",
        ),
        sa.CheckConstraint(
            "chunking_status IN ('pending','processing','succeeded','failed')",
            name="ck_document_version_chunking_status",
        ),
        sa.CheckConstraint(
            "index_status IN ('pending','processing','succeeded','failed',"
            "'delete_pending','deleted')",
            name="ck_document_version_index_status",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"], ["knowledge_documents.id"], name="fk_document_version_document"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_id", "version_number", name="uq_document_version_number"),
        sa.UniqueConstraint(
            "document_id", "idempotency_key", name="uq_document_version_idempotency"
        ),
    )
    op.create_index(
        "ix_document_version_document_created", "document_versions", ["document_id", "created_at"]
    )
    with op.batch_alter_table("knowledge_documents") as batch_op:
        batch_op.create_foreign_key(
            "fk_document_current_version",
            "document_versions",
            ["current_version_id"],
            ["id"],
        )
    op.create_table(
        "knowledge_chunks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("heading_path_json", sa.JSON(), nullable=False),
        sa.Column("page_number", sa.Integer(), nullable=True),
        sa.Column("structural_location", sa.String(length=512), nullable=True),
        sa.Column("text", sa.String(), nullable=False),
        sa.Column("token_count", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("sensitivity", sa.String(length=32), nullable=False),
        sa.Column("permission_tags_json", sa.JSON(), nullable=False),
        sa.Column("chunking_mode", sa.String(length=64), nullable=False),
        sa.Column("is_degraded", sa.Boolean(), nullable=False),
        sa.CheckConstraint("ordinal >= 0", name="ck_chunk_ordinal_nonnegative"),
        sa.CheckConstraint("token_count >= 1", name="ck_chunk_token_count_positive"),
        sa.CheckConstraint("length(content_sha256) = 64", name="ck_chunk_sha256_length"),
        sa.ForeignKeyConstraint(
            ["document_version_id"], ["document_versions.id"], name="fk_chunk_document_version"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_version_id", "ordinal", name="uq_chunk_ordinal"),
        sa.UniqueConstraint("document_version_id", "content_sha256", name="uq_chunk_content"),
    )
    op.create_index(
        "ix_chunk_version_ordinal", "knowledge_chunks", ["document_version_id", "ordinal"]
    )
    op.create_table(
        "knowledge_base_acl",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("knowledge_base_id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("sensitivity", sa.String(length=32), nullable=False),
        sa.Column("permission_tag", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["knowledge_base_id"], ["knowledge_bases.id"], name="fk_knowledge_base_acl_base"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "knowledge_base_id",
            "principal_id",
            "role",
            "sensitivity",
            "permission_tag",
            name="uq_knowledge_base_acl_grant",
        ),
    )
    op.create_index(
        "ix_knowledge_base_acl_scope", "knowledge_base_acl", ["tenant_id", "principal_id"]
    )
    op.create_table(
        "rag_index_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("chunk_id", sa.String(length=36), nullable=False),
        sa.Column("bm25_key", sa.String(length=256), nullable=True),
        sa.Column("embedding_model", sa.String(length=128), nullable=True),
        sa.Column("vector_id", sa.String(length=256), nullable=True),
        sa.Column("reranker_model", sa.String(length=128), nullable=True),
        sa.Column("index_version", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_category", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','delete_pending','deleted')",
            name="ck_rag_index_record_status",
        ),
        sa.ForeignKeyConstraint(
            ["document_version_id"], ["document_versions.id"], name="fk_rag_index_record_version"
        ),
        sa.ForeignKeyConstraint(
            ["chunk_id"], ["knowledge_chunks.id"], name="fk_rag_index_record_chunk"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chunk_id", "index_version", name="uq_rag_index_record_chunk_version"),
    )
    op.create_index(
        "ix_rag_index_record_version_status", "rag_index_records", ["document_version_id", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_rag_index_record_version_status", table_name="rag_index_records")
    op.drop_table("rag_index_records")
    op.drop_index("ix_knowledge_base_acl_scope", table_name="knowledge_base_acl")
    op.drop_table("knowledge_base_acl")
    op.drop_index("ix_chunk_version_ordinal", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")
    with op.batch_alter_table("knowledge_documents") as batch_op:
        batch_op.drop_constraint("fk_document_current_version", type_="foreignkey")
    op.drop_index("ix_document_version_document_created", table_name="document_versions")
    op.drop_table("document_versions")
    op.drop_index("ix_document_base_tenant", table_name="knowledge_documents")
    op.drop_index("ix_document_tenant_status", table_name="knowledge_documents")
    op.drop_table("knowledge_documents")
    op.drop_index("ix_knowledge_base_tenant_status", table_name="knowledge_bases")
    op.drop_table("knowledge_bases")
