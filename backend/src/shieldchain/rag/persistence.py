"""SQLAlchemy control-plane rows for product RAG.

Rows deliberately store UUIDs as canonical strings so the SQLite development profile and
future database profiles share the same externally stable identifiers.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shieldchain.db.base import Base


class KnowledgeBaseRow(Base):
    __tablename__ = "knowledge_bases"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_knowledge_base_tenant_name"),
        CheckConstraint(
            "status IN ('draft','published','archived','deleted')", name="ck_knowledge_base_status"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    default_sensitivity: Mapped[str] = mapped_column(String(32), nullable=False)
    version_policy: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_knowledge_base_tenant_status", KnowledgeBaseRow.tenant_id, KnowledgeBaseRow.status)


class KnowledgeDocumentRow(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint("knowledge_base_id", "content_sha256", name="uq_document_content"),
        CheckConstraint(
            "status IN ('draft','published','delete_pending','deleted')",
            name="ck_knowledge_document_status",
        ),
        CheckConstraint("length(content_sha256) = 64", name="ck_document_sha256_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    knowledge_base_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("knowledge_bases.id", name="fk_document_knowledge_base"),
        nullable=False,
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_version_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("document_versions.id", name="fk_document_current_version"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_document_tenant_status", KnowledgeDocumentRow.tenant_id, KnowledgeDocumentRow.status)
Index(
    "ix_document_base_tenant",
    KnowledgeDocumentRow.knowledge_base_id,
    KnowledgeDocumentRow.tenant_id,
)


class DocumentVersionRow(Base):
    __tablename__ = "document_versions"
    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_document_version_number"),
        UniqueConstraint("document_id", "idempotency_key", name="uq_document_version_idempotency"),
        CheckConstraint("version_number >= 1", name="ck_document_version_number_positive"),
        CheckConstraint(
            "parsing_status IN ('pending','processing','succeeded','failed','ocr_required')",
            name="ck_document_version_parsing_status",
        ),
        CheckConstraint(
            "chunking_status IN ('pending','processing','succeeded','failed')",
            name="ck_document_version_chunking_status",
        ),
        CheckConstraint(
            "index_status IN ('pending','processing','succeeded','failed',"
            "'delete_pending','deleted')",
            name="ck_document_version_index_status",
        ),
        CheckConstraint(
            "chunking_retry_key IS NULL OR "
            "(length(chunking_retry_key) = 64 AND lower(chunking_retry_key) = chunking_retry_key)",
            name="ck_document_version_retry_key_length",
        ),
        CheckConstraint(
            "chunking_failure_category IS NULL OR chunking_failure_category IN ("
            "'authentication','boundary_empty','boundary_limit','boundary_omission',"
            "'boundary_order','boundary_out_of_range','boundary_overlap','candidate_integrity',"
            "'candidate_limit','content_hash_collision','duplicate_output','empty_candidates',"
            "'llm_error','malformed_json','prompt_limit','rate_limit','response_error',"
            "'response_limit','schema_error','source_overlap','timeout','token_limit','unavailable')",
            name="ck_document_version_chunking_failure_category",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("knowledge_documents.id", name="fk_document_version_document"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    parsing_status: Mapped[str] = mapped_column(String(32), nullable=False)
    chunking_status: Mapped[str] = mapped_column(String(32), nullable=False)
    index_status: Mapped[str] = mapped_column(String(32), nullable=False)
    parser_name: Mapped[str] = mapped_column(String(128), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(128), nullable=False)
    chunking_strategy: Mapped[str] = mapped_column(String(128), nullable=False)
    chunking_prompt_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    chunking_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    chunking_failure_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    chunking_retry_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chunking_requested_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Index(
    "ix_document_version_document_created",
    DocumentVersionRow.document_id,
    DocumentVersionRow.created_at,
)


class KnowledgeChunkRow(Base):
    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        UniqueConstraint("document_version_id", "ordinal", name="uq_chunk_ordinal"),
        UniqueConstraint("document_version_id", "content_sha256", name="uq_chunk_content"),
        CheckConstraint("ordinal >= 0", name="ck_chunk_ordinal_nonnegative"),
        CheckConstraint("token_count >= 1", name="ck_chunk_token_count_positive"),
        CheckConstraint("length(content_sha256) = 64", name="ck_chunk_sha256_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_version_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("document_versions.id", name="fk_chunk_document_version"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    heading_path_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    page_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    structural_location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    text: Mapped[str] = mapped_column(String, nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False)
    permission_tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    chunking_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    is_degraded: Mapped[bool] = mapped_column(Boolean, nullable=False)


Index("ix_chunk_version_ordinal", KnowledgeChunkRow.document_version_id, KnowledgeChunkRow.ordinal)


class ChunkSourceRow(Base):
    __tablename__ = "chunk_sources"
    __table_args__ = (
        UniqueConstraint("chunk_id", "occurrence_ordinal", name="uq_chunk_source_occurrence"),
        CheckConstraint("occurrence_ordinal >= 0", name="ck_chunk_source_occurrence_nonnegative"),
        CheckConstraint("parsed_element_ordinal >= 0", name="ck_chunk_source_element_nonnegative"),
        CheckConstraint("start_offset >= 0", name="ck_chunk_source_start_nonnegative"),
        CheckConstraint("end_offset > start_offset", name="ck_chunk_source_end_after_start"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    chunk_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("knowledge_chunks.id", name="fk_chunk_source_chunk"), nullable=False
    )
    occurrence_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    parsed_element_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    start_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    end_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    heading_path_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    page_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    structural_location: Mapped[str | None] = mapped_column(String(512), nullable=True)


Index("ix_chunk_source_chunk", ChunkSourceRow.chunk_id)


class KnowledgeBaseAclRow(Base):
    __tablename__ = "knowledge_base_acl"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "knowledge_base_id",
            "principal_id",
            "role",
            "sensitivity",
            "permission_tag",
            name="uq_knowledge_base_acl_grant",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    knowledge_base_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("knowledge_bases.id", name="fk_knowledge_base_acl_base"),
        nullable=False,
    )
    principal_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False)
    permission_tag: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_knowledge_base_acl_scope", KnowledgeBaseAclRow.tenant_id, KnowledgeBaseAclRow.principal_id
)


class RagIndexRecordRow(Base):
    __tablename__ = "rag_index_records"
    __table_args__ = (
        UniqueConstraint("chunk_id", "index_version", name="uq_rag_index_record_chunk_version"),
        CheckConstraint(
            "status IN ('pending','processing','succeeded','failed','delete_pending','deleted')",
            name="ck_rag_index_record_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_version_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("document_versions.id", name="fk_rag_index_record_version"),
        nullable=False,
    )
    chunk_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("knowledge_chunks.id", name="fk_rag_index_record_chunk"),
        nullable=False,
    )
    bm25_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    embedding_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vector_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reranker_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    index_version: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index(
    "ix_rag_index_record_version_status",
    RagIndexRecordRow.document_version_id,
    RagIndexRecordRow.status,
)
