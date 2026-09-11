from datetime import UTC, datetime

from sqlalchemy import create_engine, inspect

from shieldchain.db.base import Base
from shieldchain.rag.persistence import (
    ChunkSourceRow,
    DocumentVersionRow,
    KnowledgeBaseAclRow,
    KnowledgeBaseRow,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
    RagIndexRecordRow,
)


def test_rag_control_plane_declares_relationships_constraints_and_indexes() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)

    assert {
        "knowledge_bases",
        "knowledge_documents",
        "document_versions",
        "knowledge_chunks",
        "chunk_sources",
        "knowledge_base_acl",
        "rag_index_records",
    }.issubset(inspector.get_table_names())
    assert any(
        item["name"] == "uq_knowledge_base_tenant_name"
        for item in inspector.get_unique_constraints("knowledge_bases")
    )
    assert any(
        item["name"] == "uq_document_version_number"
        for item in inspector.get_unique_constraints("document_versions")
    )
    assert any(
        item["name"] == "uq_chunk_ordinal"
        for item in inspector.get_unique_constraints("knowledge_chunks")
    )
    assert any(
        item["name"] == "ix_document_tenant_status"
        for item in inspector.get_indexes("knowledge_documents")
    )
    assert {
        foreign_key["referred_table"]
        for foreign_key in inspector.get_foreign_keys("knowledge_chunks")
    } == {"document_versions"}
    assert any(
        item["name"] == "uq_chunk_source_occurrence"
        for item in inspector.get_unique_constraints("chunk_sources")
    )
    version_columns = {item["name"] for item in inspector.get_columns("document_versions")}
    assert {
        "chunking_failure_category",
        "chunking_retry_key",
        "chunking_requested_model",
    } <= version_columns
    assert any(
        item["name"] == "ck_document_version_retry_key_length"
        for item in inspector.get_check_constraints("document_versions")
    )
    retry_constraint = next(
        item
        for item in inspector.get_check_constraints("document_versions")
        if item["name"] == "ck_document_version_retry_key_length"
    )
    assert "lower(chunking_retry_key) = chunking_retry_key" in retry_constraint["sqltext"]
    assert any(
        item["name"] == "ck_document_version_chunking_failure_category"
        for item in inspector.get_check_constraints("document_versions")
    )


def test_persistence_rows_keep_utc_datetime_columns_and_required_foreign_keys() -> None:
    assert KnowledgeBaseRow.created_at.type.timezone is True
    assert KnowledgeDocumentRow.updated_at.type.timezone is True
    assert DocumentVersionRow.published_at.type.timezone is True
    assert RagIndexRecordRow.updated_at.type.timezone is True
    assert KnowledgeChunkRow.document_version_id.nullable is False
    assert ChunkSourceRow.chunk_id.nullable is False
    assert KnowledgeBaseAclRow.knowledge_base_id.nullable is False


def test_persistence_models_accept_explicit_utc_timestamp() -> None:
    now = datetime(2026, 7, 18, tzinfo=UTC)
    row = KnowledgeBaseRow(
        id="7f7fa72e-b703-4a54-aa00-fd71e86c5610",
        tenant_id="ed018848-482d-46fc-afb7-b5d36a1cb3dd",
        name="Security",
        status="draft",
        default_sensitivity="internal",
        version_policy="manual",
        created_at=now,
        updated_at=now,
    )
    assert row.created_at == now
