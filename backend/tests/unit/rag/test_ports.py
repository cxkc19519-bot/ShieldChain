from datetime import UTC, datetime
from inspect import signature
from types import MappingProxyType
from typing import Protocol
from uuid import uuid4

import pytest

from shieldchain.rag.domain import AccessScope, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.ports import (
    Bm25IndexPort,
    Bm25Match,
    ChunkBoundary,
    ChunkBoundaryOptimizer,
    Clock,
    ContentStoreError,
    ContentStorePort,
    DocumentParserPort,
    EmbeddingPort,
    EmbeddingUnavailableError,
    KnowledgeRepository,
    ParsedContent,
    ParserUnavailableError,
    RerankedMatch,
    RerankerPort,
    StoredContent,
    VectorIndexPort,
    VectorIndexUnavailableError,
    VectorMatch,
    index_metadata_for_chunk,
)


def test_external_ports_are_runtime_independent_protocols() -> None:
    for port in (
        ContentStorePort,
        DocumentParserPort,
        ChunkBoundaryOptimizer,
        EmbeddingPort,
        VectorIndexPort,
        Bm25IndexPort,
        RerankerPort,
        Clock,
        KnowledgeRepository,
    ):
        assert issubclass(port, Protocol)


def test_repository_index_writes_require_a_server_tenant_boundary() -> None:
    assert "tenant_id" in signature(KnowledgeRepository.save_index_records).parameters


def test_external_errors_are_categorized_without_sdk_dependencies() -> None:
    for error in (
        ContentStoreError("storage failed"),
        ParserUnavailableError("parser unavailable"),
        EmbeddingUnavailableError("embedding unavailable"),
        VectorIndexUnavailableError("vector unavailable"),
    ):
        assert isinstance(error, Exception)


def test_port_types_accept_the_domain_boundary_values() -> None:
    scope = AccessScope(
        tenant_id=uuid4(),
        principal_id=uuid4(),
        roles={"reader"},
        allowed_sensitivities={SensitivityLevel.PUBLIC},
        permission_tags={"published"},
        knowledge_base_ids={uuid4()},
    )
    assert isinstance(scope.tenant_id, type(uuid4()))
    assert datetime.now(UTC).tzinfo is UTC


def make_chunk() -> KnowledgeChunk:
    return KnowledgeChunk(
        id=uuid4(),
        document_version_id=uuid4(),
        ordinal=0,
        heading_path=("Runbook",),
        page_number=None,
        structural_location="section:1",
        text="Contain the endpoint.",
        token_count=4,
        content_sha256="a" * 64,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"security"},
        chunking_mode="rule",
        is_degraded=False,
    )


def test_port_transfer_types_validate_content_and_copy_parser_metadata() -> None:
    metadata = {"page_count": 1}
    stored = StoredContent(
        storage_key="knowledge/uuid",
        content_sha256="b" * 64,
        size_bytes=1,
        media_type="text/plain",
    )
    parsed = ParsedContent(text="parsed content", media_type="text/plain", metadata=metadata)
    metadata["page_count"] = 2

    assert stored.size_bytes == 1
    assert isinstance(parsed.metadata, MappingProxyType)
    assert parsed.metadata == {"page_count": 1}
    with pytest.raises(TypeError):
        parsed.metadata["page_count"] = 3


@pytest.mark.parametrize(
    "factory",
    [
        lambda: StoredContent(" ", "a" * 64, 1, "text/plain"),
        lambda: StoredContent("key", "A" * 64, 1, "text/plain"),
        lambda: StoredContent("key", "a" * 64, 0, "text/plain"),
        lambda: ParsedContent(" ", "text/plain", {}),
        lambda: ChunkBoundary(2, 2),
        lambda: ChunkBoundary(-1, 1),
        lambda: VectorMatch("not-a-uuid", 0.5),  # type: ignore[arg-type]
        lambda: VectorMatch(uuid4(), float("inf")),
        lambda: VectorMatch(uuid4(), 1.1),
        lambda: Bm25Match(uuid4(), -0.01),
        lambda: Bm25Match(uuid4(), float("nan")),
        lambda: RerankedMatch(uuid4(), -0.01),
        lambda: RerankedMatch(uuid4(), 1.1),
    ],
)
def test_port_transfer_types_reject_invalid_boundaries_and_scores(factory: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        factory()  # type: ignore[operator]


def test_index_metadata_is_immutable_and_validates_security_filters() -> None:
    chunk = make_chunk()
    tenant_id = uuid4()
    knowledge_base_id = uuid4()
    document_id = uuid4()
    metadata = index_metadata_for_chunk(
        chunk,
        tenant_id=tenant_id,
        knowledge_base_id=knowledge_base_id,
        document_id=document_id,
        published=True,
    )

    assert isinstance(metadata, MappingProxyType)
    assert metadata["tenant_id"] == tenant_id
    with pytest.raises(TypeError):
        metadata["published"] = False
    with pytest.raises(TypeError):
        index_metadata_for_chunk(
            chunk,
            tenant_id="not-a-uuid",  # type: ignore[arg-type]
            knowledge_base_id=knowledge_base_id,
            document_id=document_id,
            published=True,
        )
    with pytest.raises(TypeError):
        index_metadata_for_chunk(
            chunk,
            tenant_id=tenant_id,
            knowledge_base_id=knowledge_base_id,
            document_id=document_id,
            published=1,  # type: ignore[arg-type]
        )
