from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.citations import (
    CitationAssembler,
    CitationAssemblyError,
    TrustedCitationSource,
)
from shieldchain.rag.domain import AccessScope, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.reranking import RerankedRetrievalMatch, RerankingResult
from shieldchain.rag.retrieval import FusedRetrievalMatch

NOW = datetime(2026, 7, 19, 8, tzinfo=UTC)
TENANT_ID = UUID("10000000-0000-0000-0000-000000000001")
KB_ID = UUID("20000000-0000-0000-0000-000000000001")
DOCUMENT_ID = UUID("30000000-0000-0000-0000-000000000001")
VERSION_ID = UUID("40000000-0000-0000-0000-000000000001")


def _chunk(text: str = "Isolate the affected host from the network.") -> KnowledgeChunk:
    return KnowledgeChunk(
        id=UUID("50000000-0000-0000-0000-000000000001"),
        document_version_id=VERSION_ID,
        ordinal=0,
        heading_path=("Incident Response", "Containment"),
        page_number=12,
        structural_location="section:2.1",
        text=text,
        token_count=9,
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=("soc",),
        chunking_mode="rule",
        is_degraded=False,
    )


def _scope() -> AccessScope:
    return AccessScope(
        tenant_id=TENANT_ID,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("soc",),
        knowledge_base_ids=(KB_ID,),
    )


class FakeRepository:
    def __init__(self, sources: tuple[TrustedCitationSource, ...]) -> None:
        self.sources = sources
        self.received_scope: AccessScope | None = None

    def get_trusted_citation_sources(
        self, chunk_ids: tuple[UUID, ...], *, scope: AccessScope
    ) -> tuple[TrustedCitationSource, ...]:
        self.received_scope = scope
        return tuple(source for source in self.sources if source.chunk.id in chunk_ids)


def _source(
    chunk: KnowledgeChunk | None = None, *, published: bool = True
) -> TrustedCitationSource:
    return TrustedCitationSource(
        tenant_id=TENANT_ID,
        knowledge_base_id=KB_ID,
        document_id=DOCUMENT_ID,
        chunk=chunk or _chunk(),
        published=published,
        updated_at=NOW,
    )


def _match(chunk: KnowledgeChunk | None = None) -> FusedRetrievalMatch:
    return FusedRetrievalMatch(
        chunk=chunk or _chunk(),
        fusion_score=0.04,
        bm25_score=0.72,
        vector_score=0.81,
        bm25_ranks=(1,),
        vector_ranks=(2,),
    )


def test_assembles_complete_citation_from_authoritative_original_chunk() -> None:
    chunk = _chunk()
    repository = FakeRepository((_source(chunk),))

    citations = CitationAssembler(repository=repository).assemble(
        (_match(chunk),), scope=_scope(), reranker_scores={chunk.id: 0.91}
    )

    citation = citations[0]
    assert citation.knowledge_base_id == KB_ID
    assert citation.document_id == DOCUMENT_ID
    assert citation.document_version_id == VERSION_ID
    assert citation.chunk_id == chunk.id
    assert citation.heading_path == ("Incident Response", "Containment")
    assert citation.page_number == 12
    assert citation.structural_location == "section:2.1"
    assert citation.excerpt == chunk.text
    assert citation.bm25_score == 0.72
    assert citation.vector_score == 0.81
    assert citation.fusion_score == 0.04
    assert citation.reranker_score == 0.91
    assert citation.updated_at == NOW
    assert citation.integrity_sha256 == chunk.content_sha256
    assert repository.received_scope is not None


def test_excerpt_is_a_bounded_verbatim_prefix_of_trusted_text() -> None:
    chunk = _chunk("可信原文" * 100)
    citation = CitationAssembler(
        repository=FakeRepository((_source(chunk),)), max_excerpt_characters=64
    ).assemble((_match(chunk),), scope=_scope())[0]

    assert citation.excerpt == chunk.text[:64]
    assert citation.excerpt in chunk.text


def test_reranked_result_preserves_real_reranker_score() -> None:
    chunk = _chunk()
    result = RerankingResult(
        original_query="containment",
        matches=(RerankedRetrievalMatch(_match(chunk), 0.93),),
        degradations=(),
    )

    citation = CitationAssembler(repository=FakeRepository((_source(chunk),))).assemble_reranked(
        result, scope=_scope()
    )[0]

    assert citation.reranker_score == 0.93


def test_unpublished_or_unauthorized_sources_are_not_cited() -> None:
    chunk = _chunk()
    unpublished = CitationAssembler(repository=FakeRepository((_source(chunk, published=False),)))
    assert unpublished.assemble((_match(chunk),), scope=_scope()) == ()

    wrong_tenant = replace(_source(chunk), tenant_id=uuid4())
    unauthorized = CitationAssembler(repository=FakeRepository((wrong_tenant,)))
    assert unauthorized.assemble((_match(chunk),), scope=_scope()) == ()


@pytest.mark.parametrize("tampering", ["trusted_hash", "retrieved_text"])
def test_integrity_or_retrieval_mismatch_fails_closed(tampering: str) -> None:
    chunk = _chunk()
    source_chunk = replace(chunk, content_sha256="0" * 64) if tampering == "trusted_hash" else chunk
    retrieved = replace(chunk, text="tampered result") if tampering == "retrieved_text" else chunk
    assembler = CitationAssembler(repository=FakeRepository((_source(source_chunk),)))

    with pytest.raises(CitationAssemblyError) as caught:
        assembler.assemble((_match(retrieved),), scope=_scope())

    assert caught.value.category in {"integrity_mismatch", "retrieval_mismatch"}


def test_duplicate_or_malformed_provider_provenance_is_rejected() -> None:
    chunk = _chunk()
    assembler = CitationAssembler(repository=FakeRepository((_source(chunk), _source(chunk))))

    with pytest.raises(CitationAssemblyError, match="invalid"):
        assembler.assemble((_match(chunk),), scope=_scope())
