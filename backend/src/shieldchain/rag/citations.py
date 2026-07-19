"""Fail-closed citation assembly from authoritative source chunks."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

from shieldchain.rag.domain import AccessScope, Citation, KnowledgeChunk
from shieldchain.rag.reranking import RerankingResult
from shieldchain.rag.retrieval import FusedRetrievalMatch


class CitationAssemblyError(Exception):
    """A safe citation error that must not be repaired with invented metadata."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TrustedCitationSource:
    """Server-owned provenance for one current, source-addressable chunk."""

    tenant_id: UUID
    knowledge_base_id: UUID
    document_id: UUID
    chunk: KnowledgeChunk
    published: bool
    updated_at: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "knowledge_base_id", "document_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if not isinstance(self.chunk, KnowledgeChunk):
            raise TypeError("chunk must be a KnowledgeChunk")
        if not isinstance(self.published, bool):
            raise TypeError("published must be a bool")
        if (
            not isinstance(self.updated_at, datetime)
            or self.updated_at.tzinfo is None
            or self.updated_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("updated_at must be an aware UTC datetime")


class TrustedCitationRepository(Protocol):
    """Load citation metadata within an already established access scope."""

    def get_trusted_citation_sources(
        self, chunk_ids: Sequence[UUID], *, scope: AccessScope
    ) -> Sequence[TrustedCitationSource]: ...


class CitationAssembler:
    """Join retrieval scores to authoritative provenance without trusting hit text."""

    def __init__(
        self,
        *,
        repository: TrustedCitationRepository,
        max_citations: int = 50,
        max_excerpt_characters: int = 1_200,
    ) -> None:
        if not callable(getattr(repository, "get_trusted_citation_sources", None)):
            raise TypeError("repository does not implement the citation source port")
        if not isinstance(max_citations, int) or not 1 <= max_citations <= 100:
            raise ValueError("max_citations must be between 1 and 100")
        if not isinstance(max_excerpt_characters, int) or not 64 <= max_excerpt_characters <= 4_096:
            raise ValueError("max_excerpt_characters must be between 64 and 4096")
        self._repository = repository
        self._max_citations = max_citations
        self._max_excerpt_characters = max_excerpt_characters

    def assemble(
        self,
        matches: Sequence[FusedRetrievalMatch],
        *,
        scope: AccessScope,
        reranker_scores: Mapping[UUID, float] | None = None,
    ) -> tuple[Citation, ...]:
        if not isinstance(scope, AccessScope):
            raise TypeError("scope must be an AccessScope")
        if isinstance(matches, (str, bytes)) or not isinstance(matches, Sequence):
            raise TypeError("matches must be a sequence")
        if len(matches) > self._max_citations:
            raise ValueError(f"matches must not exceed {self._max_citations}")
        if not all(isinstance(match, FusedRetrievalMatch) for match in matches):
            raise TypeError("matches must contain FusedRetrievalMatch values")
        scores = self._validated_reranker_scores(reranker_scores or {})
        requested_ids = tuple(match.chunk.id for match in matches)
        if len(set(requested_ids)) != len(requested_ids):
            raise CitationAssemblyError("duplicate_hit", "Retrieval returned duplicate chunks")
        try:
            sources = self._repository.get_trusted_citation_sources(requested_ids, scope=scope)
        except Exception as error:
            raise CitationAssemblyError(
                "provenance_unavailable", "Trusted citation provenance is unavailable"
            ) from error
        by_id = self._validated_sources(sources, requested_ids)
        citations: list[Citation] = []
        for match in matches:
            source = by_id.get(match.chunk.id)
            if source is None:
                continue
            if not source.published or not scope.allows(
                source.tenant_id,
                source.knowledge_base_id,
                source.chunk.sensitivity,
                source.chunk.permission_tags,
            ):
                continue
            self._verify_chunk(match.chunk, source.chunk)
            excerpt = source.chunk.text[: self._max_excerpt_characters]
            citations.append(
                Citation(
                    knowledge_base_id=source.knowledge_base_id,
                    document_id=source.document_id,
                    document_version_id=source.chunk.document_version_id,
                    chunk_id=source.chunk.id,
                    heading_path=source.chunk.heading_path,
                    page_number=source.chunk.page_number,
                    structural_location=source.chunk.structural_location,
                    excerpt=excerpt,
                    bm25_score=match.bm25_score,
                    vector_score=match.vector_score,
                    fusion_score=match.fusion_score,
                    reranker_score=scores.get(source.chunk.id),
                    updated_at=source.updated_at,
                    integrity_sha256=source.chunk.content_sha256,
                )
            )
        return tuple(citations)

    def assemble_reranked(
        self, result: RerankingResult, *, scope: AccessScope
    ) -> tuple[Citation, ...]:
        """Assemble a reranked result while preserving real scores and degradation gaps."""
        if not isinstance(result, RerankingResult):
            raise TypeError("result must be a RerankingResult")
        return self.assemble(
            tuple(match.fused for match in result.matches),
            scope=scope,
            reranker_scores={
                match.chunk.id: match.reranker_score
                for match in result.matches
                if match.reranker_score is not None
            },
        )

    @staticmethod
    def _validated_reranker_scores(scores: Mapping[UUID, float]) -> dict[UUID, float]:
        if not isinstance(scores, Mapping):
            raise TypeError("reranker_scores must be a mapping")
        copied: dict[UUID, float] = {}
        for chunk_id, score in scores.items():
            if not isinstance(chunk_id, UUID):
                raise TypeError("reranker score keys must be UUIDs")
            if (
                not isinstance(score, int | float)
                or isinstance(score, bool)
                or not math.isfinite(score)
                or not 0 <= score <= 1
            ):
                raise ValueError("reranker scores must be between zero and one")
            copied[chunk_id] = float(score)
        return copied

    @staticmethod
    def _validated_sources(
        sources: Sequence[TrustedCitationSource], requested_ids: Sequence[UUID]
    ) -> dict[UUID, TrustedCitationSource]:
        if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence):
            raise CitationAssemblyError(
                "provenance_response", "Trusted citation provenance is invalid"
            )
        requested = set(requested_ids)
        by_id: dict[UUID, TrustedCitationSource] = {}
        for source in sources:
            if not isinstance(source, TrustedCitationSource):
                raise CitationAssemblyError(
                    "provenance_response", "Trusted citation provenance is invalid"
                )
            chunk_id = source.chunk.id
            if chunk_id not in requested or chunk_id in by_id:
                raise CitationAssemblyError(
                    "provenance_response", "Trusted citation provenance is invalid"
                )
            by_id[chunk_id] = source
        return by_id

    @staticmethod
    def _verify_chunk(retrieved: KnowledgeChunk, trusted: KnowledgeChunk) -> None:
        digest = hashlib.sha256(trusted.text.encode("utf-8")).hexdigest()
        if digest != trusted.content_sha256:
            raise CitationAssemblyError(
                "integrity_mismatch", "The trusted source chunk failed integrity verification"
            )
        if retrieved != trusted:
            raise CitationAssemblyError(
                "retrieval_mismatch", "Retrieved content differs from trusted source content"
            )
