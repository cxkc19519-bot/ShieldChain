"""Bounded hybrid retrieval with deterministic RRF and fail-closed ACL checks."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from shieldchain.rag.domain import (
    AccessScope,
    KnowledgeChunk,
    RetrievalDegradation,
    RetrievalDegradationKind,
)
from shieldchain.rag.ports import (
    Bm25IndexError,
    Bm25IndexPort,
    Bm25Match,
    EmbeddingAuthenticationError,
    EmbeddingError,
    EmbeddingPort,
    EmbeddingRateLimitError,
    EmbeddingResponseError,
    VectorIndexError,
    VectorIndexPort,
    VectorIndexResponseError,
    VectorMatch,
)
from shieldchain.rag.rewrite import RewriteResult

RRF_K = 60


class HybridRetrievalError(Exception):
    """A safe, classified retrieval failure suitable for an API error boundary."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TrustedChunkMetadata:
    """Server-owned metadata used for the post-retrieval authorization check."""

    chunk: KnowledgeChunk
    tenant_id: UUID
    knowledge_base_id: UUID
    published: bool

    def __post_init__(self) -> None:
        if not isinstance(self.chunk, KnowledgeChunk):
            raise TypeError("chunk must be a KnowledgeChunk")
        if not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        if not isinstance(self.knowledge_base_id, UUID):
            raise TypeError("knowledge_base_id must be a UUID")
        if not isinstance(self.published, bool):
            raise TypeError("published must be a bool")


class TrustedChunkMetadataRepository(Protocol):
    """Fetch authoritative current-publication and ACL metadata by chunk ID."""

    def get_trusted_chunks(
        self, chunk_ids: Sequence[UUID], *, scope: AccessScope
    ) -> Sequence[TrustedChunkMetadata]: ...


@dataclass(frozen=True, slots=True)
class FusedRetrievalMatch:
    chunk: KnowledgeChunk
    fusion_score: float
    bm25_score: float | None
    vector_score: float | None
    bm25_ranks: tuple[int, ...]
    vector_ranks: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.chunk, KnowledgeChunk):
            raise TypeError("chunk must be a KnowledgeChunk")
        if not math.isfinite(self.fusion_score) or self.fusion_score <= 0:
            raise ValueError("fusion_score must be finite and positive")
        if self.bm25_score is not None and (
            not math.isfinite(self.bm25_score) or self.bm25_score < 0
        ):
            raise ValueError("bm25_score must be finite and non-negative")
        if self.vector_score is not None and (
            not math.isfinite(self.vector_score) or not 0 <= self.vector_score <= 1
        ):
            raise ValueError("vector_score must be between zero and one")


@dataclass(frozen=True, slots=True)
class HybridRetrievalResult:
    original_query: str
    executed_queries: tuple[str, ...]
    matches: tuple[FusedRetrievalMatch, ...]
    degradations: tuple[RetrievalDegradation, ...]


@dataclass(slots=True)
class _Accumulator:
    fusion_score: float = 0.0
    bm25_score: float | None = None
    vector_score: float | None = None
    bm25_ranks: tuple[int, ...] = ()
    vector_ranks: tuple[int, ...] = ()


class HybridRetrievalService:
    """Run original and rewritten queries through BM25 and vector retrieval."""

    def __init__(
        self,
        *,
        bm25: Bm25IndexPort,
        embedding: EmbeddingPort,
        vector_index: VectorIndexPort,
        metadata_repository: TrustedChunkMetadataRepository,
        embedding_model: str = "bge-m3",
        per_source_limit: int = 50,
        max_results: int = 50,
        max_queries: int = 6,
        max_query_characters: int = 4_096,
        max_candidates: int = 500,
    ) -> None:
        for value, name, hard_max in (
            (per_source_limit, "per_source_limit", 100),
            (max_results, "max_results", 100),
            (max_queries, "max_queries", 10),
            (max_query_characters, "max_query_characters", 8_192),
            (max_candidates, "max_candidates", 1_000),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
                or value > hard_max
            ):
                raise ValueError(f"{name} must be between 1 and {hard_max}")
        if not isinstance(embedding_model, str) or not embedding_model.strip():
            raise ValueError("embedding_model must not be empty")
        if max_results > max_candidates:
            raise ValueError("max_results must not exceed max_candidates")
        for adapter, method, name in (
            (bm25, "search", "bm25"),
            (embedding, "embed", "embedding"),
            (vector_index, "search", "vector_index"),
            (metadata_repository, "get_trusted_chunks", "metadata_repository"),
        ):
            if not callable(getattr(adapter, method, None)):
                raise TypeError(f"{name} does not implement its required port")
        self._bm25 = bm25
        self._embedding = embedding
        self._vector_index = vector_index
        self._metadata_repository = metadata_repository
        self._embedding_model = embedding_model
        self._per_source_limit = per_source_limit
        self._max_results = max_results
        self._max_queries = max_queries
        self._max_query_characters = max_query_characters
        self._max_candidates = max_candidates

    def retrieve(
        self,
        original_query: str,
        rewritten_queries: Sequence[str],
        *,
        scope: AccessScope,
        limit: int | None = None,
    ) -> HybridRetrievalResult:
        if not isinstance(scope, AccessScope):
            raise TypeError("scope must be an AccessScope")
        result_limit = self._max_results if limit is None else limit
        if (
            not isinstance(result_limit, int)
            or isinstance(result_limit, bool)
            or result_limit < 1
            or result_limit > self._max_results
        ):
            raise ValueError(f"limit must be between 1 and {self._max_results}")
        queries = self._validated_queries(original_query, rewritten_queries)
        accumulators: dict[UUID, _Accumulator] = {}

        for query in queries:
            try:
                matches = self._bm25.search(
                    query, scope=scope, limit=self._per_source_limit
                )
            except Bm25IndexError as error:
                raise HybridRetrievalError(
                    "bm25_unavailable", "BM25 retrieval is unavailable"
                ) from error
            except ValueError as error:
                raise HybridRetrievalError(
                    "bm25_query_rejected", "BM25 rejected the bounded query"
                ) from error
            matches = self._validated_bm25_matches(matches)
            self._add_ranked(accumulators, matches, source="bm25")

        degradations: tuple[RetrievalDegradation, ...] = ()
        try:
            vector_lists = self._vector_lists(queries, scope)
        except (
            EmbeddingError,
            VectorIndexError,
            _EmbeddingValidationError,
            _VectorValidationError,
        ) as error:
            category = _vector_error_category(error)
            degradations = (
                RetrievalDegradation(
                    kind=RetrievalDegradationKind.VECTOR_DEGRADED,
                    error_category=category,
                    message="Vector retrieval is unavailable; BM25 results only.",
                ),
            )
        else:
            for matches in vector_lists:
                self._add_ranked(accumulators, matches, source="vector")

        ranked_ids = sorted(
            accumulators,
            key=lambda chunk_id: (-accumulators[chunk_id].fusion_score, str(chunk_id)),
        )[: self._max_candidates]
        trusted = self._trusted_by_id(ranked_ids, scope)
        results: list[FusedRetrievalMatch] = []
        for chunk_id in ranked_ids:
            metadata = trusted.get(chunk_id)
            if metadata is None or not self._is_authorized(metadata, scope):
                continue
            item = accumulators[chunk_id]
            results.append(
                FusedRetrievalMatch(
                    chunk=metadata.chunk,
                    fusion_score=item.fusion_score,
                    bm25_score=item.bm25_score,
                    vector_score=item.vector_score,
                    bm25_ranks=item.bm25_ranks,
                    vector_ranks=item.vector_ranks,
                )
            )
            if len(results) == result_limit:
                break
        return HybridRetrievalResult(
            original_query=original_query,
            executed_queries=queries,
            matches=tuple(results),
            degradations=degradations,
        )

    def retrieve_rewrite(
        self,
        rewrite: RewriteResult,
        *,
        scope: AccessScope,
        limit: int | None = None,
    ) -> HybridRetrievalResult:
        """Execute a validated rewrite and carry its explicit degradation forward."""
        if not isinstance(rewrite, RewriteResult):
            raise TypeError("rewrite must be a RewriteResult")
        result = self.retrieve(
            rewrite.original_query,
            rewrite.queries[1:],
            scope=scope,
            limit=limit,
        )
        if not rewrite.rewrite_degraded:
            return result
        degradation = RetrievalDegradation(
            kind=RetrievalDegradationKind.REWRITE_DEGRADED,
            error_category=rewrite.failure_category or "rewrite_error",
            message="Query rewriting is unavailable; the original query was used.",
        )
        return HybridRetrievalResult(
            original_query=result.original_query,
            executed_queries=result.executed_queries,
            matches=result.matches,
            degradations=(degradation, *result.degradations),
        )

    def _validated_queries(
        self, original_query: str, rewritten_queries: Sequence[str]
    ) -> tuple[str, ...]:
        if not isinstance(original_query, str) or not original_query.strip():
            raise ValueError("original_query must not be empty")
        if isinstance(rewritten_queries, (str, bytes)) or not isinstance(
            rewritten_queries, Sequence
        ):
            raise TypeError("rewritten_queries must be a sequence of strings")
        values = (original_query, *rewritten_queries)
        if len(values) > self._max_queries:
            raise ValueError(f"queries must not exceed {self._max_queries}")
        unique: list[str] = []
        seen: set[str] = set()
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("queries must contain non-empty strings")
            normalized = value.strip()
            if len(normalized) > self._max_query_characters:
                raise ValueError("query exceeds max_query_characters")
            if normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return tuple(unique)

    def _vector_lists(
        self, queries: tuple[str, ...], scope: AccessScope
    ) -> tuple[Sequence[VectorMatch], ...]:
        try:
            vectors = self._embedding.embed(queries, model=self._embedding_model)
        except ValueError as error:
            raise _EmbeddingValidationError from error
        if (
            isinstance(vectors, (str, bytes))
            or not isinstance(vectors, Sequence)
            or len(vectors) != len(queries)
        ):
            raise _EmbeddingValidationError
        results: list[Sequence[VectorMatch]] = []
        for vector in vectors:
            if isinstance(vector, (str, bytes)) or not isinstance(vector, Sequence):
                raise _EmbeddingValidationError
            if not vector or any(
                not isinstance(value, int | float)
                or isinstance(value, bool)
                or not math.isfinite(value)
                for value in vector
            ):
                raise _EmbeddingValidationError
            try:
                matches = self._vector_index.search(
                    vector, scope=scope, limit=self._per_source_limit
                )
            except ValueError as error:
                raise _VectorValidationError from error
            results.append(self._validated_vector_matches(matches))
        return tuple(results)

    def _validated_bm25_matches(
        self, matches: Sequence[Bm25Match]
    ) -> tuple[Bm25Match, ...]:
        if (
            isinstance(matches, (str, bytes))
            or not isinstance(matches, Sequence)
            or len(matches) > self._per_source_limit
            or any(not isinstance(match, Bm25Match) for match in matches)
        ):
            raise HybridRetrievalError(
                "bm25_response", "BM25 retrieval returned an invalid response"
            )
        return tuple(matches)

    def _validated_vector_matches(
        self, matches: Sequence[VectorMatch]
    ) -> tuple[VectorMatch, ...]:
        if (
            isinstance(matches, (str, bytes))
            or not isinstance(matches, Sequence)
            or len(matches) > self._per_source_limit
            or any(not isinstance(match, VectorMatch) for match in matches)
        ):
            raise _VectorValidationError
        return tuple(matches)

    @staticmethod
    def _add_ranked(
        accumulators: dict[UUID, _Accumulator],
        matches: Sequence[Bm25Match] | Sequence[VectorMatch],
        *,
        source: str,
    ) -> None:
        seen: set[UUID] = set()
        for rank, match in enumerate(matches, start=1):
            if match.chunk_id in seen:
                continue
            seen.add(match.chunk_id)
            item = accumulators.setdefault(match.chunk_id, _Accumulator())
            item.fusion_score += 1.0 / (RRF_K + rank)
            if source == "bm25":
                item.bm25_score = max(item.bm25_score or 0.0, match.score)
                item.bm25_ranks += (rank,)
            else:
                item.vector_score = max(item.vector_score or 0.0, match.score)
                item.vector_ranks += (rank,)

    def _trusted_by_id(
        self, chunk_ids: Sequence[UUID], scope: AccessScope
    ) -> dict[UUID, TrustedChunkMetadata]:
        if not chunk_ids:
            return {}
        try:
            rows = self._metadata_repository.get_trusted_chunks(chunk_ids, scope=scope)
        except Exception as error:
            raise HybridRetrievalError(
                "metadata_unavailable", "Trusted chunk metadata is unavailable"
            ) from error
        if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
            raise HybridRetrievalError(
                "metadata_response", "Trusted chunk metadata response is invalid"
            )
        requested = set(chunk_ids)
        by_id: dict[UUID, TrustedChunkMetadata] = {}
        for row in rows:
            if not isinstance(row, TrustedChunkMetadata):
                raise HybridRetrievalError(
                    "metadata_response", "Trusted chunk metadata response is invalid"
                )
            chunk_id = row.chunk.id
            if chunk_id not in requested or chunk_id in by_id:
                raise HybridRetrievalError(
                    "metadata_response", "Trusted chunk metadata response is invalid"
                )
            by_id[chunk_id] = row
        return by_id

    @staticmethod
    def _is_authorized(metadata: TrustedChunkMetadata, scope: AccessScope) -> bool:
        return metadata.published and scope.allows(
            metadata.tenant_id,
            metadata.knowledge_base_id,
            metadata.chunk.sensitivity,
            metadata.chunk.permission_tags,
        )


class _EmbeddingValidationError(Exception):
    pass


class _VectorValidationError(Exception):
    pass


def _vector_error_category(error: Exception) -> str:
    if isinstance(error, EmbeddingAuthenticationError):
        return "embedding_authentication"
    if isinstance(error, EmbeddingRateLimitError):
        return "embedding_rate_limit"
    if isinstance(error, (EmbeddingResponseError, _EmbeddingValidationError)):
        return "embedding_response"
    if isinstance(error, (VectorIndexResponseError, _VectorValidationError)):
        return "vector_response"
    if isinstance(error, EmbeddingError):
        return "embedding_unavailable"
    return "vector_unavailable"
