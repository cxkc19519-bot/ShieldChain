"""Deterministic, offline BM25 with fail-closed authorization filtering."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from shieldchain.rag.domain import (
    AccessScope,
    IndexRecord,
    IndexStatus,
    KnowledgeChunk,
)
from shieldchain.rag.indexing import IndexingContext
from shieldchain.rag.ports import Bm25IndexError, Bm25Match, TokenizerPort


@dataclass(frozen=True, slots=True)
class Bm25ScopeMetadata:
    """Server-owned document metadata unavailable on ``KnowledgeChunk`` itself."""

    tenant_id: UUID
    knowledge_base_id: UUID
    published: bool

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        if not isinstance(self.knowledge_base_id, UUID):
            raise TypeError("knowledge_base_id must be a UUID")
        if not isinstance(self.published, bool):
            raise TypeError("published must be a bool")


@dataclass(frozen=True, slots=True)
class _IndexedChunk:
    chunk: KnowledgeChunk
    terms: tuple[str, ...]
    scope: Bm25ScopeMetadata


class DeterministicBm25Index:
    """A rebuildable in-memory BM25 adapter using the project's tokenizer port.

    ``Bm25IndexPort.upsert`` receives no tenant or knowledge-base identifiers, so a
    server-owned resolver is required. Its result is copied into each index entry and
    never inferred from a search hit. Rebuild by replaying authoritative chunks.
    """

    def __init__(
        self,
        tokenizer: TokenizerPort,
        *,
        scope_resolver: Callable[[UUID], Bm25ScopeMetadata],
        k1: float = 1.5,
        b: float = 0.75,
        index_version: str = "v1",
        max_chunks: int = 100_000,
        max_terms_per_chunk: int = 16_000,
        max_query_characters: int = 4_096,
        max_query_terms: int = 512,
        max_limit: int = 100,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(tokenizer, "tokenize", None)):
            raise TypeError("tokenizer must implement TokenizerPort")
        if not callable(scope_resolver):
            raise TypeError("scope_resolver must be callable")
        if (
            not isinstance(k1, int | float)
            or isinstance(k1, bool)
            or not math.isfinite(k1)
            or k1 <= 0
        ):
            raise ValueError("k1 must be a finite number greater than zero")
        if (
            not isinstance(b, int | float)
            or isinstance(b, bool)
            or not math.isfinite(b)
            or not 0 <= b <= 1
        ):
            raise ValueError("b must be a finite number between zero and one")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if not isinstance(index_version, str) or not index_version.strip():
            raise ValueError("index_version must not be empty")
        for value, name in (
            (max_chunks, "max_chunks"),
            (max_terms_per_chunk, "max_terms_per_chunk"),
            (max_query_characters, "max_query_characters"),
            (max_query_terms, "max_query_terms"),
            (max_limit, "max_limit"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self._tokenizer = tokenizer
        self._scope_resolver = scope_resolver
        self._k1 = float(k1)
        self._b = float(b)
        self._index_version = index_version
        self._max_chunks = max_chunks
        self._max_terms_per_chunk = max_terms_per_chunk
        self._max_query_characters = max_query_characters
        self._max_query_terms = max_query_terms
        self._max_limit = max_limit
        self._clock = clock or (lambda: datetime.now(UTC))
        self._entries: dict[UUID, _IndexedChunk] = {}

    def upsert(
        self,
        chunks: Sequence[KnowledgeChunk],
        *,
        context: IndexingContext | None = None,
    ) -> tuple[IndexRecord, ...]:
        copied = tuple(chunks)
        self._validate_unique_chunks(copied)
        incoming_ids = {chunk.id for chunk in copied if isinstance(chunk, KnowledgeChunk)}
        projected_size = len(set(self._entries).difference(incoming_ids)) + len(incoming_ids)
        if projected_size > self._max_chunks:
            raise Bm25IndexError("BM25 index exceeds max_chunks")
        pending: list[_IndexedChunk] = []
        records: list[IndexRecord] = []
        for chunk in copied:
            if not isinstance(chunk, KnowledgeChunk):
                raise TypeError("chunks must contain KnowledgeChunk values")
            scope = self._resolve_scope(chunk.document_version_id)
            if context is not None:
                if chunk.document_version_id != context.document_version_id:
                    raise Bm25IndexError("chunk is outside the indexing context")
                expected_scope = Bm25ScopeMetadata(
                    context.tenant_id, context.knowledge_base_id, context.published
                )
                if scope != expected_scope:
                    raise Bm25IndexError("scope resolver disagrees with indexing context")
            terms = self._tokenize(chunk.text)
            if len(terms) > self._max_terms_per_chunk:
                raise Bm25IndexError("chunk exceeds max_terms_per_chunk")
            pending.append(_IndexedChunk(chunk, terms, scope))
            records.append(self._record_for(chunk))
        for entry in pending:
            self._entries[entry.chunk.id] = entry
        return tuple(records)

    def search(self, query: str, *, scope: AccessScope, limit: int) -> tuple[Bm25Match, ...]:
        if not isinstance(query, str):
            raise TypeError("query must be a string")
        if len(query) > self._max_query_characters:
            raise ValueError("query exceeds max_query_characters")
        if not isinstance(scope, AccessScope):
            raise TypeError("scope must be an AccessScope")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > self._max_limit
        ):
            raise ValueError(f"limit must be between 1 and {self._max_limit}")
        query_terms = self._tokenize(query)
        if len(query_terms) > self._max_query_terms:
            raise ValueError("query exceeds max_query_terms")
        if not query_terms:
            return ()

        authorized = tuple(
            entry
            for entry in self._entries.values()
            if entry.scope.published
            and scope.allows(
                entry.scope.tenant_id,
                entry.scope.knowledge_base_id,
                entry.chunk.sensitivity,
                entry.chunk.permission_tags,
            )
        )
        if not authorized:
            return ()

        average_length = sum(len(entry.terms) for entry in authorized) / len(authorized)
        document_frequencies = {
            term: sum(term in entry.terms for entry in authorized) for term in set(query_terms)
        }
        scores: list[Bm25Match] = []
        for entry in authorized:
            frequencies = Counter(entry.terms)
            score = 0.0
            for term, query_frequency in Counter(query_terms).items():
                term_frequency = frequencies.get(term, 0)
                if term_frequency == 0:
                    continue
                document_frequency = document_frequencies[term]
                inverse_document_frequency = math.log(
                    1 + (len(authorized) - document_frequency + 0.5) / (document_frequency + 0.5)
                )
                normalization = term_frequency + self._k1 * (
                    1 - self._b + self._b * len(entry.terms) / average_length
                )
                score += (
                    inverse_document_frequency
                    * term_frequency
                    * (self._k1 + 1)
                    / normalization
                    * query_frequency
                )
            if score > 0:
                scores.append(Bm25Match(entry.chunk.id, score))
        scores.sort(key=lambda match: (-match.score, str(match.chunk_id)))
        return tuple(scores[:limit])

    def delete_document_version(
        self,
        document_version_id: UUID | None = None,
        *,
        context: IndexingContext | None = None,
    ) -> None:
        if context is not None:
            if (
                document_version_id is not None
                and document_version_id != context.document_version_id
            ):
                raise Bm25IndexError("delete context does not match document version")
            document_version_id = context.document_version_id
        if not isinstance(document_version_id, UUID):
            raise TypeError("document_version_id must be a UUID")
        self._entries = {
            chunk_id: entry
            for chunk_id, entry in self._entries.items()
            if entry.chunk.document_version_id != document_version_id
        }

    def rebuild(self, chunks: Sequence[KnowledgeChunk]) -> tuple[IndexRecord, ...]:
        """Atomically replace the index from authoritative stored chunks."""
        replacement = type(self)(
            self._tokenizer,
            scope_resolver=self._scope_resolver,
            k1=self._k1,
            b=self._b,
            index_version=self._index_version,
            max_chunks=self._max_chunks,
            max_terms_per_chunk=self._max_terms_per_chunk,
            max_query_characters=self._max_query_characters,
            max_query_terms=self._max_query_terms,
            max_limit=self._max_limit,
            clock=self._clock,
        )
        records = replacement.upsert(chunks)
        self._entries = replacement._entries
        return records

    def _resolve_scope(self, document_version_id: UUID) -> Bm25ScopeMetadata:
        try:
            scope = self._scope_resolver(document_version_id)
        except Exception as error:
            raise Bm25IndexError("scope metadata is unavailable for document version") from error
        if not isinstance(scope, Bm25ScopeMetadata):
            raise Bm25IndexError("scope metadata resolver returned an invalid value")
        return scope

    def _tokenize(self, text: str) -> tuple[str, ...]:
        try:
            raw_terms = self._tokenizer.tokenize(text)
            terms = tuple(raw_terms)
        except Exception as error:
            raise Bm25IndexError("tokenization failed") from error
        if any(not isinstance(term, str) or not term for term in terms):
            raise Bm25IndexError("tokenizer returned an invalid term")
        return terms

    def _record_for(self, chunk: KnowledgeChunk) -> IndexRecord:
        return IndexRecord(
            id=uuid5(NAMESPACE_URL, f"shieldchain:{self._index_version}:{chunk.id}"),
            document_version_id=chunk.document_version_id,
            chunk_id=chunk.id,
            bm25_key=str(chunk.id),
            embedding_model=None,
            vector_id=None,
            reranker_model=None,
            index_version=self._index_version,
            status=IndexStatus.SUCCEEDED,
            error_category=None,
            updated_at=self._clock(),
        )

    @staticmethod
    def _validate_unique_chunks(chunks: tuple[KnowledgeChunk, ...]) -> None:
        identifiers = [chunk.id for chunk in chunks if isinstance(chunk, KnowledgeChunk)]
        if len(identifiers) != len(set(identifiers)):
            raise Bm25IndexError("duplicate chunk identifiers are not allowed in one upsert")
