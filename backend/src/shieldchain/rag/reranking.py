"""Bounded cross-encoder reranking with explicit, score-free degradation."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol
from uuid import UUID

import httpx

from shieldchain.rag.domain import (
    KnowledgeChunk,
    RetrievalDegradation,
    RetrievalDegradationKind,
)
from shieldchain.rag.ports import (
    RerankedMatch,
    RerankerAuthenticationError,
    RerankerError,
    RerankerPort,
    RerankerRateLimitError,
    RerankerResponseError,
    RerankerUnavailableError,
)
from shieldchain.rag.retrieval import FusedRetrievalMatch, HybridRetrievalResult


class RerankerHttpTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object],
        timeout: float,
    ) -> httpx.Response: ...


@dataclass(frozen=True, slots=True)
class RerankerMetricsSnapshot:
    calls: int
    documents: int
    input_characters: int
    input_tokens: int
    estimated_cost: float
    failures: int


class RerankerMetrics:
    """Thread-safe counters without prompts, document text, or credentials."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._values = [0, 0, 0, 0, 0.0, 0]

    def record(
        self,
        *,
        documents: int,
        characters: int,
        tokens: int,
        cost: float,
        failed: bool,
    ) -> None:
        with self._lock:
            self._values[0] += 1
            self._values[1] += documents
            self._values[2] += characters
            self._values[3] += tokens
            self._values[4] += cost
            self._values[5] += int(failed)

    def snapshot(self) -> RerankerMetricsSnapshot:
        with self._lock:
            return RerankerMetricsSnapshot(*self._values)


class BgeRerankerV2M3Http:
    """Provider-neutral HTTP adapter for BGE-Reranker-v2-m3 compatible APIs."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        transport: RerankerHttpTransport | None = None,
        timeout_seconds: float = 20.0,
        max_batch_size: int = 64,
        max_query_characters: int = 4_096,
        max_text_characters: int = 16_000,
        max_total_characters: int = 128_000,
        max_response_bytes: int = 1_000_000,
        max_billable_tokens: int = 100_000,
        cost_per_million_tokens: float = 0.0,
        max_request_cost: float = 1.0,
        metrics: RerankerMetrics | None = None,
    ) -> None:
        if not isinstance(endpoint, str) or not endpoint.startswith(("https://", "http://")):
            raise ValueError("endpoint must be an HTTP(S) URL")
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must not be empty")
        for value, name, hard_max in (
            (max_batch_size, "max_batch_size", 100),
            (max_query_characters, "max_query_characters", 8_192),
            (max_text_characters, "max_text_characters", 32_000),
            (max_total_characters, "max_total_characters", 256_000),
            (max_response_bytes, "max_response_bytes", 8_000_000),
            (max_billable_tokens, "max_billable_tokens", 1_000_000),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
                or value > hard_max
            ):
                raise ValueError(f"{name} must be between 1 and {hard_max}")
        for value, name in (
            (timeout_seconds, "timeout_seconds"),
            (cost_per_million_tokens, "cost_per_million_tokens"),
            (max_request_cost, "max_request_cost"),
        ):
            if not isinstance(value, int | float) or isinstance(value, bool):
                raise ValueError(f"{name} must be finite and non-negative")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if timeout_seconds == 0:
            raise ValueError("timeout_seconds must be positive")
        if max_total_characters < max_query_characters:
            raise ValueError("max_total_characters must cover max_query_characters")
        self._endpoint = endpoint
        self._api_key = api_key
        self._transport = transport or httpx.Client()
        self._timeout = float(timeout_seconds)
        self._max_batch = max_batch_size
        self._max_query_chars = max_query_characters
        self._max_text_chars = max_text_characters
        self._max_total_chars = max_total_characters
        self._max_response_bytes = max_response_bytes
        self._max_tokens = max_billable_tokens
        self._cost_per_million = float(cost_per_million_tokens)
        self._max_cost = float(max_request_cost)
        self.metrics = metrics or RerankerMetrics()

    def rerank(
        self, query: str, chunks: Sequence[KnowledgeChunk], *, model: str
    ) -> tuple[RerankedMatch, ...]:
        query, copied, characters = self._validated_request(query, chunks, model)
        try:
            response = self._transport.post(
                self._endpoint,
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": model,
                    "query": query,
                    "documents": [chunk.text for chunk in copied],
                    "return_documents": False,
                },
                timeout=self._timeout,
            )
            self._raise_for_status(response)
            if len(response.content) > self._max_response_bytes:
                raise RerankerResponseError("reranker response exceeds configured size")
            matches, tokens, cost = self._parse(
                response.json(), chunks=copied, requested_model=model
            )
        except _RerankerUsageLimitError as error:
            self.metrics.record(
                documents=len(copied),
                characters=characters,
                tokens=error.tokens,
                cost=error.cost,
                failed=True,
            )
            raise
        except (
            RerankerAuthenticationError,
            RerankerRateLimitError,
            RerankerResponseError,
            RerankerUnavailableError,
        ):
            self._record_failure(len(copied), characters)
            raise
        except httpx.TransportError as error:
            self._record_failure(len(copied), characters)
            raise RerankerUnavailableError("reranker provider unavailable") from error
        except (ValueError, TypeError, KeyError) as error:
            self._record_failure(len(copied), characters)
            raise RerankerResponseError("invalid reranker response") from error

        self.metrics.record(
            documents=len(copied),
            characters=characters,
            tokens=tokens,
            cost=cost,
            failed=False,
        )
        return matches

    def _validated_request(
        self, query: str, chunks: Sequence[KnowledgeChunk], model: str
    ) -> tuple[str, tuple[KnowledgeChunk, ...], int]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must not be empty")
        normalized_query = query.strip()
        if len(normalized_query) > self._max_query_chars:
            raise ValueError("query exceeds max_query_characters")
        if isinstance(chunks, (str, bytes)) or not isinstance(chunks, Sequence):
            raise TypeError("chunks must be a sequence")
        copied = tuple(chunks)
        if not copied or len(copied) > self._max_batch:
            raise ValueError(f"chunks must contain between 1 and {self._max_batch} items")
        if any(not isinstance(chunk, KnowledgeChunk) for chunk in copied):
            raise TypeError("chunks must contain KnowledgeChunk values")
        if len({chunk.id for chunk in copied}) != len(copied):
            raise ValueError("chunks must not contain duplicate IDs")
        if any(len(chunk.text) > self._max_text_chars for chunk in copied):
            raise ValueError("a chunk exceeds max_text_characters")
        characters = len(normalized_query) + sum(len(chunk.text) for chunk in copied)
        if characters > self._max_total_chars:
            raise ValueError("request exceeds max_total_characters")
        if not isinstance(model, str) or not model.strip() or len(model) > 128:
            raise ValueError("model must be a non-empty string of at most 128 characters")
        return normalized_query, copied, characters

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        status = response.status_code
        if status in (401, 403):
            raise RerankerAuthenticationError("reranker authentication failed")
        if status == 429:
            raise RerankerRateLimitError("reranker rate limit exceeded")
        if status in (408, 425) or status >= 500:
            raise RerankerUnavailableError("reranker provider unavailable")
        if status >= 400:
            raise RerankerResponseError(f"reranker provider rejected request ({status})")

    def _parse(
        self,
        payload: Any,
        *,
        chunks: tuple[KnowledgeChunk, ...],
        requested_model: str,
    ) -> tuple[tuple[RerankedMatch, ...], int, float]:
        if not isinstance(payload, Mapping):
            raise TypeError("response must be an object")
        if payload.get("model") != requested_model:
            raise ValueError("reranker response model mismatch")
        data = payload.get("data", payload.get("results"))
        if not isinstance(data, list) or len(data) != len(chunks):
            raise ValueError("reranker result count mismatch")
        by_index: dict[int, float] = {}
        for item in data:
            if not isinstance(item, Mapping):
                raise TypeError("reranker result must be an object")
            index = item.get("index")
            score = item.get("score", item.get("relevance_score"))
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index >= len(chunks)
                or index in by_index
            ):
                raise ValueError("invalid or duplicate reranker index")
            if (
                not isinstance(score, int | float)
                or isinstance(score, bool)
                or not math.isfinite(score)
                or not 0 <= score <= 1
            ):
                raise ValueError("reranker score must be finite and between zero and one")
            by_index[index] = float(score)
        if set(by_index) != set(range(len(chunks))):
            raise ValueError("reranker indices must be complete")
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            raise TypeError("usage must be an object")
        tokens = usage.get("total_tokens", usage.get("prompt_tokens"))
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
            raise ValueError("token usage must be a non-negative integer")
        cost = tokens * self._cost_per_million / 1_000_000
        if tokens > self._max_tokens:
            raise _RerankerUsageLimitError(
                "reranker token usage exceeds configured limit", tokens=tokens, cost=cost
            )
        if cost > self._max_cost:
            raise _RerankerUsageLimitError(
                "reranker request cost exceeds configured limit", tokens=tokens, cost=cost
            )
        return (
            tuple(RerankedMatch(chunks[index].id, by_index[index]) for index in range(len(chunks))),
            tokens,
            cost,
        )

    def _record_failure(self, documents: int, characters: int) -> None:
        self.metrics.record(
            documents=documents,
            characters=characters,
            tokens=0,
            cost=0,
            failed=True,
        )


@dataclass(frozen=True, slots=True)
class RerankedRetrievalMatch:
    fused: FusedRetrievalMatch
    reranker_score: float | None

    def __post_init__(self) -> None:
        if not isinstance(self.fused, FusedRetrievalMatch):
            raise TypeError("fused must be a FusedRetrievalMatch")
        if self.reranker_score is not None and (
            not isinstance(self.reranker_score, int | float)
            or isinstance(self.reranker_score, bool)
            or not math.isfinite(self.reranker_score)
            or not 0 <= self.reranker_score <= 1
        ):
            raise ValueError("reranker_score must be between zero and one")

    @property
    def chunk(self) -> KnowledgeChunk:
        return self.fused.chunk

    @property
    def fusion_score(self) -> float:
        return self.fused.fusion_score


@dataclass(frozen=True, slots=True)
class RerankingResult:
    original_query: str
    matches: tuple[RerankedRetrievalMatch, ...]
    degradations: tuple[RetrievalDegradation, ...]


class RerankingService:
    """Rerank trusted fused candidates, preserving their real retrieval evidence."""

    def __init__(
        self,
        reranker: RerankerPort,
        *,
        model: str = "bge-reranker-v2-m3",
        max_candidates: int = 64,
        max_query_characters: int = 4_096,
        max_total_characters: int = 128_000,
    ) -> None:
        if not callable(getattr(reranker, "rerank", None)):
            raise TypeError("reranker does not implement its required port")
        if not isinstance(model, str) or not model.strip() or len(model) > 128:
            raise ValueError("model must be a non-empty string of at most 128 characters")
        for value, name, hard_max in (
            (max_candidates, "max_candidates", 100),
            (max_query_characters, "max_query_characters", 8_192),
            (max_total_characters, "max_total_characters", 256_000),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
                or value > hard_max
            ):
                raise ValueError(f"{name} must be between 1 and {hard_max}")
        self._reranker = reranker
        self._model = model.strip()
        self._max_candidates = max_candidates
        self._max_query_chars = max_query_characters
        self._max_total_chars = max_total_characters

    def rerank(self, retrieval: HybridRetrievalResult) -> RerankingResult:
        if not isinstance(retrieval, HybridRetrievalResult):
            raise TypeError("retrieval must be a HybridRetrievalResult")
        query = retrieval.original_query.strip()
        if not query or len(query) > self._max_query_chars:
            raise ValueError("original_query is outside configured bounds")
        if len(retrieval.matches) > self._max_candidates:
            raise ValueError("retrieval matches exceed max_candidates")
        if len({match.chunk.id for match in retrieval.matches}) != len(retrieval.matches):
            raise ValueError("retrieval matches must not contain duplicate chunk IDs")
        characters = len(query) + sum(len(match.chunk.text) for match in retrieval.matches)
        if characters > self._max_total_chars:
            raise ValueError("reranking input exceeds max_total_characters")
        if not retrieval.matches:
            return RerankingResult(retrieval.original_query, (), retrieval.degradations)

        chunks = tuple(match.chunk for match in retrieval.matches)
        try:
            scores = self._reranker.rerank(query, chunks, model=self._model)
            by_id = self._validate_scores(scores, chunks)
        except (RerankerError, _RerankerValidationError, ValueError, TypeError) as error:
            degradation = RetrievalDegradation(
                kind=RetrievalDegradationKind.RERANKER_DEGRADED,
                error_category=_reranker_error_category(error),
                message="Reranker is unavailable; fused retrieval order was preserved.",
            )
            return RerankingResult(
                original_query=retrieval.original_query,
                matches=tuple(RerankedRetrievalMatch(match, None) for match in retrieval.matches),
                degradations=(*retrieval.degradations, degradation),
            )

        original_positions = {
            match.chunk.id: position for position, match in enumerate(retrieval.matches)
        }
        ordered = sorted(
            retrieval.matches,
            key=lambda match: (-by_id[match.chunk.id], original_positions[match.chunk.id]),
        )
        return RerankingResult(
            original_query=retrieval.original_query,
            matches=tuple(
                RerankedRetrievalMatch(match, by_id[match.chunk.id]) for match in ordered
            ),
            degradations=retrieval.degradations,
        )

    @staticmethod
    def _validate_scores(
        scores: Sequence[RerankedMatch], chunks: tuple[KnowledgeChunk, ...]
    ) -> dict[UUID, float]:
        if isinstance(scores, (str, bytes)) or not isinstance(scores, Sequence):
            raise _RerankerValidationError
        expected = {chunk.id for chunk in chunks}
        by_id: dict[UUID, float] = {}
        for score in scores:
            if (
                not isinstance(score, RerankedMatch)
                or score.chunk_id not in expected
                or score.chunk_id in by_id
            ):
                raise _RerankerValidationError
            by_id[score.chunk_id] = score.score
        if set(by_id) != expected:
            raise _RerankerValidationError
        return by_id


class _RerankerValidationError(Exception):
    pass


class _RerankerUsageLimitError(RerankerResponseError):
    def __init__(self, message: str, *, tokens: int, cost: float) -> None:
        self.tokens = tokens
        self.cost = cost
        super().__init__(message)


def _reranker_error_category(error: Exception) -> str:
    if isinstance(error, RerankerAuthenticationError):
        return "reranker_authentication"
    if isinstance(error, RerankerRateLimitError):
        return "reranker_rate_limit"
    if isinstance(
        error, (RerankerResponseError, _RerankerValidationError, ValueError, TypeError)
    ):
        return "reranker_response"
    return "reranker_unavailable"
