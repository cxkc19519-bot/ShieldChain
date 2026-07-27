"""Loopback-only BGE-M3 embedding and reranking HTTP service."""

from __future__ import annotations

import math
import os
from collections.abc import Sequence
from threading import Lock
from typing import Annotated, Any

import torch
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from shieldchain.rag.local_models import (
    embedding_model_path,
    models_are_present,
    models_root,
    reranker_model_path,
)

MAX_BATCH_SIZE = 64
MAX_TEXT_CHARACTERS = 16_000
MAX_BATCH_CHARACTERS = 128_000
EMBEDDING_DIMENSION = 1024


class EmbeddingRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    input: list[str] = Field(min_length=1, max_length=MAX_BATCH_SIZE)


class RerankRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=4_096)
    documents: list[str] = Field(min_length=1, max_length=MAX_BATCH_SIZE)
    return_documents: bool = False


class LocalModelRuntime:
    """Lazily load the two GPU models exactly once per worker process."""

    def __init__(self, root: str | None = None) -> None:
        self._root = models_root(root)
        self._lock = Lock()
        self._embedding: Any | None = None
        self._reranker: Any | None = None

    @property
    def root(self) -> str:
        return str(self._root)

    def ready(self) -> bool:
        return models_are_present(self._root)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self._validate_texts(texts)
        encoded = self._embedding_model().encode(
            list(texts),
            batch_size=min(16, len(texts)),
            max_length=8192,
            return_dense=True,
            return_sparse=False,
            return_colbert_vecs=False,
        )
        values = encoded.get("dense_vecs") if isinstance(encoded, dict) else None
        if values is None or len(values) != len(texts):
            raise RuntimeError("BGE-M3 returned an invalid dense embedding response")
        return [self._vector(value) for value in values]

    def rerank(self, query: str, documents: Sequence[str]) -> list[float]:
        self._validate_texts((query, *documents))
        scores = self._reranker_model().compute_score(
            [[query, document] for document in documents],
            batch_size=min(16, len(documents)),
            max_length=512,
            normalize=True,
        )
        raw_scores = [scores] if isinstance(scores, float | int) else list(scores)
        if len(raw_scores) != len(documents):
            raise RuntimeError("BGE reranker returned an invalid score response")
        normalized = [float(score) for score in raw_scores]
        if any(not math.isfinite(score) or not 0 <= score <= 1 for score in normalized):
            raise RuntimeError("BGE reranker returned an invalid score")
        return normalized

    def _embedding_model(self) -> Any:
        with self._lock:
            if self._embedding is None:
                self._require_models()
                from FlagEmbedding import BGEM3FlagModel

                self._embedding = BGEM3FlagModel(
                    str(embedding_model_path(self._root)),
                    normalize_embeddings=True,
                    use_fp16=torch.cuda.is_available(),
                    devices="cuda:0" if torch.cuda.is_available() else "cpu",
                )
            return self._embedding

    def _reranker_model(self) -> Any:
        with self._lock:
            if self._reranker is None:
                self._require_models()
                from FlagEmbedding import FlagReranker

                self._reranker = FlagReranker(
                    str(reranker_model_path(self._root)),
                    use_fp16=torch.cuda.is_available(),
                    devices="cuda:0" if torch.cuda.is_available() else "cpu",
                )
            return self._reranker

    def _require_models(self) -> None:
        if not self.ready():
            raise RuntimeError(
                f"local BGE models are missing under {self._root}; "
                "run python -m shieldchain.rag.local_models"
            )

    @staticmethod
    def _validate_texts(texts: Sequence[str]) -> None:
        if not texts or len(texts) > MAX_BATCH_SIZE:
            raise ValueError(f"requests must contain between 1 and {MAX_BATCH_SIZE} texts")
        if any(not isinstance(text, str) or not text.strip() for text in texts):
            raise ValueError("texts must be non-empty strings")
        if any(len(text) > MAX_TEXT_CHARACTERS for text in texts):
            raise ValueError("a text exceeds the local model input limit")
        if sum(len(text) for text in texts) > MAX_BATCH_CHARACTERS:
            raise ValueError("request exceeds the local model batch limit")

    @staticmethod
    def _vector(value: Any) -> list[float]:
        raw = value.tolist() if hasattr(value, "tolist") else list(value)
        vector = [float(item) for item in raw]
        if len(vector) != EMBEDDING_DIMENSION or any(not math.isfinite(item) for item in vector):
            raise RuntimeError("BGE-M3 returned an invalid embedding vector")
        return vector


def _token_estimate(texts: Sequence[str]) -> int:
    return sum(max(1, len(text) // 4) for text in texts)


def create_model_app(runtime: LocalModelRuntime | None = None) -> FastAPI:
    runtime = runtime or LocalModelRuntime()
    app = FastAPI(title="ShieldChain Local RAG Models", docs_url=None, redoc_url=None)

    def require_local_token(authorization: Annotated[str | None, Header()] = None) -> None:
        configured = os.environ.get("SHIELDCHAIN_LOCAL_RAG_API_KEY", "")
        if configured and authorization != f"Bearer {configured}":
            raise HTTPException(status_code=401, detail="invalid local RAG API key")

    @app.get("/healthz")
    def health() -> dict[str, object]:
        return {"status": "ok", "models_ready": runtime.ready(), "models_root": runtime.root}

    @app.post("/v1/embeddings")
    def embeddings(
        request: EmbeddingRequest, _: None = Depends(require_local_token)
    ) -> dict[str, object]:
        try:
            vectors = runtime.embed(request.input)
        except (RuntimeError, ValueError) as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        return {
            "object": "list",
            "model": request.model,
            "data": [
                {"object": "embedding", "index": index, "embedding": vector}
                for index, vector in enumerate(vectors)
            ],
            "usage": {"total_tokens": _token_estimate(request.input)},
        }

    @app.post("/v1/rerank")
    def rerank(request: RerankRequest, _: None = Depends(require_local_token)) -> dict[str, object]:
        try:
            scores = runtime.rerank(request.query, request.documents)
        except (RuntimeError, ValueError) as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        return {
            "model": request.model,
            "data": [{"index": index, "score": score} for index, score in enumerate(scores)],
            "usage": {"total_tokens": _token_estimate((request.query, *request.documents))},
        }

    return app


app = create_model_app()
