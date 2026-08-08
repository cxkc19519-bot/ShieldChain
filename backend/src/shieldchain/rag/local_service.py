"""Durable local knowledge service backed by BGE, Milvus and local metadata."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4, uuid5

from shieldchain.rag.api_service import KnowledgeNotFound, UploadedDocument
from shieldchain.rag.local_milvus import DEFAULT_COLLECTION, ensure_collection
from shieldchain.rag.local_semantic_chunking import (
    DeepSeekSemanticChunker,
    SemanticChunkingError,
    SemanticSegment,
)
from shieldchain.rag.schemas import (
    CitationView,
    CreateKnowledgeBaseRequest,
    DegradationView,
    DocumentChunkListResponse,
    DocumentVersionListResponse,
    DocumentVersionView,
    EvaluationRequest,
    EvaluationResponse,
    KnowledgeBaseDeleteResponse,
    KnowledgeBaseView,
    KnowledgeChunkView,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentView,
    LifecycleOperationResponse,
    RetrievalHitView,
    RetrievalRequest,
    RetrievalResponse,
)

_TERM = re.compile(r"[a-z0-9_./:-]+|[\u4e00-\u9fff]", re.IGNORECASE)
_CHUNK_NAMESPACE = UUID("712c7cfa-f63d-4665-88bd-4d2edf3b5d1c")
_CHUNK_SIZE = 1_200
_CHUNK_OVERLAP = 180


class LocalRagUnavailable(RuntimeError):
    """The loopback model service or local Milvus instance cannot be used."""


class LocalKnowledgeService:
    """Persist uploaded files locally and index searchable chunks in local Milvus."""

    def __init__(self, root: str | Path | None = None) -> None:
        selected = (
            root or os.environ.get("SHIELDCHAIN_LOCAL_KNOWLEDGE_ROOT") or "data/local-knowledge"
        )
        self._root = Path(selected).expanduser().resolve()
        self._catalog_path = self._root / "catalog.json"
        self._model_url = os.environ.get("SHIELDCHAIN_LOCAL_RAG_URL", "http://127.0.0.1:8001")
        self._milvus_url = os.environ.get("SHIELDCHAIN_LOCAL_MILVUS_URI", "http://127.0.0.1:19530")
        self._collection = os.environ.get("SHIELDCHAIN_LOCAL_MILVUS_COLLECTION", DEFAULT_COLLECTION)
        self._lock = RLock()
        self._root.mkdir(parents=True, exist_ok=True)

    def list_knowledge_bases(self, *, tenant_id: UUID) -> Sequence[KnowledgeBaseView]:
        with self._lock:
            return [KnowledgeBaseView.model_validate(value) for value in self._catalog()["bases"]]

    def create_knowledge_base(
        self, payload: CreateKnowledgeBaseRequest, *, tenant_id: UUID
    ) -> KnowledgeBaseView:
        with self._lock:
            catalog = self._catalog()
            now = datetime.now(UTC)
            base = KnowledgeBaseView(
                id=uuid4(),
                name=payload.name,
                status="draft",
                default_sensitivity=payload.default_sensitivity,
                version_policy=payload.version_policy,
                created_at=now,
                updated_at=now,
            )
            catalog["bases"].append(base.model_dump(mode="json"))
            catalog["documents"][str(base.id)] = []
            self._save(catalog)
            return base

    def delete_knowledge_base(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeBaseDeleteResponse:
        with self._lock:
            catalog = self._catalog()
            records = list(self._records(catalog, knowledge_base_id))
            for record in records:
                document = KnowledgeDocumentView.model_validate(record["view"])
                for version in document.versions:
                    self._delete_vectors(version.id)
                shutil.rmtree(self._root / "documents" / str(document.id), ignore_errors=True)
            catalog["bases"] = [
                base for base in catalog["bases"] if base.get("id") != str(knowledge_base_id)
            ]
            catalog["documents"].pop(str(knowledge_base_id), None)
            self._save(catalog)
            return KnowledgeBaseDeleteResponse(id=knowledge_base_id, status="completed")

    def upload_document(
        self, knowledge_base_id: UUID, upload: UploadedDocument, *, tenant_id: UUID
    ) -> KnowledgeDocumentView:
        with self._lock:
            catalog = self._catalog()
            records = self._records(catalog, knowledge_base_id)
            now = datetime.now(UTC)
            document_id, version_id = uuid4(), uuid4()
            version = DocumentVersionView(
                id=version_id,
                document_id=document_id,
                version_number=1,
                parsing_status="succeeded",
                chunking_status="succeeded",
                index_status="processing",
                chunking_strategy="local-bge-m3-v1",
                created_at=now,
            )
            document = KnowledgeDocumentView(
                id=document_id,
                knowledge_base_id=knowledge_base_id,
                original_filename=upload.filename,
                media_type=upload.media_type,
                status="published",
                current_version_id=version_id,
                created_at=now,
                updated_at=now,
                versions=[version],
            )
            relative_path = Path("documents") / str(document_id) / f"{version_id}.bin"
            self._write_bytes(relative_path, upload.content)
            record: dict[str, object] = {
                "view": document.model_dump(mode="json"),
                "content_path": relative_path.as_posix(),
                "sha256": hashlib.sha256(upload.content).hexdigest(),
                "chunks": [],
            }
            records.append(record)
            self._save(catalog)
            self._index_record(record, tenant_id=tenant_id)
            self._save(catalog)
            return KnowledgeDocumentView.model_validate(record["view"])

    def list_documents(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeDocumentListResponse:
        with self._lock:
            return KnowledgeDocumentListResponse(
                items=[
                    KnowledgeDocumentView.model_validate(item["view"])
                    for item in self._records(self._catalog(), knowledge_base_id)
                ]
            )

    def list_versions(self, document_id: UUID, *, tenant_id: UUID) -> DocumentVersionListResponse:
        with self._lock:
            view = KnowledgeDocumentView.model_validate(
                self._document(self._catalog(), document_id)["view"]
            )
            return DocumentVersionListResponse(document=view, items=view.versions)

    def list_chunks(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> DocumentChunkListResponse:
        with self._lock:
            record = self._document(self._catalog(), document_id)
            document = KnowledgeDocumentView.model_validate(record["view"])
            if document.current_version_id != version_id:
                raise KnowledgeNotFound
            items: list[KnowledgeChunkView] = []
            for ordinal, chunk in enumerate(self._chunks(record)):
                text = str(chunk.get("text", "")).strip()
                digest = str(chunk.get("sha256", ""))
                if not text:
                    continue
                items.append(
                    KnowledgeChunkView(
                        id=UUID(str(chunk["id"])),
                        ordinal=ordinal,
                        offset=int(chunk.get("offset", 0)),
                        length=len(text),
                        text=text,
                        integrity_sha256=digest,
                    )
                )
            return DocumentChunkListResponse(
                document_id=document.id,
                document_version_id=version_id,
                items=items,
            )

    def publish(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse:
        self._require_version(document_id, version_id)
        return LifecycleOperationResponse(
            operation="publish",
            status="completed",
            document_id=document_id,
            version_id=version_id,
        )

    def rollback(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse:
        self._require_version(document_id, version_id)
        return LifecycleOperationResponse(
            operation="rollback",
            status="completed",
            document_id=document_id,
            version_id=version_id,
        )

    def delete(self, document_id: UUID, *, tenant_id: UUID) -> LifecycleOperationResponse:
        with self._lock:
            catalog = self._catalog()
            for records in catalog["documents"].values():
                for index, item in enumerate(records):
                    if item["view"]["id"] == str(document_id):
                        view = KnowledgeDocumentView.model_validate(item["view"])
                        self._delete_vectors(view.current_version_id)
                        records.pop(index)
                        self._save(catalog)
                        shutil.rmtree(
                            self._root / "documents" / str(document_id),
                            ignore_errors=True,
                        )
                        return LifecycleOperationResponse(
                            operation="delete",
                            status="completed",
                            document_id=document_id,
                        )
        raise KnowledgeNotFound

    def rebuild(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse:
        with self._lock:
            catalog = self._catalog()
            record = self._document(catalog, document_id)
            view = KnowledgeDocumentView.model_validate(record["view"])
            if view.current_version_id != version_id:
                raise KnowledgeNotFound
            self._index_record(record, tenant_id=tenant_id, rebuild=True)
            self._save(catalog)
            return LifecycleOperationResponse(
                operation="rebuild",
                status="completed",
                document_id=document_id,
                version_id=version_id,
            )

    def retrieve(
        self, request: RetrievalRequest, *, tenant_id: UUID, principal_id: UUID
    ) -> RetrievalResponse:
        with self._lock:
            catalog = self._catalog()
            records = [
                item
                for base_id in request.knowledge_base_ids
                for item in self._records(catalog, base_id)
            ]
            for record in records:
                if not self._chunks(record):
                    self._index_record(record, tenant_id=tenant_id)
            self._save(catalog)
            chunks = {UUID(str(chunk["id"])): chunk for chunk in self._chunk_records(records)}
            if not chunks:
                return self._empty(request.query)
            degradations: list[DegradationView] = []
            bm25 = self._bm25(request.query, chunks.values())
            vector: dict[UUID, float] = {}
            try:
                vector = self._vector_search(
                    request.query,
                    request.knowledge_base_ids,
                    tenant_id,
                    request.limit * 4,
                )
            except LocalRagUnavailable as error:
                degradations.append(
                    DegradationView(
                        kind="vector_degraded",
                        error_category="local_unavailable",
                        message=str(error),
                    )
                )
            candidates = self._fuse(
                bm25,
                {chunk_id: score for chunk_id, score in vector.items() if chunk_id in chunks},
                limit=request.limit * 4,
            )
            if not candidates:
                return self._empty(request.query, degradations)
            reranked: dict[UUID, float] = {}
            try:
                reranked = self._rerank(request.query, [chunks[item] for item in candidates])
            except LocalRagUnavailable as error:
                degradations.append(
                    DegradationView(
                        kind="reranker_degraded",
                        error_category="local_unavailable",
                        message=str(error),
                    )
                )
            ordered = sorted(
                candidates,
                key=lambda item: (
                    -reranked.get(item, -1.0),
                    -candidates[item][2],
                    str(item),
                ),
            )[: request.limit]
            hits = [
                self._hit(
                    chunks[chunk_id],
                    bm25.get(chunk_id),
                    vector.get(chunk_id),
                    candidates[chunk_id][2],
                    reranked.get(chunk_id),
                )
                for chunk_id in ordered
            ]
            return RetrievalResponse(
                query=request.query,
                answer=(
                    f"\u672c\u5730\u6df7\u5408\u68c0\u7d22\u627e\u5230 {len(hits)} "
                    "\u4e2a\u76f8\u5173\u6587\u6863\u7247\u6bb5\u3002"
                ),
                refusal_reason=None,
                hits=hits,
                citations=[self._citation(hit) for hit in hits],
                degradations=degradations,
            )

    def evaluate(self, request: EvaluationRequest, *, tenant_id: UUID) -> EvaluationResponse:
        return EvaluationResponse(
            dataset_id=request.dataset_id,
            dataset_version="local-bge-m3-v1",
            case_count=0,
            metrics={},
            quality_gate_passed=False,
        )

    def _index_record(
        self, record: dict[str, object], *, tenant_id: UUID, rebuild: bool = False
    ) -> None:
        view = KnowledgeDocumentView.model_validate(record["view"])
        version = self._current_version(view)
        chunks: list[dict[str, object]] = []
        strategy = "rule-degraded-v1"
        failure_category: str | None = "unavailable"
        try:
            content = self._extract_text(record, view)
            chunks, strategy, failure_category = self._make_chunks(content, view)
            if not chunks:
                raise LocalRagUnavailable("No usable text content for indexing")
            # Persist lexical chunks before optional vector work. A stopped local
            # Embedding/Milvus stack must degrade to BM25, not erase RAG evidence.
            record["chunks"] = chunks
            vectors = self._embed([str(chunk["text"]) for chunk in chunks])
            self._delete_vectors(version.id)
            self._upsert_vectors(chunks, view, version.id, tenant_id, vectors)
            self._replace_version(
                record,
                version.id,
                index_status="succeeded",
                chunking_status="succeeded",
                chunking_strategy=strategy,
                chunking_failure_category=failure_category,
            )
        except LocalRagUnavailable:
            if chunks:
                self._replace_version(
                    record,
                    version.id,
                    index_status="succeeded",
                    chunking_status="succeeded",
                    chunking_strategy=strategy,
                    chunking_failure_category=failure_category,
                )
                return
            # Original bytes remain durable when text extraction itself failed.
            self._replace_version(
                record, version.id, index_status="failed", chunking_status="succeeded"
            )
            if rebuild:
                raise
    def _embed(self, texts: Sequence[str]) -> list[list[float]]:
        payload = self._model_request(
            "/v1/embeddings", {"model": "BAAI/bge-m3", "input": list(texts)}
        )
        data = payload.get("data")
        if not isinstance(data, list) or len(data) != len(texts):
            raise LocalRagUnavailable(
                "\u672c\u5730 Embedding \u670d\u52a1\u8fd4\u56de\u4e86\u65e0\u6548\u6570\u636e"
            )
        try:
            vectors = [[float(value) for value in item["embedding"]] for item in data]
        except (KeyError, TypeError, ValueError) as error:
            raise LocalRagUnavailable(
                "\u672c\u5730 Embedding \u670d\u52a1\u8fd4\u56de\u4e86\u65e0\u6548\u5411\u91cf"
            ) from error
        if any(len(vector) != 1024 for vector in vectors):
            raise LocalRagUnavailable(
                "\u672c\u5730 Embedding \u5411\u91cf\u7ef4\u5ea6\u4e0d\u662f 1024"
            )
        return vectors

    def _rerank(self, query: str, chunks: Sequence[dict[str, object]]) -> dict[UUID, float]:
        if not chunks:
            return {}
        payload = self._model_request(
            "/v1/rerank",
            {
                "model": "BAAI/bge-reranker-v2-m3",
                "query": query,
                "documents": [str(item["text"]) for item in chunks],
            },
        )
        data = payload.get("data")
        if not isinstance(data, list) or len(data) != len(chunks):
            raise LocalRagUnavailable(
                "\u672c\u5730\u91cd\u6392\u670d\u52a1\u8fd4\u56de\u4e86\u65e0\u6548\u6570\u636e"
            )
        try:
            return {
                UUID(str(chunks[int(item["index"])]["id"])): float(item["score"]) for item in data
            }
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise LocalRagUnavailable(
                "\u672c\u5730\u91cd\u6392\u670d\u52a1\u8fd4\u56de\u4e86\u65e0\u6548\u5206\u6570"
            ) from error

    def _model_request(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("SHIELDCHAIN_LOCAL_RAG_API_KEY", "")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        try:
            with urlopen(
                Request(f"{self._model_url.rstrip('/')}{path}", encoded, headers),
                timeout=120,
            ) as response:
                value = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError) as error:
            raise LocalRagUnavailable(
                f"\u672c\u5730\u6a21\u578b\u670d\u52a1\u4e0d\u53ef\u7528\uff1a{error}"
            ) from error
        if not isinstance(value, dict):
            raise LocalRagUnavailable(
                "\u672c\u5730\u6a21\u578b\u670d\u52a1\u8fd4\u56de\u4e86\u65e0\u6548\u54cd\u5e94"
            )
        return value

    def _vector_search(
        self, query: str, base_ids: Sequence[UUID], tenant_id: UUID, limit: int
    ) -> dict[UUID, float]:
        vector = self._embed([query])[0]
        client = self._milvus_client()
        bases = ", ".join(json.dumps(str(value)) for value in base_ids)
        scope_filter = (
            f"tenant_id == {json.dumps(str(tenant_id))} and published == true "
            f"and knowledge_base_id in [{bases}]"
        )
        try:
            result = client.search(
                collection_name=self._collection,
                data=[vector],
                limit=min(limit, 100),
                filter=scope_filter,
                output_fields=[
                    "knowledge_base_id",
                    "document_id",
                    "document_version_id",
                ],
                search_params={"metric_type": "COSINE", "params": {}},
            )
            raw = result[0] if isinstance(result, list) and result else []
            return {
                UUID(str(item["id"])): max(0.0, min(1.0, (float(item["distance"]) + 1.0) / 2.0))
                for item in raw
            }
        except (KeyError, TypeError, ValueError, IndexError, Exception) as error:
            raise LocalRagUnavailable(
                f"Milvus \u5411\u91cf\u68c0\u7d22\u4e0d\u53ef\u7528\uff1a{error}"
            ) from error

    def _milvus_client(self) -> Any:
        try:
            from pymilvus import MilvusClient

            ensure_collection(uri=self._milvus_url, collection=self._collection)
            return MilvusClient(uri=self._milvus_url)
        except Exception as error:
            raise LocalRagUnavailable(f"Milvus \u4e0d\u53ef\u7528\uff1a{error}") from error

    def _upsert_vectors(
        self,
        chunks: Sequence[dict[str, object]],
        view: KnowledgeDocumentView,
        version_id: UUID,
        tenant_id: UUID,
        vectors: Sequence[Sequence[float]],
    ) -> None:
        client = self._milvus_client()
        rows = [
            {
                "id": str(chunk["id"]),
                "vector": list(vector),
                "tenant_id": str(tenant_id),
                "knowledge_base_id": str(view.knowledge_base_id),
                "document_id": str(view.id),
                "document_version_id": str(version_id),
                "sensitivity": "internal",
                "permission_tags": [],
                "published": True,
            }
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]
        try:
            client.upsert(collection_name=self._collection, data=rows)
            client.flush(collection_name=self._collection)
        except Exception as error:
            raise LocalRagUnavailable(f"Milvus 鍚戦噺鍐欏叆涓嶅彲鐢細{error}") from error

    def _delete_vectors(self, version_id: UUID | None) -> None:
        if version_id is None:
            return
        try:
            self._milvus_client().delete(
                collection_name=self._collection,
                filter=f"document_version_id == {json.dumps(str(version_id))}",
            )
        except LocalRagUnavailable:
            # Deleting a local document must still delete its durable metadata and source bytes.
            pass

    def _make_chunks(
        self, content: str, view: KnowledgeDocumentView
    ) -> tuple[list[dict[str, object]], str, str | None]:
        cleaned = self._clean_text(content)
        if not cleaned:
            return [], "deepseek-semantic-v1", None
        try:
            segments = DeepSeekSemanticChunker.from_settings().chunk(cleaned)
            strategy, failure_category = "deepseek-semantic-v1", None
        except SemanticChunkingError:
            segments = self._rule_segments(cleaned)
            strategy, failure_category = "rule-degraded-v1", "unavailable"
        return self._chunks_for_segments(segments, view), strategy, failure_category

    @staticmethod
    def _rule_segments(content: str) -> tuple[SemanticSegment, ...]:
        segments: list[SemanticSegment] = []
        start = 0
        while start < len(content):
            end = min(len(content), start + _CHUNK_SIZE)
            if end < len(content):
                boundary = max(
                    content.rfind("\n", start + _CHUNK_SIZE // 2, end),
                    content.rfind("\u3002", start + _CHUNK_SIZE // 2, end),
                )
                if boundary > start:
                    end = boundary + 1
            text = content[start:end].strip()
            if text:
                segments.append(SemanticSegment(offset=start, text=text))
            if end >= len(content):
                break
            start = max(start + 1, end - _CHUNK_OVERLAP)
        return tuple(segments)

    def _chunks_for_segments(
        self, segments: Sequence[SemanticSegment], view: KnowledgeDocumentView
    ) -> list[dict[str, object]]:
        version = self._current_version(view)
        chunks: list[dict[str, object]] = []
        for segment in segments:
            digest = hashlib.sha256(segment.text.encode("utf-8")).hexdigest()
            chunk_id = uuid5(_CHUNK_NAMESPACE, f"{version.id}:{len(chunks)}:{digest}")
            chunks.append(
                {
                    "id": str(chunk_id),
                    "text": segment.text,
                    "offset": segment.offset,
                    "sha256": digest,
                }
            )
        return chunks

    @staticmethod
    def _clean_text(content: str) -> str:
        value = re.sub(r"```.*?```", " ", content, flags=re.DOTALL)
        value = re.sub(r"!?(?:\[[^\]]*\])\([^)]*\)", " ", value)
        value = re.sub(r"[*_`>#]", "", value)
        return re.sub(r"[ \t]+", " ", value).strip()

    def _extract_text(self, record: dict[str, object], view: KnowledgeDocumentView) -> str:
        raw = self._read_bytes(record["content_path"])
        suffix = Path(view.original_filename).suffix.casefold()
        if suffix in {".txt", ".md", ".csv", ".html", ".htm"}:
            text = raw.decode("utf-8", errors="ignore")
            if suffix in {".html", ".htm"}:
                from bs4 import BeautifulSoup

                return BeautifulSoup(text, "html.parser").get_text(" ")
            return text
        if suffix == ".pdf":
            from io import BytesIO

            from pypdf import PdfReader

            return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(raw)).pages)
        if suffix == ".docx":
            from io import BytesIO

            from docx import Document

            return "\n".join(paragraph.text for paragraph in Document(BytesIO(raw)).paragraphs)
        if suffix == ".xlsx":
            from io import BytesIO

            from openpyxl import load_workbook

            workbook = load_workbook(BytesIO(raw), read_only=True, data_only=True)
            return "\n".join(
                " ".join(str(cell) for cell in row if cell is not None)
                for sheet in workbook.worksheets
                for row in sheet.iter_rows(values_only=True)
            )
        return raw.decode("utf-8", errors="ignore")

    def _bm25(self, query: str, chunks: Iterable[dict[str, object]]) -> dict[UUID, float]:
        source = list(chunks)
        terms = _TERM.findall(query.casefold())
        if not source or not terms:
            return {}
        tokenized = [Counter(_TERM.findall(str(chunk["text"]).casefold())) for chunk in source]
        lengths = [sum(counter.values()) for counter in tokenized]
        average = sum(lengths) / len(lengths) or 1.0
        document_frequency = Counter(term for counter in tokenized for term in set(counter))
        scores: dict[UUID, float] = {}
        for chunk, counts, length in zip(source, tokenized, lengths, strict=True):
            score = 0.0
            for term in terms:
                frequency = counts[term]
                if frequency:
                    inverse = math.log(
                        1
                        + (len(source) - document_frequency[term] + 0.5)
                        / (document_frequency[term] + 0.5)
                    )
                    score += (
                        inverse
                        * (frequency * 2.0)
                        / (frequency + 1.2 * (1 - 0.75 + 0.75 * length / average))
                    )
            if score:
                scores[UUID(str(chunk["id"]))] = score
        maximum = max(scores.values(), default=0.0)
        return {chunk_id: score / maximum for chunk_id, score in scores.items()} if maximum else {}

    @staticmethod
    def _fuse(
        bm25: dict[UUID, float], vector: dict[UUID, float], *, limit: int
    ) -> dict[UUID, tuple[float | None, float | None, float]]:
        identifiers = set(bm25) | set(vector)
        fused = {
            identifier: (
                bm25.get(identifier),
                vector.get(identifier),
                0.45 * bm25.get(identifier, 0.0) + 0.55 * vector.get(identifier, 0.0),
            )
            for identifier in identifiers
        }
        return dict(sorted(fused.items(), key=lambda item: (-item[1][2], str(item[0])))[:limit])

    def _chunk_records(self, records: Iterable[dict[str, object]]) -> Iterable[dict[str, object]]:
        for record in records:
            document = KnowledgeDocumentView.model_validate(record["view"])
            for chunk in self._chunks(record):
                yield {
                    **chunk,
                    "document": document,
                    "document_sha256": str(record["sha256"]),
                }

    @staticmethod
    def _chunks(record: dict[str, object]) -> list[dict[str, object]]:
        chunks = record.get("chunks", [])
        return (
            [item for item in chunks if isinstance(item, dict)] if isinstance(chunks, list) else []
        )

    @staticmethod
    def _current_version(view: KnowledgeDocumentView) -> DocumentVersionView:
        for version in view.versions:
            if version.id == view.current_version_id:
                return version
        raise KnowledgeNotFound

    def _replace_version(
        self, record: dict[str, object], version_id: UUID, **changes: object
    ) -> None:
        view = KnowledgeDocumentView.model_validate(record["view"])
        versions = [
            version.model_copy(update=changes) if version.id == version_id else version
            for version in view.versions
        ]
        record["view"] = view.model_copy(
            update={"versions": versions, "updated_at": datetime.now(UTC)}
        ).model_dump(mode="json")

    def _hit(
        self,
        chunk: dict[str, object],
        bm25: float | None,
        vector: float | None,
        fusion: float,
        reranker: float | None,
    ) -> RetrievalHitView:
        document = chunk["document"]
        if not isinstance(document, KnowledgeDocumentView):
            raise TypeError("local chunk metadata is invalid")
        version = self._current_version(document)
        return RetrievalHitView(
            chunk_id=UUID(str(chunk["id"])),
            knowledge_base_id=document.knowledge_base_id,
            document_id=document.id,
            document_version_id=version.id,
            document_title=document.original_filename,
            excerpt=str(chunk["text"]),
            heading_path=[],
            structural_location=f"chunk@{chunk['offset']}",
            bm25_score=bm25,
            vector_score=vector,
            fusion_score=fusion,
            reranker_score=reranker,
            updated_at=document.updated_at,
            integrity_sha256=str(chunk["sha256"]),
        )

    @staticmethod
    def _citation(hit: RetrievalHitView) -> CitationView:
        return CitationView(citation_id=f"local:{hit.chunk_id}", **hit.model_dump())

    @staticmethod
    def _empty(query: str, degradations: list[DegradationView] | None = None) -> RetrievalResponse:
        return RetrievalResponse(
            query=query,
            answer=None,
            refusal_reason="insufficient_evidence",
            hits=[],
            citations=[],
            degradations=degradations or [],
        )

    def _catalog(self) -> dict[str, Any]:
        if not self._catalog_path.exists():
            return {"bases": [], "documents": {}}
        value = json.loads(self._catalog_path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("bases"), list)
            or not isinstance(value.get("documents"), dict)
        ):
            raise TypeError("local knowledge catalog is invalid")
        return value

    def _save(self, catalog: dict[str, Any]) -> None:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self._root, delete=False
        ) as handle:
            json.dump(catalog, handle, ensure_ascii=False, indent=2, sort_keys=True)
            temporary = Path(handle.name)
        temporary.replace(self._catalog_path)

    def _records(self, catalog: dict[str, Any], knowledge_base_id: UUID) -> list[dict[str, object]]:
        if not any(item.get("id") == str(knowledge_base_id) for item in catalog["bases"]):
            raise KnowledgeNotFound
        records = catalog["documents"].get(str(knowledge_base_id))
        if not isinstance(records, list):
            raise TypeError("local knowledge records are invalid")
        return records

    def _document(self, catalog: dict[str, Any], document_id: UUID) -> dict[str, object]:
        for records in catalog["documents"].values():
            for item in records:
                if item["view"]["id"] == str(document_id):
                    return item
        raise KnowledgeNotFound

    def _require_version(self, document_id: UUID, version_id: UUID) -> None:
        view = KnowledgeDocumentView.model_validate(
            self._document(self._catalog(), document_id)["view"]
        )
        if all(version.id != version_id for version in view.versions):
            raise KnowledgeNotFound

    def _write_bytes(self, relative_path: Path, content: bytes) -> None:
        target = self._root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", dir=target.parent, delete=False) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        temporary.replace(target)

    def _read_bytes(self, relative_path: object) -> bytes:
        if not isinstance(relative_path, str):
            return b""
        try:
            return (self._root / relative_path).read_bytes()
        except OSError:
            return b""
