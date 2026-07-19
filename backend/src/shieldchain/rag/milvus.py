from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Protocol
from uuid import UUID, uuid5

from shieldchain.rag.domain import (
    AccessScope,
    IndexRecord,
    IndexStatus,
    KnowledgeChunk,
    SensitivityLevel,
)
from shieldchain.rag.indexing import IndexingContext
from shieldchain.rag.ports import (
    VectorIndexResponseError,
    VectorIndexUnavailableError,
    VectorMatch,
    index_metadata_for_chunk,
)

MILVUS_FIELDS = (
    "id",
    "vector",
    "tenant_id",
    "knowledge_base_id",
    "document_id",
    "document_version_id",
    "sensitivity",
    "permission_tags",
    "published",
)
MILVUS_SCHEMA = MappingProxyType({
    "id": MappingProxyType({"type": "VARCHAR", "max_length": 36, "primary": True}),
    "vector": MappingProxyType({"type": "FLOAT_VECTOR", "dim": 1024}),
    "tenant_id": MappingProxyType({"type": "VARCHAR", "max_length": 36}),
    "knowledge_base_id": MappingProxyType({"type": "VARCHAR", "max_length": 36}),
    "document_id": MappingProxyType({"type": "VARCHAR", "max_length": 36}),
    "document_version_id": MappingProxyType({"type": "VARCHAR", "max_length": 36}),
    "sensitivity": MappingProxyType({"type": "VARCHAR", "max_length": 32}),
    "permission_tags": MappingProxyType({
        "type": "ARRAY",
        "element_type": "VARCHAR",
        "max_capacity": 16,
        "element_max_length": 128,
    }),
    "published": MappingProxyType({"type": "BOOL"}),
})
MILVUS_INDEX = MappingProxyType({"field": "vector", "metric_type": "COSINE"})
_INDEX_RECORD_NAMESPACE = UUID("561c3cc8-72f4-4bb0-8998-40e6c8afe4fb")


class MilvusClient(Protocol):
    def upsert(self, *, collection: str, data: Sequence[Mapping[str, object]]) -> Any: ...

    def search(
        self,
        *,
        collection: str,
        vector: Sequence[float],
        filter: str,
        limit: int,
        output_fields: Sequence[str],
    ) -> Sequence[Mapping[str, object]]: ...

    def delete(self, *, collection: str, filter: str) -> Any: ...


class PymilvusClientAdapter:
    """Translate the standard pymilvus client API into the narrow application port."""

    def __init__(self, client: Any) -> None:
        for method in ("upsert", "search", "delete"):
            if not callable(getattr(client, method, None)):
                raise TypeError(f"pymilvus client must provide {method}")
        self._client = client

    def upsert(self, *, collection: str, data: Sequence[Mapping[str, object]]) -> Any:
        return self._client.upsert(collection_name=collection, data=list(data))

    def search(
        self,
        *,
        collection: str,
        vector: Sequence[float],
        filter: str,
        limit: int,
        output_fields: Sequence[str],
    ) -> tuple[Mapping[str, object], ...]:
        result = self._client.search(
            collection_name=collection,
            data=[list(vector)],
            filter=filter,
            limit=limit,
            output_fields=list(output_fields),
            search_params={"metric_type": "COSINE", "params": {}},
        )
        if (
            not isinstance(result, Sequence)
            or isinstance(result, (str, bytes))
            or len(result) != 1
            or not isinstance(result[0], Sequence)
        ):
            raise VectorIndexResponseError("pymilvus returned invalid search results")
        normalized: list[Mapping[str, object]] = []
        for hit in result[0]:
            if not isinstance(hit, Mapping) or not isinstance(hit.get("entity"), Mapping):
                raise VectorIndexResponseError("pymilvus returned invalid search hit")
            try:
                cosine = float(hit["distance"])
                score = (cosine + 1.0) / 2.0
                if not math.isfinite(score) or not 0 <= score <= 1:
                    raise ValueError
                normalized.append({**hit["entity"], "id": hit["id"], "score": score})
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                raise VectorIndexResponseError("pymilvus returned invalid search hit") from error
        return tuple(normalized)

    def delete(self, *, collection: str, filter: str) -> Any:
        return self._client.delete(collection_name=collection, filter=filter)


class ManagedMilvusIndex:
    """Milvus adapter with provider-side ACL filtering and fail-closed hit verification."""

    def __init__(
        self,
        *,
        client: MilvusClient,
        collection: str,
        embedding_model: str = "BAAI/bge-m3",
        expected_dimension: int = 1024,
        index_version: str = "v1",
        published_by_default: bool = False,
        max_permission_tags: int = 16,
    ) -> None:
        if not collection.strip() or not embedding_model.strip() or not index_version.strip():
            raise ValueError("collection, embedding_model and index_version must not be empty")
        if not isinstance(expected_dimension, int) or expected_dimension < 1:
            raise ValueError("expected_dimension must be a positive integer")
        if not isinstance(max_permission_tags, int) or not 1 <= max_permission_tags <= 16:
            raise ValueError("max_permission_tags must be between 1 and 16")
        self._client = client
        self._collection = collection
        self._model = embedding_model
        self._dimension = expected_dimension
        self._index_version = index_version
        self._published = published_by_default
        self._max_permission_tags = max_permission_tags

    def upsert(
        self,
        chunks: Sequence[KnowledgeChunk],
        vectors: Sequence[Sequence[float]],
        *,
        tenant_id: UUID | None = None,
        knowledge_base_id: UUID | None = None,
        document_id: UUID | None = None,
        document_version_id: UUID | None = None,
        context: IndexingContext | None = None,
    ) -> tuple[IndexRecord, ...]:
        published = self._published
        if context is not None:
            supplied = (tenant_id, knowledge_base_id, document_id, document_version_id)
            expected = (
                context.tenant_id,
                context.knowledge_base_id,
                context.document_id,
                context.document_version_id,
            )
            if any(value is not None for value in supplied) and supplied != expected:
                raise ValueError("explicit metadata disagrees with indexing context")
            tenant_id, knowledge_base_id, document_id, document_version_id = expected
            published = context.published
        if not all(
            isinstance(value, UUID)
            for value in (tenant_id, knowledge_base_id, document_id, document_version_id)
        ):
            raise TypeError("trusted indexing metadata must contain UUID values")
        copied_chunks = tuple(chunks)
        copied_vectors = tuple(tuple(vector) for vector in vectors)
        if len(copied_chunks) != len(copied_vectors):
            raise ValueError("chunks and vectors must have equal lengths")
        if any(chunk.document_version_id != document_version_id for chunk in copied_chunks):
            raise ValueError("all chunks must belong to document_version_id")
        rows: list[Mapping[str, object]] = []
        for chunk, vector in zip(copied_chunks, copied_vectors, strict=True):
            self._validate_vector(vector)
            if len(chunk.permission_tags) > self._max_permission_tags:
                raise ValueError("chunk permission tags exceed configured capacity")
            metadata = index_metadata_for_chunk(
                chunk,
                tenant_id=tenant_id,
                knowledge_base_id=knowledge_base_id,
                document_id=document_id,
                published=published,
            )
            rows.append(
                {
                    "id": str(chunk.id),
                    "vector": list(vector),
                    **metadata,
                    "permission_tags": list(metadata["permission_tags"]),
                }
            )
        try:
            if rows:
                self._client.upsert(collection=self._collection, data=rows)
        except Exception as error:
            raise VectorIndexUnavailableError("Milvus upsert failed") from error
        now = datetime.now(UTC)
        return tuple(
            IndexRecord(
                id=uuid5(_INDEX_RECORD_NAMESPACE, f"{self._collection}:{chunk.id}"),
                document_version_id=document_version_id,
                chunk_id=chunk.id,
                bm25_key=None,
                embedding_model=self._model,
                vector_id=str(chunk.id),
                reranker_model=None,
                index_version=self._index_version,
                status=IndexStatus.SUCCEEDED,
                error_category=None,
                updated_at=now,
            )
            for chunk in copied_chunks
        )

    def search(
        self, vector: Sequence[float], *, scope: AccessScope, limit: int
    ) -> tuple[VectorMatch, ...]:
        copied_vector = tuple(vector)
        self._validate_vector(copied_vector)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if not scope.knowledge_base_ids:
            return ()
        expression = self._scope_filter(scope, max_permission_tags=self._max_permission_tags)
        try:
            hits = self._client.search(
                collection=self._collection,
                vector=copied_vector,
                filter=expression,
                limit=limit,
                output_fields=MILVUS_FIELDS[2:],
            )
        except Exception as error:
            raise VectorIndexUnavailableError("Milvus search failed") from error
        if not isinstance(hits, Sequence) or isinstance(hits, (str, bytes)):
            raise VectorIndexResponseError("Milvus returned invalid search results")
        matches: list[VectorMatch] = []
        for hit in hits:
            match = self._verified_match(hit, scope)
            if match is not None:
                matches.append(match)
            if len(matches) == limit:
                break
        return tuple(matches)

    def delete_document_version(
        self,
        document_version_id: UUID | None = None,
        *,
        context: IndexingContext | None = None,
    ) -> None:
        tenant_clause = ""
        if context is not None:
            if (
                document_version_id is not None
                and document_version_id != context.document_version_id
            ):
                raise ValueError("delete context does not match document version")
            document_version_id = context.document_version_id
            tenant_clause = f'tenant_id == {json.dumps(str(context.tenant_id))} and '
        if not isinstance(document_version_id, UUID):
            raise TypeError("document_version_id must be a UUID")
        try:
            self._client.delete(
                collection=self._collection,
                filter=(
                    f"{tenant_clause}document_version_id == "
                    f"{json.dumps(str(document_version_id))}"
                ),
            )
        except Exception as error:
            raise VectorIndexUnavailableError("Milvus delete failed") from error

    def _validate_vector(self, vector: Sequence[float]) -> None:
        if len(vector) != self._dimension:
            raise ValueError("vector dimension mismatch")
        if any(
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or not math.isfinite(value)
            for value in vector
        ):
            raise ValueError("vectors must contain finite numbers")

    @staticmethod
    def _scope_filter(scope: AccessScope, *, max_permission_tags: int = 16) -> str:
        knowledge_bases = ", ".join(
            json.dumps(str(item)) for item in sorted(scope.knowledge_base_ids)
        )
        sensitivities = ", ".join(
            json.dumps(item.value) for item in sorted(scope.allowed_sensitivities)
        )
        tags = ", ".join(json.dumps(item) for item in sorted(scope.permission_tags))
        # AccessScope requires every tag on the row to be granted to the principal.
        # Milvus ARRAY_CONTAINS_ALL has the reverse direction, so expand the bounded
        # ARRAY positions explicitly and still verify every returned hit below.
        allowed = f"[{tags}]"
        lengths = ["array_length(permission_tags) == 0"]
        if tags:
            for count in range(1, max_permission_tags + 1):
                positions = " and ".join(
                    f"permission_tags[{position}] in {allowed}" for position in range(count)
                )
                lengths.append(
                    f"(array_length(permission_tags) == {count} and {positions})"
                )
        tag_clause = f"({' or '.join(lengths)})"
        return (
            f'tenant_id == "{scope.tenant_id}" and published == true '
            f"and knowledge_base_id in [{knowledge_bases}] "
            f"and sensitivity in [{sensitivities}] and {tag_clause}"
        )

    @staticmethod
    def _verified_match(hit: Mapping[str, object], scope: AccessScope) -> VectorMatch | None:
        try:
            chunk_id = UUID(str(hit["id"]))
            score = float(hit["score"])
            tenant_id = UUID(str(hit["tenant_id"]))
            knowledge_base_id = UUID(str(hit["knowledge_base_id"]))
            UUID(str(hit["document_id"]))
            UUID(str(hit["document_version_id"]))
            sensitivity = SensitivityLevel(str(hit["sensitivity"]))
            tags_raw = hit["permission_tags"]
            published = hit["published"]
            if not isinstance(tags_raw, Sequence) or isinstance(tags_raw, (str, bytes)):
                raise TypeError
            if any(not isinstance(tag, str) or not tag.strip() for tag in tags_raw):
                raise TypeError
            tags = tuple(tags_raw)
            if published is not True or not scope.allows(
                tenant_id, knowledge_base_id, sensitivity, tags
            ):
                return None
            return VectorMatch(chunk_id=chunk_id, score=score)
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise VectorIndexResponseError("Milvus returned invalid hit metadata") from error
