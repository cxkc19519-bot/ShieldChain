from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.domain import AccessScope, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.milvus import (
    MILVUS_FIELDS,
    MILVUS_INDEX,
    MILVUS_SCHEMA,
    ManagedMilvusIndex,
    PymilvusClientAdapter,
)
from shieldchain.rag.ports import VectorIndexResponseError, VectorIndexUnavailableError


@dataclass
class FakeMilvus:
    hits: list[dict[str, object]] = field(default_factory=list)
    fail: bool = False
    upserts: list[dict[str, Any]] = field(default_factory=list)
    searches: list[dict[str, Any]] = field(default_factory=list)
    deletes: list[dict[str, Any]] = field(default_factory=list)

    def upsert(self, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("provider secret")
        self.upserts.append(kwargs)

    def search(self, **kwargs: Any) -> list[dict[str, object]]:
        if self.fail:
            raise RuntimeError("provider secret")
        self.searches.append(kwargs)
        return self.hits

    def delete(self, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("provider secret")
        self.deletes.append(kwargs)


def chunk(version_id: UUID, *, tags: tuple[str, ...] = ("soc",)) -> KnowledgeChunk:
    chunk_id = uuid4()
    return KnowledgeChunk(
        id=chunk_id,
        document_version_id=version_id,
        ordinal=0,
        heading_path=("Detection",),
        page_number=None,
        structural_location="markdown:p1",
        text="CVE-2026-1234",
        token_count=3,
        content_sha256="a" * 64,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags=tags,
        chunking_mode="rule",
        is_degraded=False,
    )


def scope(tenant_id: UUID, knowledge_base_id: UUID) -> AccessScope:
    return AccessScope(
        tenant_id=tenant_id,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=("soc",),
        knowledge_base_ids=(knowledge_base_id,),
    )


def hit(
    chunk_id: UUID,
    tenant_id: UUID,
    knowledge_base_id: UUID,
    **changes: object,
) -> dict[str, object]:
    result: dict[str, object] = {
        "id": str(chunk_id),
        "score": 0.8,
        "tenant_id": str(tenant_id),
        "knowledge_base_id": str(knowledge_base_id),
        "document_id": str(uuid4()),
        "document_version_id": str(uuid4()),
        "sensitivity": "internal",
        "permission_tags": ["soc"],
        "published": True,
    }
    result.update(changes)
    return result


def test_upsert_has_complete_schema_metadata_and_stable_ids() -> None:
    client = FakeMilvus()
    index = ManagedMilvusIndex(
        client=client,
        collection="knowledge",
        expected_dimension=3,
        published_by_default=True,
    )
    tenant_id, knowledge_base_id, document_id, version_id = (uuid4() for _ in range(4))
    item = chunk(version_id)

    first = index.upsert(
        [item],
        [[0.1, 0.2, 0.3]],
        tenant_id=tenant_id,
        knowledge_base_id=knowledge_base_id,
        document_id=document_id,
        document_version_id=version_id,
    )
    second = index.upsert(
        [item],
        [[0.1, 0.2, 0.3]],
        tenant_id=tenant_id,
        knowledge_base_id=knowledge_base_id,
        document_id=document_id,
        document_version_id=version_id,
    )

    assert first[0].id == second[0].id
    row = client.upserts[0]["data"][0]
    assert set(row) == set(MILVUS_FIELDS)
    assert set(MILVUS_SCHEMA) == set(MILVUS_FIELDS)
    assert MILVUS_SCHEMA["vector"]["dim"] == 1024
    assert MILVUS_SCHEMA["permission_tags"]["max_capacity"] == 16
    assert MILVUS_INDEX["metric_type"] == "COSINE"
    assert row["tenant_id"] == tenant_id
    assert row["permission_tags"] == ["soc"]
    assert row["published"] is True


def test_search_pushes_acl_filter_and_rechecks_returned_metadata() -> None:
    tenant_id, knowledge_base_id = uuid4(), uuid4()
    allowed_id, wrong_tenant_id, wrong_tag_id, draft_id = (uuid4() for _ in range(4))
    client = FakeMilvus(
        hits=[
            hit(allowed_id, tenant_id, knowledge_base_id),
            hit(wrong_tenant_id, uuid4(), knowledge_base_id),
            hit(wrong_tag_id, tenant_id, knowledge_base_id, permission_tags=["admin"]),
            hit(draft_id, tenant_id, knowledge_base_id, published=False),
        ]
    )
    index = ManagedMilvusIndex(client=client, collection="knowledge", expected_dimension=3)

    assert [item.chunk_id for item in index.search(
        [0.1, 0.2, 0.3], scope=scope(tenant_id, knowledge_base_id), limit=10
    )] == [allowed_id]
    expression = client.searches[0]["filter"]
    assert str(tenant_id) in expression
    assert str(knowledge_base_id) in expression
    assert "internal" in expression
    assert "permission_tags" in expression
    assert "published == true" in expression
    assert "array_contains_any" not in expression.lower()
    assert "permission_tags[0] in" in expression


def test_malformed_hit_fails_closed() -> None:
    tenant_id, knowledge_base_id = uuid4(), uuid4()
    client = FakeMilvus(hits=[{"id": str(uuid4()), "score": 0.5}])
    index = ManagedMilvusIndex(client=client, collection="knowledge", expected_dimension=3)

    with pytest.raises(VectorIndexResponseError):
        index.search([0.1, 0.2, 0.3], scope=scope(tenant_id, knowledge_base_id), limit=1)


def test_acl_filter_quotes_permission_tags_as_data() -> None:
    tenant_id, knowledge_base_id = uuid4(), uuid4()
    malicious_tag = 'soc\") or published == false or (\"'
    access = AccessScope(
        tenant_id=tenant_id,
        principal_id=uuid4(),
        roles=("analyst",),
        allowed_sensitivities=(SensitivityLevel.INTERNAL,),
        permission_tags=(malicious_tag,),
        knowledge_base_ids=(knowledge_base_id,),
    )
    client = FakeMilvus()
    index = ManagedMilvusIndex(client=client, collection="knowledge", expected_dimension=3)

    index.search([0.1, 0.2, 0.3], scope=access, limit=1)

    assert '\\\"' in client.searches[0]["filter"]


def test_delete_is_repeatable_and_provider_failures_are_classified() -> None:
    version_id = uuid4()
    client = FakeMilvus()
    index = ManagedMilvusIndex(client=client, collection="knowledge", expected_dimension=3)

    index.delete_document_version(version_id)
    index.delete_document_version(version_id)
    assert client.deletes[0] == client.deletes[1]

    client.fail = True
    with pytest.raises(VectorIndexUnavailableError, match="delete failed"):
        index.delete_document_version(version_id)


@pytest.mark.parametrize("vector", [[0.1, 0.2], [0.1, float("inf"), 0.3]])
def test_vector_validation_happens_before_network(vector: list[float]) -> None:
    client = FakeMilvus()
    index = ManagedMilvusIndex(client=client, collection="knowledge", expected_dimension=3)

    with pytest.raises(ValueError):
        index.search(vector, scope=scope(uuid4(), uuid4()), limit=5)

    assert client.searches == []


def test_pymilvus_adapter_translates_standard_api_and_normalizes_cosine() -> None:
    class RawClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        def upsert(self, **kwargs):
            self.calls.append(("upsert", kwargs))

        def search(self, **kwargs):
            self.calls.append(("search", kwargs))
            return [[{"id": "chunk", "distance": 0.6, "entity": {"published": True}}]]

        def delete(self, **kwargs):
            self.calls.append(("delete", kwargs))

    raw = RawClient()
    client = PymilvusClientAdapter(raw)
    client.upsert(collection="knowledge", data=[{"id": "chunk"}])
    hits = client.search(
        collection="knowledge",
        vector=[0.1, 0.2],
        filter="published == true",
        limit=1,
        output_fields=["published"],
    )
    client.delete(collection="knowledge", filter='document_version_id == "v1"')

    assert hits == ({"published": True, "id": "chunk", "score": 0.8},)
    assert raw.calls[0][1]["collection_name"] == "knowledge"
    assert raw.calls[1][1]["data"] == [[0.1, 0.2]]
    assert raw.calls[1][1]["search_params"] == {"metric_type": "COSINE", "params": {}}
    assert raw.calls[2][1]["filter"] == 'document_version_id == "v1"'
