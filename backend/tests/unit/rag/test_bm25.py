from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.bm25 import Bm25ScopeMetadata, DeterministicBm25Index
from shieldchain.rag.domain import AccessScope, IndexStatus, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.ports import Bm25IndexError
from shieldchain.rag.tokenization import DeterministicSecurityTokenizer

TENANT_ID = UUID("10000000-0000-0000-0000-000000000001")
OTHER_TENANT_ID = UUID("10000000-0000-0000-0000-000000000002")
KB_ID = UUID("20000000-0000-0000-0000-000000000001")
OTHER_KB_ID = UUID("20000000-0000-0000-0000-000000000002")
VERSION_ID = UUID("30000000-0000-0000-0000-000000000001")
OTHER_VERSION_ID = UUID("30000000-0000-0000-0000-000000000002")


def make_chunk(
    chunk_id: UUID,
    text: str,
    *,
    version_id: UUID = VERSION_ID,
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL,
    tags: frozenset[str] = frozenset({"soc"}),
) -> KnowledgeChunk:
    return KnowledgeChunk(
        id=chunk_id,
        document_version_id=version_id,
        ordinal=0,
        heading_path=("Runbook",),
        page_number=None,
        structural_location="section:1",
        text=text,
        token_count=max(1, len(DeterministicSecurityTokenizer().tokenize(text))),
        content_sha256="a" * 64,
        sensitivity=sensitivity,
        permission_tags=tags,
        chunking_mode="rule",
        is_degraded=False,
    )


def make_scope(
    *,
    tenant_id: UUID = TENANT_ID,
    knowledge_base_ids: frozenset[UUID] = frozenset({KB_ID}),
    sensitivities: frozenset[SensitivityLevel] = frozenset({SensitivityLevel.INTERNAL}),
    tags: frozenset[str] = frozenset({"soc"}),
) -> AccessScope:
    return AccessScope(
        tenant_id=tenant_id,
        principal_id=uuid4(),
        roles={"analyst"},
        allowed_sensitivities=sensitivities,
        permission_tags=tags,
        knowledge_base_ids=knowledge_base_ids,
    )


def make_index(
    metadata: dict[UUID, Bm25ScopeMetadata] | None = None,
) -> DeterministicBm25Index:
    scopes = metadata or {
        VERSION_ID: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=True),
        OTHER_VERSION_ID: Bm25ScopeMetadata(OTHER_TENANT_ID, OTHER_KB_ID, published=True),
    }
    return DeterministicBm25Index(
        DeterministicSecurityTokenizer(),
        scope_resolver=scopes.__getitem__,
        clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
    )


def test_bm25_indexes_english_chinese_and_atomic_security_terms() -> None:
    index = make_index()
    english = make_chunk(UUID(int=2), "Investigate endpoint persistence and PowerShell")
    chinese = make_chunk(UUID(int=1), "检测恶意IP地址并隔离受感染主机 CVE-2024-3094")
    index.upsert((english, chinese))

    assert [
        match.chunk_id for match in index.search("隔离感染主机", scope=make_scope(), limit=5)
    ] == [chinese.id]
    assert [
        match.chunk_id for match in index.search("CVE-2024-3094", scope=make_scope(), limit=5)
    ] == [chinese.id]
    assert (
        index.search("persistence powershell", scope=make_scope(), limit=5)[0].chunk_id
        == english.id
    )


def test_upsert_returns_stable_success_records_and_replaces_existing_chunk() -> None:
    index = make_index()
    original = make_chunk(UUID(int=7), "malware quarantine")
    updated = make_chunk(UUID(int=7), "credential rotation")

    first = index.upsert((original,))[0]
    second = index.upsert((updated,))[0]

    assert first == second
    assert first.status is IndexStatus.SUCCEEDED
    assert first.index_version == "v1"
    assert first.bm25_key == str(original.id)
    assert not index.search("malware", scope=make_scope(), limit=5)
    assert index.search("credential", scope=make_scope(), limit=5)[0].chunk_id == updated.id


def test_scope_filters_tenant_knowledge_base_sensitivity_tags_and_unpublished() -> None:
    unpublished_version = UUID("30000000-0000-0000-0000-000000000003")
    index = make_index(
        {
            VERSION_ID: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=True),
            OTHER_VERSION_ID: Bm25ScopeMetadata(OTHER_TENANT_ID, OTHER_KB_ID, published=True),
            unpublished_version: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=False),
        }
    )
    allowed = make_chunk(UUID(int=1), "shared indicator")
    other_tenant = make_chunk(UUID(int=2), "shared indicator", version_id=OTHER_VERSION_ID)
    restricted = make_chunk(
        UUID(int=3), "shared indicator", sensitivity=SensitivityLevel.RESTRICTED
    )
    extra_tag = make_chunk(UUID(int=4), "shared indicator", tags=frozenset({"soc", "ir"}))
    unpublished = make_chunk(UUID(int=5), "shared indicator", version_id=unpublished_version)
    index.upsert((allowed, other_tenant, restricted, extra_tag, unpublished))

    assert [
        match.chunk_id for match in index.search("indicator", scope=make_scope(), limit=10)
    ] == [allowed.id]
    assert not index.search("indicator", scope=make_scope(tenant_id=OTHER_TENANT_ID), limit=10)
    assert not index.search(
        "indicator", scope=make_scope(knowledge_base_ids=frozenset({OTHER_KB_ID})), limit=10
    )


def test_delete_and_rebuild_are_deterministic_and_remove_stale_documents() -> None:
    index = make_index()
    old = make_chunk(UUID(int=9), "old forensic evidence")
    retained = make_chunk(UUID(int=8), "retained forensic evidence", version_id=OTHER_VERSION_ID)
    index.upsert((old, retained))

    index.delete_document_version(VERSION_ID)
    assert not index.search("old", scope=make_scope(), limit=10)

    index.rebuild((old,))
    assert [match.chunk_id for match in index.search("forensic", scope=make_scope(), limit=10)] == [
        old.id
    ]
    assert not index.search("retained", scope=make_scope(tenant_id=OTHER_TENANT_ID), limit=10)


def test_stable_ties_duplicate_input_empty_query_and_limit() -> None:
    index = make_index()
    higher_id = make_chunk(UUID(int=2), "same term")
    lower_id = make_chunk(UUID(int=1), "same term")
    index.upsert((higher_id, lower_id))

    assert [match.chunk_id for match in index.search("same", scope=make_scope(), limit=2)] == [
        lower_id.id,
        higher_id.id,
    ]
    assert index.search("   ", scope=make_scope(), limit=2) == ()
    assert index.search("missing", scope=make_scope(), limit=2) == ()
    with pytest.raises(Bm25IndexError, match="duplicate"):
        index.upsert((lower_id, lower_id))
    for invalid_limit in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="limit"):
            index.search("same", scope=make_scope(), limit=invalid_limit)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"k1": 0.0}, "k1"),
        ({"k1": float("inf")}, "k1"),
        ({"b": -0.01}, "b"),
        ({"b": 1.01}, "b"),
        ({"b": float("nan")}, "b"),
    ],
)
def test_numeric_parameters_are_bounded(kwargs: dict[str, float], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        DeterministicBm25Index(
            DeterministicSecurityTokenizer(),
            scope_resolver=lambda _: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=True),
            **kwargs,
        )


def test_missing_or_invalid_scope_metadata_fails_closed() -> None:
    chunk = make_chunk(UUID(int=1), "indicator")
    missing = make_index({OTHER_VERSION_ID: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=True)})
    with pytest.raises(Bm25IndexError, match="scope metadata"):
        missing.upsert((chunk,))

    with pytest.raises(TypeError, match="published"):
        Bm25ScopeMetadata(TENANT_ID, KB_ID, published=1)  # type: ignore[arg-type]


def test_bm25_enforces_index_query_and_result_resource_bounds() -> None:
    index = DeterministicBm25Index(
        DeterministicSecurityTokenizer(),
        scope_resolver=lambda _: Bm25ScopeMetadata(TENANT_ID, KB_ID, published=True),
        max_chunks=1,
        max_query_characters=4,
        max_query_terms=1,
        max_limit=1,
    )
    index.upsert((make_chunk(UUID(int=1), "term"),))
    with pytest.raises(Bm25IndexError, match="max_chunks"):
        index.upsert((make_chunk(UUID(int=2), "term"),))
    with pytest.raises(ValueError, match="characters"):
        index.search("12345", scope=make_scope(), limit=1)
    with pytest.raises(ValueError, match="terms"):
        index.search("a b", scope=make_scope(), limit=1)
    with pytest.raises(ValueError, match="between"):
        index.search("one", scope=make_scope(), limit=2)
