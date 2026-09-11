from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from shieldchain.rag.api_service import UploadedDocument
from shieldchain.rag.curated_pack import (
    CuratedPackError,
    import_curated_pack,
    load_curated_pack,
)
from shieldchain.rag.schemas import (
    CreateKnowledgeBaseRequest,
    KnowledgeBaseView,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentView,
)

PACK_ROOT = Path(__file__).parents[4] / "sample_docs" / "security_vertical"
TENANT = UUID("00000000-0000-4000-8000-000000000101")
AS_OF = date(2026, 9, 2)


def _copy_summary_pack(tmp_path: Path) -> Path:
    copied = tmp_path / "security_vertical"
    copied.mkdir()
    manifest = json.loads((PACK_ROOT / "manifest.json").read_text(encoding="utf-8"))
    manifest["documents"] = [
        document
        for document in manifest["documents"]
        if document["media_type"] == "text/markdown"
    ]
    for document in manifest["documents"]:
        shutil.copy2(PACK_ROOT / document["filename"], copied / document["filename"])
    (copied / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )
    return copied


class FakeKnowledgeService:
    def __init__(self) -> None:
        self.bases: list[KnowledgeBaseView] = []
        self.documents: dict[UUID, list[KnowledgeDocumentView]] = {}
        self.uploads: list[UploadedDocument] = []

    def list_knowledge_bases(self, *, tenant_id: UUID):
        assert tenant_id == TENANT
        return self.bases

    def create_knowledge_base(
        self, payload: CreateKnowledgeBaseRequest, *, tenant_id: UUID
    ) -> KnowledgeBaseView:
        assert tenant_id == TENANT
        now = datetime(2026, 9, 2, tzinfo=UTC)
        base = KnowledgeBaseView(
            id=uuid4(),
            name=payload.name,
            status="draft",
            default_sensitivity=payload.default_sensitivity,
            version_policy=payload.version_policy,
            created_at=now,
            updated_at=now,
        )
        self.bases.append(base)
        self.documents[base.id] = []
        return base

    def list_documents(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeDocumentListResponse:
        assert tenant_id == TENANT
        return KnowledgeDocumentListResponse(items=self.documents[knowledge_base_id])

    def upload_document(
        self, knowledge_base_id: UUID, upload: UploadedDocument, *, tenant_id: UUID
    ) -> KnowledgeDocumentView:
        assert tenant_id == TENANT
        self.uploads.append(upload)
        now = datetime(2026, 9, 2, tzinfo=UTC)
        document = KnowledgeDocumentView(
            id=uuid4(),
            knowledge_base_id=knowledge_base_id,
            original_filename=upload.filename,
            media_type=upload.media_type,
            status="published",
            current_version_id=None,
            created_at=now,
            updated_at=now,
            versions=[],
        )
        self.documents[knowledge_base_id].append(document)
        return document


def test_bundled_pack_has_required_categories_sources_and_integrity() -> None:
    pack = load_curated_pack(PACK_ROOT, as_of=AS_OF)

    assert pack.pack_id == "shieldchain-security-vertical"
    assert pack.version == "2026.09.3"
    assert "官方公开 PDF 与 HTML 快照" in pack.usage_policy
    assert {document.category for document in pack.documents} >= {
        "regulatory_policy",
        "vulnerability_intelligence",
        "attack_knowledge",
        "vendor_security_research",
    }
    assert all(document.sources for document in pack.documents)
    assert all(document.sha256 for document in pack.documents)
    assert sum(document.media_type == "application/pdf" for document in pack.documents) == 4
    assert sum(document.media_type == "text/html" for document in pack.documents) == 4
    assert all(
        document.content.startswith(b"%PDF-")
        for document in pack.documents
        if document.media_type == "application/pdf"
    )
    assert all(
        b"<html" in document.content.lower()
        for document in pack.documents
        if document.media_type == "text/html"
    )
    assert {source.source_tier for document in pack.documents for source in document.sources} == {
        "primary_authority",
        "official_vendor",
    }


def test_pack_rejects_tampered_content_before_import(tmp_path: Path) -> None:
    copied = _copy_summary_pack(tmp_path)
    target = copied / "02_0day与在野利用漏洞响应作战手册_2026-07.md"
    target.write_text(target.read_text(encoding="utf-8") + "\n篡改内容\n", encoding="utf-8")

    with pytest.raises(CuratedPackError, match="sha256"):
        load_curated_pack(copied, as_of=AS_OF)


def test_pack_fails_closed_after_any_document_review_deadline() -> None:
    with pytest.raises(CuratedPackError, match="review is overdue"):
        load_curated_pack(PACK_ROOT, as_of=date(2026, 9, 10))


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.invalid/policy",
        "https://attack.mitre.org:444/resources/versions/",
        "https://attack.mitre.org:invalid/resources/versions/",
        "https://user@attack.mitre.org/resources/versions/",
    ],
)
def test_pack_rejects_unapproved_or_ambiguous_source_urls(tmp_path: Path, url: str) -> None:
    copied = _copy_summary_pack(tmp_path)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"][0]["sources"][0]["url"] = url
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CuratedPackError, match="authoritative HTTPS source"):
        load_curated_pack(copied, as_of=AS_OF)


def test_pack_rejects_document_path_traversal(tmp_path: Path) -> None:
    copied = _copy_summary_pack(tmp_path)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"][0]["filename"] = "../outside.md"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CuratedPackError, match="direct Markdown, HTML or PDF file"):
        load_curated_pack(copied, as_of=AS_OF)


def test_import_is_idempotent_and_preserves_curated_access_tags() -> None:
    service = FakeKnowledgeService()

    first = import_curated_pack(service, PACK_ROOT, tenant_id=TENANT, as_of=AS_OF)
    second = import_curated_pack(service, PACK_ROOT, tenant_id=TENANT, as_of=AS_OF)

    assert len(first.imported) == 13
    assert first.skipped == ()
    assert second.imported == ()
    assert second.skipped == tuple(document.filename for document in first.pack.documents)
    assert len(service.bases) == 1
    assert len(service.uploads) == 13
    assert sum(upload.media_type == "application/pdf" for upload in service.uploads) == 4
    assert sum(upload.media_type == "text/html" for upload in service.uploads) == 4
    assert all("security-vertical" in upload.permission_tags for upload in service.uploads)
    assert all(upload.verified_at == first.pack.verified_at for upload in service.uploads)
    assert all(upload.review_due_at is not None for upload in service.uploads)
    assert all(upload.source_tiers for upload in service.uploads)
    assert all(upload.source_urls for upload in service.uploads)
    assert {tag for upload in service.uploads for tag in upload.permission_tags} >= {
        "source-primary-authority",
        "source-official-vendor",
    }
