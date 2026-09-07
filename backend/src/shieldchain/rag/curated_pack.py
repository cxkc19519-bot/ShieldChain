"""Validation and idempotent import for the bundled security knowledge pack."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID

from shieldchain.rag.api_service import KnowledgeApiService, UploadedDocument
from shieldchain.rag.schemas import CreateKnowledgeBaseRequest, Sensitivity

_MANIFEST_NAME = "manifest.json"
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_CURATED_DOCUMENT_BYTES = 32 * 1024 * 1024
_MEDIA_TYPES = {
    ".html": "text/html",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
}
_REQUIRED_CATEGORIES = frozenset(
    {
        "regulatory_policy",
        "vulnerability_intelligence",
        "attack_knowledge",
        "vendor_security_research",
    }
)
_ALLOWED_CATEGORIES = _REQUIRED_CATEGORIES | {"maintenance_policy"}
_ALLOWED_SOURCE_HOSTS = frozenset(
    {
        "attack.mitre.org",
        "cac.gov.cn",
        "cisa.gov",
        "github.com",
        "download.sangfor.com.cn",
        "sangfor.com.cn",
        "sec.sangfor.com.cn",
        "support.sangfor.com.cn",
        "www.cac.gov.cn",
        "www.cisa.gov",
        "www.sangfor.com.cn",
    }
)

SourceTier = Literal["primary_authority", "official_vendor"]


class CuratedPackError(ValueError):
    """The bundled pack failed a deterministic trust or integrity check."""


@dataclass(frozen=True, slots=True)
class CuratedSource:
    publisher: str
    source_tier: SourceTier
    url: str
    published_at: date | None
    accessed_at: date


@dataclass(frozen=True, slots=True)
class CuratedDocument:
    filename: str
    title: str
    category: str
    media_type: str
    sha256: str
    sensitivity: Sensitivity
    permission_tags: tuple[str, ...]
    reviewed_at: date
    review_due_at: date
    reviewer_role: str
    sources: tuple[CuratedSource, ...]
    content: bytes


@dataclass(frozen=True, slots=True)
class CuratedPack:
    pack_id: str
    name: str
    version: str
    usage_policy: str
    verified_at: date
    review_due_at: date
    documents: tuple[CuratedDocument, ...]


@dataclass(frozen=True, slots=True)
class CuratedPackImportResult:
    pack: CuratedPack
    knowledge_base_id: UUID
    imported: tuple[str, ...]
    skipped: tuple[str, ...]


def _today() -> date:
    return date.today()


def _mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CuratedPackError(f"{field} must be an object")
    return value


def _strict_keys(
    value: Mapping[str, Any], *, required: set[str], field: str, optional: set[str] | None = None
) -> None:
    optional = optional or set()
    keys = set(value)
    if not required <= keys or keys - required - optional:
        raise CuratedPackError(f"{field} has an invalid schema")


def _text(value: object, *, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CuratedPackError(f"{field} must be non-blank text")
    return value.strip()


def _date(value: object, *, field: str, optional: bool = False) -> date | None:
    if value is None and optional:
        return None
    text = _text(value, field=field, maximum=10)
    try:
        return date.fromisoformat(text)
    except ValueError as error:
        raise CuratedPackError(f"{field} must be an ISO date") from error


def _source(value: object, *, field: str, verified_at: date) -> CuratedSource:
    item = _mapping(value, field=field)
    _strict_keys(
        item,
        required={"publisher", "source_tier", "url", "published_at", "accessed_at"},
        field=field,
    )
    source_tier = _text(item["source_tier"], field=f"{field}.source_tier", maximum=32)
    if source_tier not in {"primary_authority", "official_vendor"}:
        raise CuratedPackError(f"{field}.source_tier is invalid")
    url = _text(item["url"], field=f"{field}.url", maximum=2_048)
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise CuratedPackError(
            f"{field}.url is not an approved authoritative HTTPS source"
        ) from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_SOURCE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise CuratedPackError(f"{field}.url is not an approved authoritative HTTPS source")
    accessed_at = _date(item["accessed_at"], field=f"{field}.accessed_at")
    if accessed_at is None or accessed_at > verified_at:
        raise CuratedPackError(f"{field}.accessed_at must not be after pack verification")
    return CuratedSource(
        publisher=_text(item["publisher"], field=f"{field}.publisher", maximum=200),
        source_tier=cast(SourceTier, source_tier),
        url=url,
        published_at=_date(item["published_at"], field=f"{field}.published_at", optional=True),
        accessed_at=accessed_at,
    )


def _document(
    value: object,
    *,
    field: str,
    root: Path,
    verified_at: date,
    pack_review_due_at: date,
) -> CuratedDocument:
    item = _mapping(value, field=field)
    _strict_keys(
        item,
        required={
            "filename",
            "title",
            "category",
            "media_type",
            "sha256",
            "sensitivity",
            "permission_tags",
            "reviewed_at",
            "review_due_at",
            "reviewer_role",
            "sources",
        },
        field=field,
    )
    filename = _text(item["filename"], field=f"{field}.filename", maximum=240)
    suffix = Path(filename).suffix.casefold()
    if Path(filename).name != filename or suffix not in _MEDIA_TYPES:
        raise CuratedPackError(
            f"{field}.filename must be a direct Markdown, HTML or PDF file"
        )
    path = (root / filename).resolve(strict=True)
    if path.parent != root or path.is_symlink():
        raise CuratedPackError(f"{field}.filename escapes the curated pack root")
    content = path.read_bytes()
    if not content or len(content) > _MAX_CURATED_DOCUMENT_BYTES:
        raise CuratedPackError(f"{field} has an invalid document size")
    media_type = _text(item["media_type"], field=f"{field}.media_type", maximum=100)
    if media_type != _MEDIA_TYPES[suffix]:
        raise CuratedPackError(f"{field}.media_type does not match the filename")
    expected_sha256 = _text(item["sha256"], field=f"{field}.sha256", maximum=64).casefold()
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise CuratedPackError(f"{field}.sha256 is invalid")
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise CuratedPackError(f"{field}.sha256 does not match the document")
    title = _text(item["title"], field=f"{field}.title", maximum=240)
    decoded: str | None = None
    if suffix == ".md":
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CuratedPackError(f"{field} is not UTF-8") from error
        first_line = next(
            (line.strip().lstrip("\ufeff") for line in decoded.splitlines() if line.strip()), ""
        )
        if first_line != f"# {title}":
            raise CuratedPackError(f"{field}.title does not match the first heading")
    elif suffix == ".html":
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CuratedPackError(f"{field} is not UTF-8") from error
        normalized = decoded.casefold()
        if "<html" not in normalized or "<title" not in normalized or "</html>" not in normalized:
            raise CuratedPackError(f"{field} is not structurally recognizable HTML")
    elif (
        not content.startswith(b"%PDF-")
        or b"startxref" not in content
        or b"%%EOF" not in content
    ):
        raise CuratedPackError(f"{field} is not a structurally recognizable PDF")
    category = _text(item["category"], field=f"{field}.category", maximum=64)
    if category not in _ALLOWED_CATEGORIES:
        raise CuratedPackError(f"{field}.category is unsupported")
    sensitivity = _text(item["sensitivity"], field=f"{field}.sensitivity", maximum=20)
    if sensitivity not in {"public", "internal", "confidential", "restricted"}:
        raise CuratedPackError(f"{field}.sensitivity is invalid")
    raw_tags = item["permission_tags"]
    if not isinstance(raw_tags, list) or not 1 <= len(raw_tags) <= 16:
        raise CuratedPackError(f"{field}.permission_tags is invalid")
    tags = tuple(_text(tag, field=f"{field}.permission_tags", maximum=64) for tag in raw_tags)
    if len(set(tags)) != len(tags):
        raise CuratedPackError(f"{field}.permission_tags must be unique")
    reviewed_at = _date(item["reviewed_at"], field=f"{field}.reviewed_at")
    review_due_at = _date(item["review_due_at"], field=f"{field}.review_due_at")
    if (
        reviewed_at is None
        or review_due_at is None
        or reviewed_at > verified_at
        or review_due_at < verified_at
        or review_due_at > pack_review_due_at
    ):
        raise CuratedPackError(f"{field} has an invalid review window")
    raw_sources = item["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise CuratedPackError(f"{field}.sources must not be empty")
    sources = tuple(
        _source(source, field=f"{field}.sources[{index}]", verified_at=verified_at)
        for index, source in enumerate(raw_sources)
    )
    if suffix == ".md" and decoded is not None and any(
        source.url not in decoded for source in sources
    ):
        raise CuratedPackError(f"{field} must include every declared source URL")
    return CuratedDocument(
        filename=filename,
        title=title,
        category=category,
        media_type=media_type,
        sha256=expected_sha256,
        sensitivity=cast(Sensitivity, sensitivity),
        permission_tags=tags,
        reviewed_at=reviewed_at,
        review_due_at=review_due_at,
        reviewer_role=_text(item["reviewer_role"], field=f"{field}.reviewer_role", maximum=100),
        sources=sources,
        content=content,
    )


def load_curated_pack(root: str | Path, *, as_of: date | None = None) -> CuratedPack:
    """Load the strict manifest and verify every bundled document before use."""

    selected_root = Path(root).expanduser().resolve(strict=True)
    if not selected_root.is_dir() or selected_root.is_symlink():
        raise CuratedPackError("curated pack root must be a real directory")
    manifest_path = (selected_root / _MANIFEST_NAME).resolve(strict=True)
    if manifest_path.parent != selected_root or manifest_path.is_symlink():
        raise CuratedPackError("curated pack manifest escapes the pack root")
    raw = manifest_path.read_bytes()
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise CuratedPackError("curated pack manifest size is invalid")
    try:
        payload = _mapping(json.loads(raw), field="manifest")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CuratedPackError("curated pack manifest is invalid JSON") from error
    _strict_keys(
        payload,
        required={
            "schema_version",
            "pack_id",
            "name",
            "version",
            "usage_policy",
            "verified_at",
            "review_due_at",
            "documents",
        },
        field="manifest",
    )
    if payload["schema_version"] != "1.0":
        raise CuratedPackError("curated pack schema version is unsupported")
    verified_at = _date(payload["verified_at"], field="manifest.verified_at")
    review_due_at = _date(payload["review_due_at"], field="manifest.review_due_at")
    if verified_at is None or review_due_at is None or review_due_at < verified_at:
        raise CuratedPackError("curated pack review window is invalid")
    today = as_of or _today()
    if verified_at > today:
        raise CuratedPackError("curated pack verification date is in the future")
    if review_due_at < today:
        raise CuratedPackError("curated pack review is overdue")
    raw_documents = payload["documents"]
    if not isinstance(raw_documents, list) or not raw_documents:
        raise CuratedPackError("curated pack documents must not be empty")
    documents = tuple(
        _document(
            value,
            field=f"manifest.documents[{index}]",
            root=selected_root,
            verified_at=verified_at,
            pack_review_due_at=review_due_at,
        )
        for index, value in enumerate(raw_documents)
    )
    if any(document.review_due_at < today for document in documents):
        raise CuratedPackError("curated pack contains a document whose review is overdue")
    filenames = [document.filename for document in documents]
    if len(set(filenames)) != len(filenames):
        raise CuratedPackError("curated pack document filenames must be unique")
    categories = {document.category for document in documents}
    if not _REQUIRED_CATEGORIES <= categories:
        raise CuratedPackError("curated pack is missing a required security category")
    return CuratedPack(
        pack_id=_text(payload["pack_id"], field="manifest.pack_id", maximum=128),
        name=_text(payload["name"], field="manifest.name", maximum=200),
        version=_text(payload["version"], field="manifest.version", maximum=64),
        usage_policy=_text(
            payload["usage_policy"], field="manifest.usage_policy", maximum=1_000
        ),
        verified_at=verified_at,
        review_due_at=review_due_at,
        documents=documents,
    )


def import_curated_pack(
    service: KnowledgeApiService,
    root: str | Path,
    *,
    tenant_id: UUID,
    as_of: date | None = None,
) -> CuratedPackImportResult:
    """Validate first, then import missing versioned files into one managed base."""

    pack = load_curated_pack(root, as_of=as_of)
    matching_bases = [
        base
        for base in service.list_knowledge_bases(tenant_id=tenant_id)
        if base.name == pack.name
    ]
    if len(matching_bases) > 1:
        raise CuratedPackError("multiple knowledge bases match the curated pack name")
    base = (
        matching_bases[0]
        if matching_bases
        else service.create_knowledge_base(
            CreateKnowledgeBaseRequest(
                name=pack.name,
                default_sensitivity="internal",
                version_policy="immutable",
            ),
            tenant_id=tenant_id,
        )
    )
    existing = {
        document.original_filename
        for document in service.list_documents(base.id, tenant_id=tenant_id).items
    }
    imported: list[str] = []
    skipped: list[str] = []
    for document in pack.documents:
        if document.filename in existing:
            skipped.append(document.filename)
            continue
        service.upload_document(
            base.id,
            UploadedDocument(
                filename=document.filename,
                media_type=document.media_type,
                content=document.content,
                sensitivity=document.sensitivity,
                permission_tags=document.permission_tags,
                verified_at=pack.verified_at,
                review_due_at=document.review_due_at,
                source_tiers=tuple(
                    dict.fromkeys(source.source_tier for source in document.sources)
                ),
                source_urls=tuple(source.url for source in document.sources),
            ),
            tenant_id=tenant_id,
        )
        imported.append(document.filename)
    return CuratedPackImportResult(
        pack=pack,
        knowledge_base_id=base.id,
        imported=tuple(imported),
        skipped=tuple(skipped),
    )
