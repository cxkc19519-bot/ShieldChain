"""Bounded, offline validation for untrusted knowledge-document uploads."""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol
from xml.etree import ElementTree

from shieldchain.core.config import Settings
from shieldchain.rag.ports import StoredContent

_MEBIBYTE = 1024 * 1024
_MAX_UPLOAD_BYTES = 25 * _MEBIBYTE
_MAX_EXPANDED_BYTES = 100 * _MEBIBYTE
_MAX_COMPRESSION_RATIO = 100
_MAX_EXTRACTED_CHARACTERS = 2_000_000
_MAX_ZIP_MEMBERS = 10_000
_MAX_STREAM_CHUNKS = 262_144
_STREAM_CHUNK_SIZE = 64 * 1024
_MAX_OOXML_MANIFEST_BYTES = _MEBIBYTE
_CENTRAL_DIRECTORY_HEADER = struct.Struct("<4s6H3L5H2L")

_MEDIA_TYPES_BY_EXTENSION = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".html": "text/html",
    ".csv": "text/csv",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
_TEXT_EXTENSIONS = frozenset({".md", ".txt", ".html", ".csv"})
_ZIP_EXTENSIONS = frozenset({".docx", ".xlsx"})
_OOXML_MAIN_PARTS = {
    ".docx": (
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
    ".xlsx": (
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ),
}


class UnsafeDocumentError(ValueError):
    """A document failed a safe intake boundary; details are deliberately non-sensitive."""


class _StreamInputError(Exception):
    """Private marker for safe stream-validation failures."""


class ContentStoreWriter(Protocol):
    def put(self, content: Iterable[bytes], *, media_type: str) -> StoredContent: ...


@dataclass(frozen=True, slots=True)
class IntakeLimits:
    max_upload_bytes: int = _MAX_UPLOAD_BYTES
    max_expanded_bytes: int = _MAX_EXPANDED_BYTES
    max_compression_ratio: int = _MAX_COMPRESSION_RATIO
    max_extracted_characters: int = _MAX_EXTRACTED_CHARACTERS
    max_zip_members: int = _MAX_ZIP_MEMBERS
    max_stream_chunks: int = 100_000

    def __post_init__(self) -> None:
        for name, hard_cap in (
            ("max_upload_bytes", _MAX_UPLOAD_BYTES),
            ("max_expanded_bytes", _MAX_EXPANDED_BYTES),
            ("max_compression_ratio", _MAX_COMPRESSION_RATIO),
            ("max_extracted_characters", _MAX_EXTRACTED_CHARACTERS),
            ("max_zip_members", _MAX_ZIP_MEMBERS),
            ("max_stream_chunks", _MAX_STREAM_CHUNKS),
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= hard_cap:
                raise ValueError(f"{name} must be within its hard safety bound")

    @classmethod
    def from_settings(cls, settings: Settings) -> IntakeLimits:
        return cls(
            max_upload_bytes=settings.rag_max_upload_bytes,
            max_expanded_bytes=settings.rag_max_expanded_bytes,
            max_compression_ratio=settings.rag_max_compression_ratio,
            max_extracted_characters=settings.rag_max_extracted_characters,
            max_zip_members=settings.rag_max_zip_members,
            max_stream_chunks=settings.rag_max_upload_chunks,
        )


@dataclass(frozen=True, slots=True)
class IntakeRequest:
    """Upload-only request. URLs and local paths are rejected before any read occurs."""

    filename: str
    media_type: str
    content: Iterable[bytes]
    remote_url: str | None = None
    local_path: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.filename, str) or not self.filename.strip():
            raise UnsafeDocumentError("invalid document upload")
        if not isinstance(self.media_type, str) or not self.media_type.strip():
            raise UnsafeDocumentError("invalid document upload")
        if self.remote_url is not None or self.local_path is not None:
            raise UnsafeDocumentError("document source is not accepted")
        if "/" in self.filename or "\\" in self.filename or ":" in self.filename:
            raise UnsafeDocumentError("document source is not accepted")


class SecureIntake:
    """Validate untrusted streams before delegating a clean stream to the content store."""

    def __init__(self, store: ContentStoreWriter, limits: IntakeLimits | None = None) -> None:
        self._store = store
        self._limits = limits or IntakeLimits()

    @classmethod
    def from_settings(cls, store: ContentStoreWriter, settings: Settings) -> SecureIntake:
        return cls(store, IntakeLimits.from_settings(settings))

    def accept(self, request: IntakeRequest) -> StoredContent:
        extension, expected_media_type = _validated_extension_and_media_type(request)
        with tempfile.SpooledTemporaryFile(max_size=_MEBIBYTE, mode="w+b") as spool:
            digest, size_bytes, sample = _copy_bounded_stream(request.content, spool, self._limits)
            detected_media_type = _sniff_media_type(sample)
            _validate_detected_media_type(extension, expected_media_type, detected_media_type)
            if extension in _ZIP_EXTENSIONS:
                _validate_zip_container(spool, extension, self._limits)
            spool.seek(0)
            stored = self._store.put(_read_chunks(spool), media_type=expected_media_type)
        if not isinstance(stored, StoredContent):
            raise UnsafeDocumentError("content store did not confirm document storage")
        if stored.size_bytes != size_bytes or stored.content_sha256 != digest:
            raise UnsafeDocumentError("content store integrity mismatch")
        return stored


def _validated_extension_and_media_type(request: IntakeRequest) -> tuple[str, str]:
    filename = request.filename.strip()
    extension = os.path.splitext(filename)[1].lower()
    expected = _MEDIA_TYPES_BY_EXTENSION.get(extension)
    declared = request.media_type.split(";", 1)[0].strip().lower()
    if expected is None or declared != expected:
        raise UnsafeDocumentError("unsupported document type")
    return extension, expected


def _copy_bounded_stream(
    content: Iterable[bytes], spool: tempfile.SpooledTemporaryFile[bytes], limits: IntakeLimits
) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    size_bytes = 0
    sample = bytearray()
    chunk_count = 0
    try:
        iterator = iter(content)
        for chunk in iterator:
            chunk_count += 1
            if chunk_count > limits.max_stream_chunks:
                raise _StreamInputError("document has too many stream chunks")
            if not isinstance(chunk, bytes | bytearray | memoryview):
                raise _StreamInputError("invalid document stream")
            block = bytes(chunk)
            if not block:
                raise _StreamInputError("empty document stream chunk")
            size_bytes += len(block)
            if size_bytes > limits.max_upload_bytes:
                raise _StreamInputError("document exceeds size limit")
            digest.update(block)
            spool.write(block)
            if len(sample) < _STREAM_CHUNK_SIZE:
                sample.extend(block[: _STREAM_CHUNK_SIZE - len(sample)])
    except _StreamInputError as error:
        raise UnsafeDocumentError(str(error)) from None
    except Exception:
        raise UnsafeDocumentError("document stream failed") from None
    if size_bytes == 0:
        raise UnsafeDocumentError("empty document is not accepted")
    return digest.hexdigest(), size_bytes, bytes(sample)


def _sniff_media_type(sample: bytes) -> str:
    if sample.startswith(b"%PDF-"):
        return "application/pdf"
    if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if b"\x00" in sample:
        return "application/octet-stream"
    return "text/plain"


def _validate_detected_media_type(
    extension: str, expected_media_type: str, detected_media_type: str
) -> None:
    if extension in _ZIP_EXTENSIONS:
        if detected_media_type != "application/zip":
            raise UnsafeDocumentError("document media type does not match content")
        return
    if extension == ".pdf":
        if detected_media_type != expected_media_type:
            raise UnsafeDocumentError("document media type does not match content")
        return
    if extension in _TEXT_EXTENSIONS and detected_media_type != "text/plain":
        raise UnsafeDocumentError("document media type does not match content")


def _validate_zip_container(
    spool: tempfile.SpooledTemporaryFile[bytes], extension: str, limits: IntakeLimits
) -> None:
    try:
        _preflight_zip_metadata(spool, limits)
        spool.seek(0)
        with zipfile.ZipFile(spool) as archive:
            members = archive.infolist()
            if len(members) > limits.max_zip_members:
                raise UnsafeDocumentError("office document has too many members")
            for member in members:
                _validate_zip_member_path(member.filename)
            _validate_ooxml_type(archive, members, extension)
    except (
        ElementTree.ParseError,
        OSError,
        struct.error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        raise UnsafeDocumentError("invalid office document container") from None
    total_uncompressed = 0
    for member in members:
        if member.is_dir():
            continue
        total_uncompressed += member.file_size
        if total_uncompressed > limits.max_expanded_bytes:
            raise UnsafeDocumentError("office document expansion exceeds limit")
        compressed_size = max(member.compress_size, 1)
        if member.file_size / compressed_size > limits.max_compression_ratio:
            raise UnsafeDocumentError("office document compression ratio exceeds limit")


def _preflight_zip_metadata(
    spool: tempfile.SpooledTemporaryFile[bytes], limits: IntakeLimits
) -> None:
    spool.seek(0, os.SEEK_END)
    size_bytes = spool.tell()
    tail_size = min(size_bytes, 65_557)
    spool.seek(size_bytes - tail_size)
    tail = spool.read(tail_size)
    eocd_offset = tail.rfind(b"PK\x05\x06")
    if eocd_offset < 0 or eocd_offset + 22 > len(tail):
        raise UnsafeDocumentError("invalid office document container")
    (
        _,
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        comment,
    ) = struct.unpack_from("<4s4H2LH", tail, eocd_offset)
    if (
        eocd_offset + 22 + comment != len(tail)
        or disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
        or b"PK\x06\x06" in tail
        or b"PK\x06\x07" in tail
        or total_entries > limits.max_zip_members
    ):
        raise UnsafeDocumentError("unsupported office document container")
    eocd_absolute_offset = size_bytes - tail_size + eocd_offset
    directory_end = directory_offset + directory_size
    if directory_end > eocd_absolute_offset or directory_size > size_bytes:
        raise UnsafeDocumentError("invalid office document container")
    spool.seek(directory_offset)
    directory = spool.read(directory_size)
    if len(directory) != directory_size:
        raise UnsafeDocumentError("invalid office document container")
    cursor = 0
    member_count = 0
    while cursor < directory_size:
        if cursor + _CENTRAL_DIRECTORY_HEADER.size > directory_size:
            raise UnsafeDocumentError("invalid office document container")
        (
            signature,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            compressed_size,
            uncompressed_size,
            name_size,
            extra_size,
            comment_size,
            disk_start,
            _,
            _,
            local_offset,
        ) = _CENTRAL_DIRECTORY_HEADER.unpack_from(directory, cursor)
        record_size = _CENTRAL_DIRECTORY_HEADER.size + name_size + extra_size + comment_size
        if signature != b"PK\x01\x02" or cursor + record_size > directory_size:
            raise UnsafeDocumentError("invalid office document container")
        extra_start = cursor + _CENTRAL_DIRECTORY_HEADER.size + name_size
        extra = directory[extra_start : extra_start + extra_size]
        if (
            compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
            or disk_start == 0xFFFF
            or _contains_zip64_extra(extra)
        ):
            raise UnsafeDocumentError("unsupported office document container")
        cursor += record_size
        member_count += 1
    if cursor != directory_size or member_count != total_entries:
        raise UnsafeDocumentError("invalid office document container")


def _contains_zip64_extra(extra: bytes) -> bool:
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise UnsafeDocumentError("invalid office document container")
        header_id, size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if cursor + size > len(extra):
            raise UnsafeDocumentError("invalid office document container")
        if header_id == 0x0001:
            return True
        cursor += size
    return False


def _validate_ooxml_type(
    archive: zipfile.ZipFile, members: list[zipfile.ZipInfo], extension: str
) -> None:
    required_part, required_content_type = _OOXML_MAIN_PARTS[extension]
    names = [member.filename for member in members]
    if names.count("[Content_Types].xml") != 1 or names.count(required_part) != 1:
        raise UnsafeDocumentError("invalid office document type")
    manifest = archive.getinfo("[Content_Types].xml")
    if manifest.is_dir() or manifest.file_size > _MAX_OOXML_MANIFEST_BYTES:
        raise UnsafeDocumentError("invalid office document type")
    with archive.open(manifest) as source:
        document = source.read(_MAX_OOXML_MANIFEST_BYTES + 1)
    if len(document) > _MAX_OOXML_MANIFEST_BYTES:
        raise UnsafeDocumentError("invalid office document type")
    root = ElementTree.fromstring(document)
    required_name = f"/{required_part}"
    if not any(
        element.tag.endswith("Override")
        and element.attrib.get("PartName") == required_name
        and element.attrib.get("ContentType") == required_content_type
        for element in root
    ):
        raise UnsafeDocumentError("invalid office document type")


def _validate_zip_member_path(name: str) -> None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or ":" in normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and path.parts[0].endswith(":"))
    ):
        raise UnsafeDocumentError("unsafe office document member")


def _read_chunks(spool: tempfile.SpooledTemporaryFile[bytes]) -> Iterator[bytes]:
    while block := spool.read(_STREAM_CHUNK_SIZE):
        yield block
