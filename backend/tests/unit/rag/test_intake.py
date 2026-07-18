from __future__ import annotations

import io
import struct
import zipfile

import pytest

from shieldchain.core.config import Settings
from shieldchain.rag.intake import (
    IntakeLimits,
    IntakeRequest,
    SecureIntake,
    UnsafeDocumentError,
)
from shieldchain.rag.ports import ContentStoreError, StoredContent


class RecordingStore:
    def __init__(self) -> None:
        self.payloads: list[tuple[bytes, str]] = []

    def put(self, content, *, media_type: str):
        payload = b"".join(content)
        self.payloads.append((payload, media_type))
        import hashlib

        return StoredContent(
            "knowledge/00000000-0000-0000-0000-000000000001",
            hashlib.sha256(payload).hexdigest(),
            len(payload),
            media_type,
        )


def zip_payload(*, name: str = "word/document.xml", data: bytes = b"<document/>") -> bytes:
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return result.getvalue()


def ooxml_payload(kind: str, *, extra_name: str | None = None) -> bytes:
    required_part = "word/document.xml" if kind == "docx" else "xl/workbook.xml"
    content_type = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
        if kind == "docx"
        else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    )
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            (
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                f'<Override PartName="/{required_part}" ContentType="{content_type}"/>'
                "</Types>"
            ),
        )
        archive.writestr(required_part, b"<root/>")
        if extra_name is not None:
            archive.writestr(extra_name, b"<root/>")
    return result.getvalue()


def zip64_payload(kind: str) -> bytes:
    payload = ooxml_payload(kind)
    eocd_offset = payload.rfind(b"PK\x05\x06")
    _, _, _, _, count, directory_size, directory_offset, comment_length = struct.unpack_from(
        "<4s4H2LH", payload, eocd_offset
    )
    assert comment_length == 0
    zip64_record_offset = eocd_offset
    zip64_record = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        directory_size,
        directory_offset,
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, zip64_record_offset, 1)
    zip64_eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    result = payload[:eocd_offset] + zip64_record + locator + zip64_eocd
    assert zipfile.ZipFile(io.BytesIO(result)).namelist()
    return result


def test_streams_sha_and_size_then_passes_only_validated_content_to_store() -> None:
    store = RecordingStore()
    intake = SecureIntake(store, IntakeLimits(max_upload_bytes=16))

    result = intake.accept(IntakeRequest("notes.md", "text/markdown", (b"safe ", b"content")))

    assert result.size_bytes == 12
    assert (
        result.content_sha256 == "99d5e9e0dc50e56ad7c9ecd0a0feea56fcb81d0ba7a27b7fa1e971c5dadd452b"
    )
    assert store.payloads == [(b"safe content", "text/markdown")]


@pytest.mark.parametrize(
    ("filename", "media_type", "payload"),
    [
        ("notes.exe", "application/octet-stream", b"MZ"),
        ("notes.pdf", "application/pdf", b"not a pdf"),
        ("notes.txt", "application/pdf", b"plain text"),
        (
            "notes.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"not zip",
        ),
    ],
)
def test_rejects_disallowed_extensions_and_inconsistent_declared_or_sniffed_media_type(
    filename: str, media_type: str, payload: bytes
) -> None:
    store = RecordingStore()

    with pytest.raises(UnsafeDocumentError):
        SecureIntake(store).accept(IntakeRequest(filename, media_type, [payload]))

    assert store.payloads == []


def test_rejects_remote_urls_local_paths_and_oversized_streams_without_store_write() -> None:
    store = RecordingStore()
    intake = SecureIntake(store, IntakeLimits(max_upload_bytes=3))

    for make_request in (
        lambda: IntakeRequest("https://example.invalid/file.txt", "text/plain", [b"x"]),
        lambda: IntakeRequest(
            "notes.txt", "text/plain", [b"x"], remote_url="https://example.invalid"
        ),
        lambda: IntakeRequest("notes.txt", "text/plain", [b"x"], local_path="C:\\secret.txt"),
        lambda: IntakeRequest("notes.txt", "text/plain", [b"toolong"]),
    ):
        with pytest.raises(UnsafeDocumentError):
            intake.accept(make_request())

    assert store.payloads == []


def test_zip_container_checks_member_path_count_size_and_compression_ratio_without_extracting() -> (
    None
):
    store = RecordingStore()
    limits = IntakeLimits(
        max_upload_bytes=1_000_000,
        max_expanded_bytes=100,
        max_compression_ratio=2,
        max_zip_members=1,
    )
    intake = SecureIntake(store, limits)

    for payload in (
        zip_payload(name="../escape.xml"),
        zip_payload(data=b"x" * 200),
        zip_payload(data=b"x" * 80),
        _two_member_zip(),
    ):
        with pytest.raises(UnsafeDocumentError):
            intake.accept(
                IntakeRequest(
                    "book.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    [payload],
                )
            )

    assert store.payloads == []


@pytest.mark.parametrize(
    ("filename", "media_type", "kind"),
    [
        (
            "guide.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx",
        ),
        (
            "table.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
        ),
    ],
)
def test_accepts_only_matching_ooxml_containers(filename: str, media_type: str, kind: str) -> None:
    store = RecordingStore()

    SecureIntake(store).accept(IntakeRequest(filename, media_type, [ooxml_payload(kind)]))

    assert len(store.payloads) == 1


@pytest.mark.parametrize(
    ("filename", "media_type", "payload"),
    [
        (
            "guide.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ooxml_payload("xlsx"),
        ),
        (
            "table.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ooxml_payload("docx"),
        ),
        (
            "guide.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            zip_payload(),
        ),
        (
            "guide.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            zip64_payload("docx"),
        ),
        (
            "guide.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ooxml_payload("docx", extra_name="C:evil.xml"),
        ),
    ],
)
def test_rejects_generic_zip_wrong_ooxml_and_zip64_markers(
    filename: str, media_type: str, payload: bytes
) -> None:
    with pytest.raises(UnsafeDocumentError) as error:
        SecureIntake(RecordingStore()).accept(IntakeRequest(filename, media_type, [payload]))

    assert error.value.__cause__ is None


def test_rejects_eocd_count_smaller_than_actual_central_directory() -> None:
    payload = bytearray(ooxml_payload("docx", extra_name="extra.xml"))
    eocd_offset = payload.rfind(b"PK\x05\x06")
    struct.pack_into("<H", payload, eocd_offset + 8, 2)
    struct.pack_into("<H", payload, eocd_offset + 10, 2)

    with pytest.raises(UnsafeDocumentError):
        SecureIntake(RecordingStore()).accept(
            IntakeRequest(
                "guide.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                [bytes(payload)],
            )
        )


@pytest.mark.parametrize("error", [UnsafeDocumentError("secret"), ContentStoreError("secret")])
def test_iterable_errors_are_reclassified_without_sensitive_cause(error: Exception) -> None:
    def failing_stream():
        raise error
        yield b"unreachable"

    with pytest.raises(UnsafeDocumentError) as received:
        SecureIntake(RecordingStore()).accept(
            IntakeRequest("notes.txt", "text/plain", failing_stream())
        )
    assert received.value.__cause__ is None
    assert "secret" not in str(received.value)


def test_rejects_empty_or_excessive_stream_chunks_before_store_write() -> None:
    store = RecordingStore()
    intake = SecureIntake(store, IntakeLimits(max_upload_bytes=20, max_stream_chunks=3))

    def infinite_empty_chunks():
        while True:
            yield b""

    for payload in (infinite_empty_chunks(), [b"a", b"b", b"c", b"d"]):
        with pytest.raises(UnsafeDocumentError):
            intake.accept(IntakeRequest("notes.txt", "text/plain", payload))

    assert store.payloads == []


def _two_member_zip() -> bytes:
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("xl/workbook.xml", b"a")
        archive.writestr("xl/worksheets/sheet1.xml", b"b")
    return result.getvalue()


def test_limits_are_taken_from_settings_and_have_non_bypassable_hard_caps() -> None:
    settings = Settings(_env_file=None)
    assert IntakeLimits.from_settings(settings).max_upload_bytes == 25 * 1024 * 1024
    assert IntakeLimits.from_settings(settings).max_expanded_bytes == 100 * 1024 * 1024
    with pytest.raises(ValueError):
        Settings(_env_file=None, rag_max_upload_bytes=25 * 1024 * 1024 + 1)
    with pytest.raises(ValueError):
        Settings(_env_file=None, rag_max_upload_chunks=262_145)
