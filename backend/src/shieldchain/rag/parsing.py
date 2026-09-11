"""A bounded, offline parsing adapter for the seven Phase 3 document types.

Every parse runs in a fresh ``spawn`` worker. This avoids inheriting parent state on Windows and
lets the parent terminate parser-library hangs without receiving a large result over IPC.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shieldchain.core.config import Settings
from shieldchain.rag.domain import ParsingStatus
from shieldchain.rag.parsers.deterministic import (
    ParseBudgetExceeded,
    ParserBudget,
    ParseUnsupported,
    parse_document,
)
from shieldchain.rag.ports import (
    ParsedContent,
    ParsedElement,
    ParserError,
    UnsupportedDocumentError,
)

_MEBIBYTE = 1024 * 1024
_MAX_RESULT_BYTES = 16 * _MEBIBYTE
_MEDIA_TYPES = {
    ".pdf": ("application/pdf", "pdf"),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    ".md": ("text/markdown", "md"),
    ".txt": ("text/plain", "txt"),
    ".html": ("text/html", "html"),
    ".csv": ("text/csv", "csv"),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
}


class ParsingTimeoutError(ParserError):
    """The worker exceeded the parent-owned parse deadline."""


class ParsingBudgetError(ParserError):
    """The document exceeded a configured parser resource budget."""


class DocumentParsingError(ParserError):
    """A parser failed without exposing untrusted document details."""


@dataclass(frozen=True, slots=True)
class ParsingLimits:
    max_input_bytes: int = 25 * _MEBIBYTE
    max_characters: int = 2_000_000
    max_pages: int = 10_000
    max_rows: int = 200_000
    max_cells: int = 1_000_000
    max_zip_members: int = 10_000
    max_expanded_bytes: int = 100 * _MEBIBYTE
    max_compression_ratio: int = 100
    max_elements: int = 100_000
    max_estimated_result_bytes: int = _MAX_RESULT_BYTES
    max_result_bytes: int = _MAX_RESULT_BYTES
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        integer_limits = {
            "max_input_bytes": (self.max_input_bytes, 25 * _MEBIBYTE),
            "max_characters": (self.max_characters, 2_000_000),
            "max_pages": (self.max_pages, 10_000),
            "max_rows": (self.max_rows, 200_000),
            "max_cells": (self.max_cells, 1_000_000),
            "max_zip_members": (self.max_zip_members, 10_000),
            "max_expanded_bytes": (self.max_expanded_bytes, 100 * _MEBIBYTE),
            "max_compression_ratio": (self.max_compression_ratio, 100),
            "max_elements": (self.max_elements, 100_000),
            "max_estimated_result_bytes": (
                self.max_estimated_result_bytes,
                _MAX_RESULT_BYTES,
            ),
            "max_result_bytes": (self.max_result_bytes, _MAX_RESULT_BYTES),
        }
        for name, (value, hard_maximum) in integer_limits.items():
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= hard_maximum
            ):
                raise ValueError(f"{name} must be within its hard safety bound")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise ValueError("timeout_seconds must be within its hard safety bound")
        if not 0.001 <= self.timeout_seconds <= 30.0:
            raise ValueError("timeout_seconds must be within its hard safety bound")

    @classmethod
    def from_settings(cls, settings: Settings) -> ParsingLimits:
        return cls(
            max_input_bytes=settings.rag_max_upload_bytes,
            max_characters=settings.rag_max_extracted_characters,
            max_pages=settings.rag_max_parse_pages,
            max_rows=settings.rag_max_parse_rows,
            max_cells=settings.rag_max_parse_cells,
            max_zip_members=settings.rag_max_zip_members,
            max_expanded_bytes=settings.rag_max_expanded_bytes,
            max_compression_ratio=settings.rag_max_compression_ratio,
            max_elements=settings.rag_max_parse_elements,
            timeout_seconds=settings.rag_parse_timeout_seconds,
        )


class BoundedDocumentParser:
    """Defensive implementation of ``DocumentParserPort`` with no filesystem or network input."""

    parser_name = "shieldchain.deterministic"
    parser_version = "1"

    def __init__(
        self,
        limits: ParsingLimits | None = None,
        *,
        temp_root: Path | None = None,
        worker_target: Callable[..., None] | None = None,
    ) -> None:
        self._limits = limits or ParsingLimits()
        self._temp_root = temp_root
        self._worker_target = worker_target or _parse_worker

    @classmethod
    def from_settings(cls, settings: Settings) -> BoundedDocumentParser:
        return cls(ParsingLimits.from_settings(settings))

    def parse(self, content: bytes, *, media_type: str, filename: str) -> ParsedContent:
        extension, kind = _validate_request(content, media_type, filename, self._limits)
        del extension
        payload = _run_in_worker(
            kind,
            content,
            filename,
            self._limits,
            temp_root=self._temp_root,
            worker_target=self._worker_target,
        )
        if not payload.get("ok"):
            _raise_worker_error(payload)
        return _content_from_dto(payload["result"], media_type)


def _validate_request(
    content: bytes, media_type: str, filename: str, limits: ParsingLimits
) -> tuple[str, str]:
    if not isinstance(content, bytes) or not content or len(content) > limits.max_input_bytes:
        raise DocumentParsingError("document payload is invalid")
    if (
        not isinstance(filename, str)
        or not filename.strip()
        or any(token in filename for token in ("/", "\\", ":"))
    ):
        raise UnsupportedDocumentError("invalid document source")
    if not isinstance(media_type, str):
        raise UnsupportedDocumentError("unsupported document type")
    extension = os.path.splitext(filename)[1].lower()
    expected = _MEDIA_TYPES.get(extension)
    if expected is None or media_type.split(";", 1)[0].strip().lower() != expected[0]:
        raise UnsupportedDocumentError("unsupported document type")
    return extension, expected[1]


def _run_in_worker(
    kind: str,
    content: bytes,
    filename: str,
    limits: ParsingLimits,
    *,
    temp_root: Path | None,
    worker_target: Callable[..., None],
) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    try:
        with tempfile.TemporaryDirectory(prefix="shieldchain-parser-", dir=temp_root) as directory:
            result_path = Path(directory) / "result.json"
            process = context.Process(
                name="shieldchain-parser",
                target=worker_target,
                args=(str(result_path), kind, content, filename, asdict(limits)),
            )
            process.daemon = True
            try:
                process.start()
                process.join(limits.timeout_seconds)
                if process.is_alive():
                    _stop_worker(process)
                    raise ParsingTimeoutError("document parser timed out")
                if process.exitcode != 0:
                    raise DocumentParsingError("document parser ended unexpectedly")
                return _read_result(result_path, limits.max_result_bytes)
            finally:
                _stop_worker(process)
                _close_process(process)
    except ParsingTimeoutError:
        raise
    except (OSError, RuntimeError):
        raise DocumentParsingError("document parser is unavailable") from None


def _stop_worker(process: multiprocessing.Process) -> None:
    if process.pid is None:
        return
    if process.is_alive():
        process.terminate()
        process.join(0.5)
    if process.is_alive():
        process.kill()
        process.join(0.5)


def _close_process(process: multiprocessing.Process) -> None:
    if process.pid is not None and not process.is_alive():
        process.close()


def _parse_worker(
    result_path: str, kind: str, content: bytes, filename: str, limits: dict[str, Any]
) -> None:
    try:
        budget = ParserBudget(
            max_characters=limits["max_characters"],
            max_pages=limits["max_pages"],
            max_rows=limits["max_rows"],
            max_cells=limits["max_cells"],
            max_zip_members=limits["max_zip_members"],
            max_expanded_bytes=limits["max_expanded_bytes"],
            max_compression_ratio=limits["max_compression_ratio"],
            max_elements=limits["max_elements"],
            max_estimated_result_bytes=limits["max_estimated_result_bytes"],
        )
        parsed = parse_document(kind, content, filename, budget)
        _write_result(
            result_path,
            {
                "ok": True,
                "result": {
                    "status": parsed.status,
                    "title": parsed.title,
                    "metadata": parsed.metadata,
                    "elements": parsed.elements,
                    "characters": budget.characters,
                    "rows": budget.rows,
                    "cells": budget.cells,
                },
            },
            max_result_bytes=limits["max_result_bytes"],
        )
    except ParseBudgetExceeded:
        _write_result(result_path, {"ok": False, "error": "budget"}, max_result_bytes=1024)
    except ParseUnsupported:
        _write_result(result_path, {"ok": False, "error": "unsupported"}, max_result_bytes=1024)
    except BaseException:
        # Do not serialize exception detail, document text, filesystem paths, or tracebacks.
        try:
            _write_result(result_path, {"ok": False, "error": "failed"}, max_result_bytes=1024)
        except OSError:
            pass


def _write_result(result_path: str, payload: dict[str, Any], *, max_result_bytes: int) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_result_bytes:
        encoded = b'{"ok":false,"error":"budget"}'
    target = Path(result_path)
    partial = target.with_name(f".{target.name}.{os.getpid()}.partial")
    with partial.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    os.replace(partial, target)


def _read_result(result_path: Path, max_result_bytes: int) -> dict[str, Any]:
    try:
        file_stat = result_path.lstat()
        if not stat.S_ISREG(file_stat.st_mode) or not 2 <= file_stat.st_size <= max_result_bytes:
            raise ValueError
        with result_path.open("rb") as source:
            encoded = source.read(max_result_bytes + 1)
        if len(encoded) != file_stat.st_size or len(encoded) > max_result_bytes:
            raise ValueError
        payload = json.loads(encoded.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
        keys = set(payload)
        if (
            payload.get("ok") is True
            and keys == {"ok", "result"}
            and isinstance(payload["result"], dict)
        ):
            return payload
        if (
            payload.get("ok") is False
            and keys == {"ok", "error"}
            and payload["error"]
            in {
                "budget",
                "unsupported",
                "failed",
            }
        ):
            return payload
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        pass
    raise DocumentParsingError("document parser returned an invalid result")


def _raise_worker_error(payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if error == "budget":
        raise ParsingBudgetError("document exceeds parsing budget")
    if error == "unsupported":
        raise UnsupportedDocumentError("unsupported or malformed document")
    raise DocumentParsingError("document parsing failed")


def _content_from_dto(dto: Any, media_type: str) -> ParsedContent:
    if not isinstance(dto, dict):
        raise DocumentParsingError("document parser returned an invalid result")
    try:
        status = ParsingStatus(dto["status"])
        elements = tuple(ParsedElement(**element) for element in dto["elements"])
        title = dto["title"]
        if not isinstance(title, str) or not title.strip():
            raise ValueError
        metadata = dict(dto["metadata"])
        metadata.update(
            {
                "title": title,
                "parser_name": BoundedDocumentParser.parser_name,
                "parser_version": BoundedDocumentParser.parser_version,
                "character_count": dto["characters"],
                "row_count": dto["rows"],
                "cell_count": dto["cells"],
            }
        )
        text = _render_text(elements, status)
        return ParsedContent(
            text=text,
            media_type=media_type,
            metadata=metadata,
            elements=elements,
            status=status,
        )
    except (KeyError, TypeError, ValueError):
        raise DocumentParsingError("document parser returned an invalid result") from None


def _render_text(elements: tuple[ParsedElement, ...], status: ParsingStatus) -> str:
    if status is ParsingStatus.OCR_REQUIRED:
        return "OCR_REQUIRED"
    lines = [f"[{element.source_location}] {element.text}" for element in elements if element.text]
    if not lines:
        raise DocumentParsingError("document contains no extractable text")
    return "\n".join(lines)
