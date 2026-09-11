"""Rule-only, source-preserving chunk construction for parsed documents."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from types import MappingProxyType
from uuid import UUID, uuid5

from shieldchain.rag.domain import ChunkSource, KnowledgeChunk, SensitivityLevel
from shieldchain.rag.ports import ParsedContent, ParsedElement
from shieldchain.rag.tokenization import DeterministicSecurityTokenizer, TokenSpan

_CHUNK_NAMESPACE = UUID("9252d3e2-4764-5319-94bb-b1b0e3efab5b")
_STRUCTURAL_KINDS = frozenset({"table", "table_row", "code", "code_block", "log", "log_line"})


@dataclass(frozen=True, slots=True)
class ChunkingPolicy:
    target_tokens: int = 512
    hard_limit_tokens: int = 768
    overlap_tokens: int = 64

    def __post_init__(self) -> None:
        for name in ("target_tokens", "hard_limit_tokens", "overlap_tokens"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.target_tokens < 1 or self.hard_limit_tokens < self.target_tokens:
            raise ValueError("target_tokens must be positive and no greater than hard_limit_tokens")
        if self.overlap_tokens >= self.target_tokens:
            raise ValueError("overlap_tokens must be smaller than target_tokens")


@dataclass(frozen=True, slots=True)
class ChunkedItem:
    chunk: KnowledgeChunk
    sources: tuple[ChunkSource, ...]

    def __post_init__(self) -> None:
        if not self.sources:
            raise ValueError("chunked item must include at least one source span")


@dataclass(frozen=True, slots=True)
class ChunkingResult:
    """Deduplicated chunks plus every original reference needed for later persistence."""

    items: tuple[ChunkedItem, ...]
    _elements: tuple[ParsedElement, ...]
    _heading_paths: tuple[tuple[str, ...], ...]

    def source_text(self, *, content_value: ParsedContent, source: ChunkSource) -> str:
        try:
            element = content_value.elements[source.parsed_element_ordinal]
        except IndexError as error:
            raise ValueError("source span does not refer to parsed content") from error
        return element.text[source.start_offset : source.end_offset]

    def reconstruct_source(self, element_ordinal: int) -> str:
        element = self._elements[element_ordinal]
        recovered = [""] * len(element.text)
        for item in self.items:
            for source in item.sources:
                if source.parsed_element_ordinal != element_ordinal:
                    continue
                recovered[source.start_offset : source.end_offset] = element.text[
                    source.start_offset : source.end_offset
                ]
        return "".join(recovered)

    def heading_path_for(self, element_ordinal: int) -> tuple[str, ...]:
        try:
            return self._heading_paths[element_ordinal]
        except IndexError as error:
            raise ValueError("element ordinal is outside parsed content") from error

    @property
    def source_spans(self) -> MappingProxyType:
        return MappingProxyType({item.chunk.id: item.sources for item in self.items})


class DeterministicChunker:
    """Pre-split parsed structure and build bounded chunks without changing source text."""

    def __init__(
        self,
        *,
        policy: ChunkingPolicy | None = None,
        tokenizer: DeterministicSecurityTokenizer | None = None,
    ) -> None:
        self.policy = policy or ChunkingPolicy()
        self.tokenizer = tokenizer or DeterministicSecurityTokenizer()

    def chunk(
        self,
        content: ParsedContent,
        *,
        document_version_id: UUID,
        sensitivity: SensitivityLevel,
        permission_tags: Iterable[str],
    ) -> ChunkingResult:
        if not isinstance(content, ParsedContent):
            raise TypeError("content must be ParsedContent")
        if not isinstance(document_version_id, UUID):
            raise TypeError("document_version_id must be a UUID")
        if not isinstance(sensitivity, SensitivityLevel):
            raise TypeError("sensitivity must be a SensitivityLevel")
        permission_tags = tuple(permission_tags)
        elements = content.elements or (ParsedElement("paragraph", content.text, "document:body"),)
        path = (str(content.metadata.get("title") or "Document"),)
        element_heading_paths: list[tuple[str, ...]] = []
        pending: list[tuple[str, tuple[str, ...], ParsedElement, int, int, int, bool]] = []
        for element_ordinal, element in enumerate(elements):
            if element.kind == "heading" and element.text.strip():
                path = (element.heading or element.text.strip(),)
            elif element.heading:
                path = (element.heading,)
            element_heading_paths.append(path)
            for start, end, degraded in self._element_ranges(element):
                pending.append(
                    (element.text[start:end], path, element, element_ordinal, start, end, degraded)
                )

        items: list[ChunkedItem] = []
        by_hash: dict[str, int] = {}
        for text, heading_path, element, element_ordinal, start, end, degraded in pending:
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            chunk_id = self._id_for(document_version_id, digest)
            source = ChunkSource(
                chunk_id=chunk_id,
                occurrence_ordinal=0,
                parsed_element_ordinal=element_ordinal,
                start_offset=start,
                end_offset=end,
                heading_path=heading_path,
                page_number=element.page_number,
                structural_location=element.source_location,
            )
            existing = by_hash.get(digest)
            if existing is not None and items[existing].chunk.text == text:
                existing_item = items[existing]
                source = ChunkSource(
                    chunk_id=existing_item.chunk.id,
                    occurrence_ordinal=len(existing_item.sources),
                    parsed_element_ordinal=element_ordinal,
                    start_offset=start,
                    end_offset=end,
                    heading_path=heading_path,
                    page_number=element.page_number,
                    structural_location=element.source_location,
                )
                sources = existing_item.sources + (source,)
                items[existing] = ChunkedItem(
                    replace(existing_item.chunk, sources=sources), sources
                )
                continue
            ordinal = len(items)
            structural_location = f"{element.source_location}#chars:{start}-{end}"
            token_count = self.tokenizer.count(text)
            chunk = KnowledgeChunk(
                id=chunk_id,
                document_version_id=document_version_id,
                ordinal=ordinal,
                heading_path=heading_path,
                page_number=element.page_number,
                structural_location=structural_location,
                text=text,
                token_count=token_count,
                content_sha256=digest,
                sensitivity=sensitivity,
                permission_tags=permission_tags,
                chunking_mode="rule_structural_split" if degraded else "rule",
                is_degraded=degraded,
                sources=(source,),
            )
            by_hash[digest] = ordinal
            items.append(ChunkedItem(chunk, (source,)))
        return ChunkingResult(tuple(items), tuple(elements), tuple(element_heading_paths))

    def stable_chunk_id(self, chunk: KnowledgeChunk) -> UUID:
        """Recompute the deterministic identifier from immutable chunk identity inputs."""
        return self._id_for(chunk.document_version_id, chunk.content_sha256)

    @staticmethod
    def _id_for(document_version_id: UUID, content_sha256: str) -> UUID:
        return uuid5(_CHUNK_NAMESPACE, f"{document_version_id}:{content_sha256}")

    def _element_ranges(self, element: ParsedElement) -> tuple[tuple[int, int, bool], ...]:
        if not element.text.strip():
            return ()
        tokens = self.tokenizer.token_spans(element.text)
        if not tokens:
            return ()
        structural = element.kind.casefold() in _STRUCTURAL_KINDS
        if structural and len(tokens) <= self.policy.hard_limit_tokens:
            return ((0, len(element.text), False),)
        limit = self.policy.hard_limit_tokens if structural else self.policy.target_tokens
        ranges: list[tuple[int, int, bool]] = []
        start_token = 0
        while start_token < len(tokens):
            end_token = min(start_token + limit, len(tokens))
            hard_split = False
            if end_token < len(tokens):
                safe = self._safe_end(element.text, tokens, start_token, end_token, structural)
                if safe is not None:
                    end_token = safe
                else:
                    hard_split = structural
            start = 0 if start_token == 0 else tokens[start_token].start
            # Include whitespace/newlines up to the next token. This makes the source ranges
            # cover every original character (especially structural line boundaries).
            end = len(element.text) if end_token == len(tokens) else tokens[end_token].start
            ranges.append((start, end, hard_split))
            if end_token == len(tokens):
                break
            overlap = 0 if structural else self.policy.overlap_tokens
            start_token = max(start_token + 1, end_token - overlap)
        if structural and any(hard_split for _, _, hard_split in ranges):
            return tuple((start, end, True) for start, end, _ in ranges)
        return tuple(ranges)

    @staticmethod
    def _safe_end(
        text: str,
        tokens: tuple[TokenSpan, ...],
        start_token: int,
        end_token: int,
        structural: bool,
    ) -> int | None:
        for index in range(end_token - 1, start_token, -1):
            separator = text[tokens[index - 1].end : tokens[index].start]
            if "\n" in separator:
                return index
            if structural and any(mark in separator for mark in ",|；;"):
                return index
            if not structural and any(mark in separator for mark in ".!?。！？；;"):
                return index
        return None
