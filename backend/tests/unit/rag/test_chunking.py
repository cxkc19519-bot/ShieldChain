from __future__ import annotations

from uuid import uuid4

import pytest

from shieldchain.rag.chunking import ChunkingPolicy, DeterministicChunker
from shieldchain.rag.domain import SensitivityLevel
from shieldchain.rag.ports import ParsedContent, ParsedElement


def content(*elements: ParsedElement) -> ParsedContent:
    return ParsedContent(
        text="\n".join(element.text for element in elements),
        media_type="text/plain",
        metadata={"title": "Runbook"},
        elements=elements,
    )


def chunk(content_value: ParsedContent, *, policy: ChunkingPolicy | None = None):
    return DeterministicChunker(policy=policy).chunk(
        content_value,
        document_version_id=uuid4(),
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"soc"},
    )


def test_chunker_preserves_heading_path_page_and_exact_source_spans() -> None:
    parsed = content(
        ParsedElement("heading", "响应流程", "line:1", heading="响应流程"),
        ParsedElement("paragraph", "先隔离主机，再保留证据。", "line:2", heading="响应流程"),
        ParsedElement("page", "复核告警。", "page:2", page_number=2),
    )
    result = chunk(parsed)

    assert [item.chunk.ordinal for item in result.items] == [0, 1, 2]
    assert result.items[1].chunk.heading_path == ("响应流程",)
    assert result.items[2].chunk.page_number == 2
    for item in result.items:
        for source in item.sources:
            assert item.chunk.text == result.source_text(content_value=parsed, source=source)


def test_chunker_uses_token_overlap_for_long_prose_without_losing_source() -> None:
    value = " ".join(f"word{number}" for number in range(25))
    parsed = content(ParsedElement("paragraph", value, "line:1"))
    policy = ChunkingPolicy(target_tokens=8, hard_limit_tokens=12, overlap_tokens=2)
    result = chunk(parsed, policy=policy)

    assert len(result.items) >= 3
    assert all(item.chunk.token_count <= 12 for item in result.items)
    assert result.items[0].chunk.text.split()[-2:] == result.items[1].chunk.text.split()[:2]
    assert result.reconstruct_source(0) == value


@pytest.mark.parametrize("kind", ["table_row", "code", "log"])
def test_table_code_and_log_stay_whole_when_below_hard_limit(kind: str) -> None:
    source = "a b c d e f g h i"
    result = chunk(
        content(ParsedElement(kind, source, f"{kind}:1")),
        policy=ChunkingPolicy(target_tokens=4, hard_limit_tokens=12, overlap_tokens=1),
    )

    assert len(result.items) == 1
    assert result.items[0].chunk.text == source


@pytest.mark.parametrize("kind", ["table_row", "code", "log"])
def test_large_structural_element_splits_at_a_safe_line_boundary(kind: str) -> None:
    source = "one two three four\nfive six seven eight\nnine ten eleven twelve"
    result = chunk(
        content(ParsedElement(kind, source, f"{kind}:1")),
        policy=ChunkingPolicy(target_tokens=4, hard_limit_tokens=5, overlap_tokens=0),
    )

    assert len(result.items) == 3
    assert all(item.chunk.token_count <= 5 for item in result.items)
    assert result.reconstruct_source(0) == source


def test_blank_elements_are_ignored_and_duplicate_content_keeps_every_reference() -> None:
    result = chunk(
        content(
            ParsedElement("paragraph", "   ", "line:1"),
            ParsedElement("paragraph", "same evidence", "line:2"),
            ParsedElement("paragraph", "same evidence", "line:3"),
        )
    )

    assert len(result.items) == 1
    assert [source.structural_location for source in result.items[0].sources] == [
        "line:2",
        "line:3",
    ]


def test_stable_ids_and_hashes_can_be_recomputed() -> None:
    document_version_id = uuid4()
    parsed = content(ParsedElement("paragraph", "preserve this evidence", "line:1"))
    chunker = DeterministicChunker()
    first = chunker.chunk(
        parsed,
        document_version_id=document_version_id,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"soc"},
    )
    second = chunker.chunk(
        parsed,
        document_version_id=document_version_id,
        sensitivity=SensitivityLevel.INTERNAL,
        permission_tags={"soc"},
    )

    assert first.items[0].chunk.id == second.items[0].chunk.id
    assert first.items[0].chunk.content_sha256 == second.items[0].chunk.content_sha256
    assert first.items[0].chunk.id == chunker.stable_chunk_id(first.items[0].chunk)


def test_policy_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError):
        ChunkingPolicy(target_tokens=9, hard_limit_tokens=8, overlap_tokens=1)


def test_oversized_single_line_structure_hard_splits_and_marks_degraded() -> None:
    source = "alpha beta gamma delta epsilon zeta eta theta iota kappa"
    result = chunk(
        content(ParsedElement("code", source, "code:1")),
        policy=ChunkingPolicy(target_tokens=3, hard_limit_tokens=4, overlap_tokens=0),
    )

    assert len(result.items) > 1
    assert all(item.chunk.token_count <= 4 for item in result.items)
    assert all(item.chunk.is_degraded for item in result.items)
    assert all(item.chunk.chunking_mode == "rule_structural_split" for item in result.items)
