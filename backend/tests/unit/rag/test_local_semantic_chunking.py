from __future__ import annotations

from shieldchain.rag.local_semantic_chunking import DeepSeekSemanticChunker


def test_local_semantic_chunking_disables_thinking_for_json_output() -> None:
    captured: dict[str, object] = {}

    def transport(
        _url: str, _headers: dict[str, str], payload: dict[str, object]
    ) -> dict[str, object]:
        captured.update(payload)
        return {"choices": [{"message": {"content": '{"groups":[[0],[1]]}'}}]}

    chunker = DeepSeekSemanticChunker(
        api_key="test-key",
        base_url="https://llm.invalid",
        model="deepseek-v4-flash",
        transport=transport,
    )

    segments = chunker.chunk("first source unit\nsecond source unit")

    assert [segment.text for segment in segments] == ["first source unit", "second source unit"]
    assert captured["thinking"] == {"type": "disabled"}
    assert captured["response_format"] == {"type": "json_object"}
