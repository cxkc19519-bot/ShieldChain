"""DeepSeek-backed semantic document chunking for the local RAG profile."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from shieldchain.core.config import Settings, get_settings

MAX_REQUEST_CHARACTERS = 14_000
MAX_CHUNK_CHARACTERS = 900
REQUEST_TIMEOUT_SECONDS = 60
MAX_REQUEST_ATTEMPTS = 2


class SemanticChunkingError(RuntimeError):
    """The model did not produce a safe semantic chunk plan."""


@dataclass(frozen=True, slots=True)
class SemanticSegment:
    """A validated document segment, including its original character offset."""

    offset: int
    text: str


class DeepSeekSemanticChunker:
    """Ask DeepSeek for groups of source units, then validate all boundaries locally."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        transport: Callable[[str, dict[str, str], dict[str, object]], dict[str, object]]
        | None = None,
    ) -> None:
        if not api_key.strip():
            raise SemanticChunkingError("DeepSeek API key is not configured")
        if not base_url.strip() or not model.strip():
            raise ValueError("DeepSeek base URL and model must not be blank")
        self._api_key = api_key
        self._url = f"{base_url.rstrip('/')}/chat/completions"
        self._model = model
        self._transport = transport or self._post

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> DeepSeekSemanticChunker:
        configured = settings or get_settings()
        return cls(
            api_key=configured.deepseek_api_key.get_secret_value(),
            base_url=str(configured.deepseek_base_url),
            model=configured.deepseek_model,
        )

    def chunk(self, content: str) -> tuple[SemanticSegment, ...]:
        units = _source_units(content)
        if not units:
            return ()
        groups: list[list[_SourceUnit]] = []
        for batch in _batches(units):
            groups.extend(self._request_groups(batch))
        return tuple(
            SemanticSegment(offset=group[0].offset, text="\n\n".join(unit.text for unit in group))
            for group in groups
        )

    def _request_groups(self, units: Sequence[_SourceUnit]) -> list[list[_SourceUnit]]:
        listed = "\n".join(f"[{index}] {unit.text}" for index, unit in enumerate(units))
        payload: dict[str, object] = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": 2_000,
            "thinking": {"type": "disabled"},
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return JSON only. Group numbered source units into semantic chunks. "
                        "This is for RAG. "
                        "Never rewrite, omit, or reorder source units. Keep each group "
                        "self-contained and normally 300-650 Chinese characters, never above 900. "
                        'JSON schema: {"groups":[[0,1],[2]]}; every index appears exactly once '
                        "in ascending contiguous order."
                    ),
                },
                {"role": "user", "content": f"Source units:\n{listed}\nReturn JSON now."},
            ],
        }
        last_error: SemanticChunkingError | None = None
        for _attempt in range(MAX_REQUEST_ATTEMPTS):
            try:
                response = self._transport(
                    self._url,
                    {
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    payload,
                )
                try:
                    choices = response["choices"]
                    content = choices[0]["message"]["content"]
                    decoded = json.loads(content)
                except (KeyError, TypeError, ValueError, IndexError) as error:
                    raise SemanticChunkingError(
                        "DeepSeek returned an invalid semantic chunk plan"
                    ) from error
                return _validate_groups(decoded, units)
            except SemanticChunkingError as error:
                last_error = error
        raise SemanticChunkingError(
            "DeepSeek did not return a safe semantic chunk plan after retry"
        ) from last_error
    @staticmethod
    def _post(url: str, headers: dict[str, str], payload: dict[str, object]) -> dict[str, object]:
        try:
            request = Request(url, json.dumps(payload).encode("utf-8"), headers)
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError) as error:
            raise SemanticChunkingError("DeepSeek semantic chunking request failed") from error
        if not isinstance(decoded, dict):
            raise SemanticChunkingError("DeepSeek returned an invalid API response")
        return decoded


@dataclass(frozen=True, slots=True)
class _SourceUnit:
    offset: int
    text: str


def _source_units(content: str) -> list[_SourceUnit]:
    units: list[_SourceUnit] = []
    cursor = 0
    for raw in re.split(r"\n+", content):
        offset = content.find(raw, cursor)
        cursor = offset + len(raw)
        text = raw.strip()
        if not text:
            continue
        units.extend(_split_long_unit(text, offset))
    return units


def _split_long_unit(text: str, offset: int) -> list[_SourceUnit]:
    if len(text) <= MAX_CHUNK_CHARACTERS:
        return [_SourceUnit(offset=offset, text=text)]
    parts: list[_SourceUnit] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + MAX_CHUNK_CHARACTERS)
        if end < len(text):
            boundary = max(text.rfind("。", start + 300, end), text.rfind("\n", start + 300, end))
            if boundary > start:
                end = boundary + 1
        parts.append(_SourceUnit(offset=offset + start, text=text[start:end].strip()))
        start = end
    return parts


def _batches(units: Sequence[_SourceUnit]) -> list[list[_SourceUnit]]:
    batches: list[list[_SourceUnit]] = []
    current: list[_SourceUnit] = []
    size = 0
    for unit in units:
        if current and size + len(unit.text) > MAX_REQUEST_CHARACTERS:
            batches.append(current)
            current, size = [], 0
        current.append(unit)
        size += len(unit.text)
    if current:
        batches.append(current)
    return batches


def _validate_groups(value: object, units: Sequence[_SourceUnit]) -> list[list[_SourceUnit]]:
    if not isinstance(value, dict) or not isinstance(value.get("groups"), list):
        raise SemanticChunkingError("DeepSeek semantic chunk plan is not JSON groups")
    indexes: list[int] = []
    groups: list[list[_SourceUnit]] = []
    for raw_group in value["groups"]:
        if not isinstance(raw_group, list) or not raw_group:
            raise SemanticChunkingError("DeepSeek semantic chunk group is invalid")
        if any(not isinstance(index, int) or isinstance(index, bool) for index in raw_group):
            raise SemanticChunkingError("DeepSeek semantic chunk indexes are invalid")
        indexes.extend(raw_group)
        group = [units[index] for index in raw_group if 0 <= index < len(units)]
        if (
            len(group) != len(raw_group)
            or len("\n\n".join(item.text for item in group)) > MAX_CHUNK_CHARACTERS
        ):
            raise SemanticChunkingError("DeepSeek semantic chunks exceed local safety limits")
        groups.append(group)
    if indexes != list(range(len(units))):
        raise SemanticChunkingError(
            "DeepSeek semantic chunk plan does not cover source units safely"
        )
    return groups
