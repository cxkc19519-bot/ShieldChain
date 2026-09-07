"""Strict fixed datasets for auditable grounded-assistant evaluation."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

_STATUSES = frozenset(
    {"conversational", "grounded", "extractive_degraded", "refused"}
)
_REFUSALS = frozenset(
    {
        "insufficient_evidence",
        "conflicting_evidence",
        "stale_evidence",
        "unauthorized",
        "unsafe_content",
    }
)


def _text(value: object, field: str, maximum: int = 4_096) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a trimmed non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return value


@dataclass(frozen=True, slots=True)
class AssistantEvaluationCase:
    case_id: str
    language: str
    message: str
    expected_statuses: Sequence[str]
    expected_refusal_reason: str | None
    expected_document_ids: Sequence[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", _text(self.case_id, "case_id", 200))
        if self.language not in {"zh", "en"}:
            raise ValueError("language must be zh or en")
        object.__setattr__(self, "message", _text(self.message, "message"))
        statuses = tuple(self.expected_statuses)
        if not statuses or len(set(statuses)) != len(statuses) or not set(statuses) <= _STATUSES:
            raise ValueError("expected_statuses is invalid")
        documents = tuple(
            _text(item, "expected_document_ids", 255)
            for item in self.expected_document_ids
        )
        if len(set(documents)) != len(documents):
            raise ValueError("expected_document_ids must be unique")
        reason = self.expected_refusal_reason
        if reason is not None and reason not in _REFUSALS:
            raise ValueError("expected_refusal_reason is invalid")
        if ("refused" in statuses) != (reason is not None):
            raise ValueError("refused cases must declare exactly one refusal reason")
        object.__setattr__(self, "expected_statuses", statuses)
        object.__setattr__(self, "expected_document_ids", documents)


@dataclass(frozen=True, slots=True)
class AssistantEvaluationDataset:
    dataset_id: str
    version: str
    cases: tuple[AssistantEvaluationCase, ...]
    digest_sha256: str


def load_assistant_evaluation_dataset(path: str | Path) -> AssistantEvaluationDataset:
    source = Path(path)
    raw = source.read_bytes()
    if not raw or len(raw) > 2_000_000:
        raise ValueError("assistant evaluation dataset size is invalid")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("assistant evaluation dataset must be UTF-8 JSON") from error
    if not isinstance(payload, Mapping) or set(payload) != {"dataset_id", "version", "cases"}:
        raise ValueError("assistant evaluation dataset schema is invalid")
    raw_cases = payload["cases"]
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 1_000:
        raise ValueError("assistant evaluation cases are invalid")
    fields = {
        "case_id",
        "language",
        "message",
        "expected_statuses",
        "expected_refusal_reason",
        "expected_document_ids",
    }
    cases: list[AssistantEvaluationCase] = []
    for item in raw_cases:
        if not isinstance(item, Mapping) or set(item) != fields:
            raise ValueError("assistant evaluation case schema is invalid")
        cases.append(AssistantEvaluationCase(**item))
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("assistant evaluation case identifiers must be unique")
    if {case.language for case in cases} != {"zh", "en"}:
        raise ValueError("assistant evaluation dataset must be bilingual")
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return AssistantEvaluationDataset(
        dataset_id=_text(payload["dataset_id"], "dataset_id", 128),
        version=_text(payload["version"], "version", 64),
        cases=tuple(cases),
        digest_sha256=sha256(canonical).hexdigest(),
    )
