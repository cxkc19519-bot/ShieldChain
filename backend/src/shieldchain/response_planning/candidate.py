from __future__ import annotations

import json
import math
import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CLIENT_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOOL = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_ARGUMENT = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_FORBIDDEN_KEYS = frozenset(
    {
        "tenant",
        "tenant_id",
        "principal",
        "principal_id",
        "role",
        "risk",
        "approval",
        "approved",
        "policy",
        "idempotency_key",
        "timeout",
        "credential",
        "token",
        "url",
        "uri",
        "shell",
        "command",
        "code",
        "script",
        "target_ip",
        "endpoint_id",
        "account_id",
    }
)
type CandidateScalar = str | int | float | bool


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateAssumption(_StrictModel):
    statement: str = Field(min_length=1, max_length=1000)
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=16)

    @field_validator("statement")
    @classmethod
    def normalize_statement(cls, value: str) -> str:
        return _text(value, 1000)


class CandidateVerification(_StrictModel):
    tool: str
    expected_state: dict[str, CandidateScalar] = Field(max_length=16)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str) -> str:
        if not _TOOL.fullmatch(value):
            raise ValueError("verification tool is invalid")
        return value

    @field_validator("expected_state")
    @classmethod
    def validate_expected_state(
        cls, value: dict[str, CandidateScalar]
    ) -> dict[str, CandidateScalar]:
        return _scalars(value, allow_empty=False)


class CandidateAction(_StrictModel):
    client_action_id: str
    tool: str
    target_reference_id: UUID
    arguments: dict[str, CandidateScalar] = Field(default_factory=dict, max_length=16)
    expected_state: dict[str, CandidateScalar] = Field(max_length=16)
    depends_on: tuple[str, ...] = Field(default=(), max_length=8)
    public_reason: str = Field(min_length=1, max_length=1000)
    verification: CandidateVerification | None = None
    rollback_note: str = Field(min_length=1, max_length=512)

    @field_validator("client_action_id")
    @classmethod
    def validate_client_action_id(cls, value: str) -> str:
        if not _CLIENT_ID.fullmatch(value):
            raise ValueError("client_action_id is invalid")
        return value

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str) -> str:
        if not _TOOL.fullmatch(value):
            raise ValueError("tool is invalid")
        return value

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: dict[str, CandidateScalar]) -> dict[str, CandidateScalar]:
        return _scalars(value, allow_empty=True)

    @field_validator("expected_state")
    @classmethod
    def validate_expected_state(
        cls, value: dict[str, CandidateScalar]
    ) -> dict[str, CandidateScalar]:
        return _scalars(value, allow_empty=False)

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(not _CLIENT_ID.fullmatch(item) for item in value):
            raise ValueError("depends_on is invalid")
        return value

    @field_validator("public_reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        return _text(value, 1000)

    @field_validator("rollback_note")
    @classmethod
    def normalize_rollback(cls, value: str) -> str:
        return _text(value, 512)


class ResponsePlanCandidate(_StrictModel):
    action: Literal["propose_response_plan"]
    public_summary: str = Field(min_length=1, max_length=2000)
    assumptions: tuple[CandidateAssumption, ...] = Field(default=(), max_length=16)
    actions: tuple[CandidateAction, ...] = Field(default=(), max_length=8)
    stop_conditions: tuple[str, ...] = Field(min_length=1, max_length=16)
    operator_notes: tuple[str, ...] = Field(default=(), max_length=16)

    @field_validator("public_summary")
    @classmethod
    def normalize_summary(cls, value: str) -> str:
        return _text(value, 2000)

    @field_validator("stop_conditions", "operator_notes")
    @classmethod
    def normalize_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_text(item, 512) for item in value)
        if len(set(normalized)) != len(normalized):
            raise ValueError("candidate string list contains duplicates")
        return normalized

    @model_validator(mode="after")
    def validate_action_graph(self) -> ResponsePlanCandidate:
        seen: set[str] = set()
        for action in self.actions:
            if action.client_action_id in seen:
                raise ValueError("duplicate client_action_id")
            if any(item not in seen for item in action.depends_on):
                raise ValueError("dependencies must reference earlier actions")
            seen.add(action.client_action_id)
        return self


def parse_response_plan_candidate(raw: str) -> ResponsePlanCandidate:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 64 * 1024:
        raise ValueError("response plan candidate is empty or too large")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=_reject_constant)
    except json.JSONDecodeError as error:
        raise ValueError("response plan candidate must be one strict JSON object") from error
    if not isinstance(payload, dict):
        raise ValueError("response plan candidate must be one strict JSON object")
    return ResponsePlanCandidate.model_validate(payload)


def _reject_constant(value: str):
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _text(value: str, limit: int) -> str:
    if not isinstance(value, str):
        raise TypeError("candidate text must be a string")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > limit or any(ord(char) < 32 for char in normalized):
        raise ValueError("candidate text is invalid")
    return normalized


def _scalars(value: dict[str, CandidateScalar], *, allow_empty: bool) -> dict[str, CandidateScalar]:
    if not allow_empty and not value:
        raise ValueError("candidate mapping must not be empty")
    result: dict[str, CandidateScalar] = {}
    for key, item in value.items():
        if not _ARGUMENT.fullmatch(key) or key in _FORBIDDEN_KEYS:
            raise ValueError(f"candidate field is forbidden: {key}")
        if not isinstance(item, (str, int, float, bool)) or item is None:
            raise TypeError("candidate values must be JSON scalars")
        if isinstance(item, str):
            item = _text(item, 512)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("candidate numbers must be finite")
        result[key] = item
    return dict(sorted(result.items()))
