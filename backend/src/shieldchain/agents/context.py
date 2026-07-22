"""Deterministic, authorization-first context assembly for agent roles."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from shieldchain.agents.domain import AgentRole
from shieldchain.agents.security import (
    AccessDenied,
    ContextAccessPolicy,
    ContextContentType,
    ServerAccessContext,
    UntrustedContentEnvelope,
)
from shieldchain.rag.domain import SensitivityLevel


class AssemblyStatus(StrEnum):
    COMPLETE = "complete"
    DEGRADED = "degraded"
    REFUSED = "refused"


class ContextAssemblyStatusReason(StrEnum):
    TOKEN_BUDGET_TRUNCATED = "token_budget_truncated"
    REQUIRED_CONTEXT_OVER_BUDGET = "required_context_over_budget"
    DUPLICATES_MERGED = "duplicates_merged"


class ContextSectionName(StrEnum):
    SYSTEM_RULES = "system_rules"
    SAFETY_BOUNDARIES = "safety_boundaries"
    CURRENT_TASK = "current_task"
    ALLOWED_ACTIONS = "allowed_actions"
    CASE_SUMMARY = "case_summary"
    EVIDENCE = "evidence"
    KNOWLEDGE = "knowledge"
    HANDOFFS = "handoffs"
    OUTPUT_SCHEMA = "output_schema"


_CANDIDATE_TYPES = frozenset(
    {ContextContentType.EVIDENCE, ContextContentType.KNOWLEDGE, ContextContentType.HANDOFF}
)
_CONTENT_FIELDS = MappingProxyType(
    {
        ContextContentType.EVIDENCE: "excerpt",
        ContextContentType.KNOWLEDGE: "excerpt",
        ContextContentType.HANDOFF: "conclusion",
    }
)
_SECTION_BY_TYPE = MappingProxyType(
    {
        ContextContentType.EVIDENCE: ContextSectionName.EVIDENCE,
        ContextContentType.KNOWLEDGE: ContextSectionName.KNOWLEDGE,
        ContextContentType.HANDOFF: ContextSectionName.HANDOFFS,
    }
)
_SPACE = re.compile(r"\s+")


def _strings(values: Iterable[str], name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be an iterable of strings")
    try:
        frozen = tuple(values)
    except TypeError as error:
        raise TypeError(f"{name} must be iterable") from error
    if not frozen or any(not isinstance(item, str) or not item.strip() for item in frozen):
        raise ValueError(f"{name} must contain non-empty strings")
    return frozen


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _tokens(text: str) -> int:
    return max(1, math.ceil(len(text.encode("utf-8")) / 4))


def _freeze_json(value: object, name: str) -> object:
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"{name} mapping keys must be non-empty strings")
            frozen[key] = _freeze_json(item, name)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, name) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"{name} numbers must be finite")
        return value
    raise TypeError(f"{name} must contain only JSON-safe values")


def _jsonable(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


def _stable_json(value: Mapping[str, object], name: str) -> str:
    frozen = _freeze_json(value, name)
    return json.dumps(_jsonable(frozen), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True, slots=True)
class ContextAssemblyCandidate:
    content_type: ContextContentType
    tenant_id: UUID
    sensitivity: SensitivityLevel
    permission_tags: Iterable[str]
    source_id: str
    payload: Mapping[str, object]
    relevance: float
    observed_at: datetime
    owner_role: AgentRole | None = None
    participant_roles: Iterable[AgentRole] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.content_type, ContextContentType):
            raise TypeError("content_type must be a ContextContentType")
        if self.content_type not in _CANDIDATE_TYPES:
            raise ValueError("content_type is not supported by context assembly")
        if not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        if not isinstance(self.sensitivity, SensitivityLevel):
            raise TypeError("sensitivity must be a SensitivityLevel")
        if isinstance(self.permission_tags, (str, bytes)):
            raise TypeError("permission_tags must be an iterable of strings")
        object.__setattr__(self, "permission_tags", frozenset(self.permission_tags))
        if any(not isinstance(item, str) or not item.strip() for item in self.permission_tags):
            raise ValueError("permission_tags must contain non-empty strings")
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source_id must not be empty")
        if len(self.source_id) > 512:
            raise ValueError("source_id exceeds maximum length 512")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        object.__setattr__(self, "payload", _freeze_json(self.payload, "payload"))
        if (
            not isinstance(self.relevance, (int, float))
            or isinstance(self.relevance, bool)
            or not math.isfinite(self.relevance)
            or not 0 <= self.relevance <= 1
        ):
            raise ValueError("relevance must be between 0 and 1")
        _utc(self.observed_at, "observed_at")
        participants = tuple(self.participant_roles)
        if any(not isinstance(item, AgentRole) for item in participants):
            raise TypeError("participant_roles must contain AgentRole values")
        object.__setattr__(self, "participant_roles", participants)


@dataclass(frozen=True, slots=True)
class AssembledContextItem:
    content_type: ContextContentType
    source_ids: tuple[str, ...]
    content: str
    score: float
    prompt_block: str
    token_count: int


@dataclass(frozen=True, slots=True)
class AssembledContextSection:
    name: ContextSectionName
    items: tuple[AssembledContextItem, ...]
    protected: bool = False


@dataclass(frozen=True, slots=True)
class AssembledContext:
    status: AssemblyStatus
    sections: tuple[AssembledContextSection, ...]
    total_tokens: int
    max_tokens: int
    filtered_count: int
    omitted_count: int
    reasons: tuple[ContextAssemblyStatusReason, ...]

    def section(self, name: ContextSectionName) -> AssembledContextSection:
        for section in self.sections:
            if section.name is name:
                return section
        raise KeyError(name.value)

    def to_prompt(self) -> str:
        return "\n".join(
            f"[{section.name.value}]\n" + "\n".join(item.prompt_block for item in section.items)
            for section in self.sections
        )


@dataclass(frozen=True, slots=True)
class _AuthorizedItem:
    content_type: ContextContentType
    source_id: str
    content: str
    score: float


class ContextAssemblyService:
    """Filter, rank, deduplicate and budget context in a fixed section order."""

    def __init__(
        self,
        *,
        now: datetime,
        policy: ContextAccessPolicy | None = None,
        half_life: timedelta = timedelta(days=30),
    ) -> None:
        _utc(now, "now")
        if not isinstance(half_life, timedelta) or half_life <= timedelta(0):
            raise ValueError("half_life must be positive")
        self._now = now
        self._policy = policy or ContextAccessPolicy()
        self._half_life = half_life

    def assemble(
        self,
        *,
        access: ServerAccessContext,
        system_rules: Iterable[str],
        safety_boundaries: Iterable[str],
        current_task: str,
        allowed_actions: Iterable[str],
        case_tenant_id: UUID,
        case_sensitivity: SensitivityLevel,
        case_permission_tags: Iterable[str],
        case_summary: Mapping[str, object],
        candidates: Iterable[ContextAssemblyCandidate],
        output_schema: Mapping[str, object],
        max_tokens: int,
    ) -> AssembledContext:
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        if max_tokens > 2_000_000:
            raise ValueError("max_tokens exceeds the hard maximum")
        rules = _strings(system_rules, "system_rules")
        boundaries = _strings(safety_boundaries, "safety_boundaries")
        actions = _strings(allowed_actions, "allowed_actions")
        if not isinstance(current_task, str) or not current_task.strip():
            raise ValueError("current_task must not be empty")
        if not isinstance(case_summary, Mapping) or not isinstance(output_schema, Mapping):
            raise TypeError("case_summary and output_schema must be mappings")
        projected_case = self._policy.project(
            access,
            content_type=ContextContentType.SHARED_CASE,
            tenant_id=case_tenant_id,
            sensitivity=case_sensitivity,
            permission_tags=case_permission_tags,
            payload=case_summary,
        )
        base_sections = self._base_sections(
            rules, boundaries, current_task, actions, projected_case, output_schema
        )
        base_tokens = sum(
            _tokens(f"[{section.name.value}]\n") + sum(item.token_count for item in section.items)
            for section in base_sections
        )
        if base_tokens > max_tokens:
            return AssembledContext(
                AssemblyStatus.REFUSED,
                (),
                0,
                max_tokens,
                0,
                0,
                (ContextAssemblyStatusReason.REQUIRED_CONTEXT_OVER_BUDGET,),
            )
        authorized, filtered = self._authorize(access, candidates)
        merged, duplicate_count = self._rank_and_merge(authorized)
        selected: dict[ContextSectionName, list[AssembledContextItem]] = {
            ContextSectionName.EVIDENCE: [],
            ContextSectionName.KNOWLEDGE: [],
            ContextSectionName.HANDOFFS: [],
        }
        total_tokens = base_tokens
        omitted = 0
        for item in merged:
            if total_tokens + item.token_count > max_tokens:
                omitted += 1
                continue
            selected[_SECTION_BY_TYPE[item.content_type]].append(item)
            total_tokens += item.token_count
        sections = self._with_optional_sections(base_sections, selected)
        reasons: list[ContextAssemblyStatusReason] = []
        if duplicate_count:
            reasons.append(ContextAssemblyStatusReason.DUPLICATES_MERGED)
        if omitted:
            reasons.append(ContextAssemblyStatusReason.TOKEN_BUDGET_TRUNCATED)
        status = AssemblyStatus.DEGRADED if omitted else AssemblyStatus.COMPLETE
        return AssembledContext(
            status,
            sections,
            total_tokens,
            max_tokens,
            filtered,
            omitted,
            tuple(reasons),
        )

    def _authorize(
        self,
        access: ServerAccessContext,
        candidates: Iterable[ContextAssemblyCandidate],
    ) -> tuple[tuple[_AuthorizedItem, ...], int]:
        if isinstance(candidates, (str, bytes)):
            raise TypeError("candidates must be iterable")
        values = tuple(candidates)
        if len(values) > 1000:
            raise ValueError("candidates exceed maximum count 1000")
        if any(not isinstance(item, ContextAssemblyCandidate) for item in values):
            raise TypeError("candidates must contain ContextAssemblyCandidate values")
        authorized: list[_AuthorizedItem] = []
        filtered = 0
        for candidate in values:
            try:
                projected = self._policy.project(
                    access,
                    content_type=candidate.content_type,
                    tenant_id=candidate.tenant_id,
                    sensitivity=candidate.sensitivity,
                    permission_tags=candidate.permission_tags,
                    payload=candidate.payload,
                    owner_role=candidate.owner_role,
                    participant_roles=candidate.participant_roles,
                )
            except AccessDenied:
                filtered += 1
                continue
            content = projected.get(_CONTENT_FIELDS[candidate.content_type])
            if not isinstance(content, str) or not content.strip():
                raise ValueError("authorized candidate has no bounded text content")
            age = self._now - candidate.observed_at
            if age < timedelta(0):
                raise ValueError("candidate observed_at cannot be in the future")
            decay = 0.5 ** (age / self._half_life)
            authorized.append(
                _AuthorizedItem(
                    candidate.content_type,
                    candidate.source_id,
                    content.strip(),
                    candidate.relevance * decay,
                )
            )
        return tuple(authorized), filtered

    @staticmethod
    def _rank_and_merge(
        values: tuple[_AuthorizedItem, ...],
    ) -> tuple[tuple[AssembledContextItem, ...], int]:
        ordered = sorted(
            values,
            key=lambda item: (-item.score, item.content_type.value, item.source_id),
        )
        grouped: dict[tuple[ContextContentType, str], list[_AuthorizedItem]] = {}
        for item in ordered:
            normalized = _SPACE.sub(" ", item.content).strip().casefold()
            grouped.setdefault((item.content_type, normalized), []).append(item)
        merged: list[AssembledContextItem] = []
        duplicate_count = 0
        for items in grouped.values():
            best = items[0]
            source_ids = tuple(sorted({item.source_id for item in items}))
            duplicate_count += len(items) - 1
            envelope = UntrustedContentEnvelope.create(
                content_type=best.content_type,
                source_id=source_ids[0],
                content=best.content,
            )
            block_values = json.loads(envelope.to_prompt_block())
            block_values["source_ids"] = list(source_ids)
            block_values.pop("source_id", None)
            prompt_block = json.dumps(
                block_values,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            merged.append(
                AssembledContextItem(
                    best.content_type,
                    source_ids,
                    best.content,
                    best.score,
                    prompt_block,
                    _tokens(prompt_block) + 1,
                )
            )
        merged.sort(key=lambda item: (-item.score, item.content_type.value, item.source_ids))
        return tuple(merged), duplicate_count

    @staticmethod
    def _base_sections(
        rules: tuple[str, ...],
        boundaries: tuple[str, ...],
        current_task: str,
        actions: tuple[str, ...],
        case_summary: Mapping[str, object],
        output_schema: Mapping[str, object],
    ) -> tuple[AssembledContextSection, ...]:
        def trusted(
            name: ContextSectionName, values: tuple[str, ...], *, protected: bool = False
        ) -> AssembledContextSection:
            items = tuple(
                AssembledContextItem(
                    ContextContentType.SHARED_CASE,
                    (),
                    value,
                    1,
                    value,
                    _tokens(value) + 1,
                )
                for value in values
            )
            return AssembledContextSection(name, items, protected)

        stable_case = _stable_json(case_summary, "case_summary")
        stable_schema = _stable_json(output_schema, "output_schema")
        return (
            trusted(ContextSectionName.SYSTEM_RULES, rules, protected=True),
            trusted(ContextSectionName.SAFETY_BOUNDARIES, boundaries, protected=True),
            trusted(ContextSectionName.CURRENT_TASK, (current_task.strip(),)),
            trusted(ContextSectionName.ALLOWED_ACTIONS, actions),
            trusted(ContextSectionName.CASE_SUMMARY, (stable_case,)),
            trusted(ContextSectionName.EVIDENCE, ()),
            trusted(ContextSectionName.KNOWLEDGE, ()),
            trusted(ContextSectionName.HANDOFFS, ()),
            trusted(ContextSectionName.OUTPUT_SCHEMA, (stable_schema,), protected=True),
        )

    @staticmethod
    def _with_optional_sections(
        base: tuple[AssembledContextSection, ...],
        selected: Mapping[ContextSectionName, list[AssembledContextItem]],
    ) -> tuple[AssembledContextSection, ...]:
        return tuple(
            AssembledContextSection(section.name, tuple(selected[section.name]), section.protected)
            if section.name in selected
            else section
            for section in base
        )
