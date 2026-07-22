"""Layered agent memory boundaries, safe case compression and experience promotion."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from shieldchain.agents.domain import ConfirmedFact, Hypothesis, Reference, TrustedReference
from shieldchain.core.logging import redact_sensitive_data


class MemoryBoundaryError(RuntimeError):
    """Memory content attempted to cross a deterministic layer boundary."""


class MemoryLayer(StrEnum):
    WORKING = "working"
    CASE = "case"
    SESSION = "session"
    AUDIT = "audit"
    EXPERIENCE = "experience"


class MemoryContentKind(StrEnum):
    WORK_ITEM = "work_item"
    CASE_NOTE = "case_note"
    USER_PREFERENCE = "user_preference"
    CONVERSATION_SUMMARY = "conversation_summary"
    AUDIT_SUMMARY = "audit_summary"


class ProtectedArtifactKind(StrEnum):
    EVIDENCE = "evidence"
    APPROVAL = "approval"
    TOOL_RESULT = "tool_result"


_SHA256 = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_AUDIT_TEXT = re.compile(
    r"(?i)(raw[_ -]?prompt|system prompt|chain[_ -]?of[_ -]?thought|思维链|原始提示)"
)


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _text(value: str, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds maximum length {maximum}")
    return value.strip()


def _references(values: Iterable[Reference]) -> tuple[Reference, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("references must be iterable")
    try:
        frozen = tuple(values)
    except TypeError as error:
        raise TypeError("references must be iterable") from error
    if any(not isinstance(item, TrustedReference) for item in frozen):
        raise TypeError("references must contain trusted references")
    return frozen


@dataclass(frozen=True, slots=True)
class LayeredMemoryEntry:
    id: UUID
    layer: MemoryLayer
    kind: MemoryContentKind
    content: str
    created_at: datetime
    case_id: UUID | None = None
    references: Iterable[Reference] = ()
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise TypeError("id must be a UUID")
        if not isinstance(self.layer, MemoryLayer) or not isinstance(self.kind, MemoryContentKind):
            raise TypeError("layer and kind must be enum values")
        object.__setattr__(self, "content", _text(self.content, "content"))
        _utc(self.created_at, "created_at")
        refs = _references(self.references)
        object.__setattr__(self, "references", refs)
        if self.layer in {MemoryLayer.WORKING, MemoryLayer.CASE, MemoryLayer.AUDIT}:
            if not isinstance(self.case_id, UUID):
                raise MemoryBoundaryError(f"{self.layer.value} memory requires case_id")
        elif self.case_id is not None:
            raise MemoryBoundaryError(f"{self.layer.value} memory must be isolated from case_id")
        if self.case_id is not None and any(item.case_id != self.case_id for item in refs):
            raise MemoryBoundaryError("memory reference belongs to another case")
        if self.layer is MemoryLayer.WORKING:
            if self.kind is not MemoryContentKind.WORK_ITEM:
                raise MemoryBoundaryError("working memory only accepts work items")
            if self.expires_at is None:
                raise MemoryBoundaryError("working memory requires expires_at")
        elif self.expires_at is not None:
            raise MemoryBoundaryError("only working memory may expire")
        if self.expires_at is not None:
            _utc(self.expires_at, "expires_at")
            if self.expires_at <= self.created_at:
                raise ValueError("expires_at must be after created_at")
        if self.layer is MemoryLayer.CASE and self.kind is not MemoryContentKind.CASE_NOTE:
            raise MemoryBoundaryError("case memory only accepts case notes")
        if self.layer is MemoryLayer.SESSION:
            if self.kind not in {
                MemoryContentKind.USER_PREFERENCE,
                MemoryContentKind.CONVERSATION_SUMMARY,
            }:
                raise MemoryBoundaryError("session memory only accepts preferences or summaries")
            if refs:
                raise MemoryBoundaryError("session memory cannot contain security references")
        if self.layer is MemoryLayer.AUDIT:
            if self.kind is not MemoryContentKind.AUDIT_SUMMARY:
                raise MemoryBoundaryError("audit memory only accepts audit summaries")
            if _FORBIDDEN_AUDIT_TEXT.search(self.content):
                raise MemoryBoundaryError("audit memory cannot contain prompts or chain of thought")
        if self.layer is MemoryLayer.EXPERIENCE:
            raise MemoryBoundaryError("experience memory must use the promotion service")


@dataclass(frozen=True, slots=True)
class ProtectedArtifactReference:
    id: UUID
    case_id: UUID
    kind: ProtectedArtifactKind
    source_id: str
    integrity_sha256: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID) or not isinstance(self.case_id, UUID):
            raise TypeError("id and case_id must be UUID values")
        if not isinstance(self.kind, ProtectedArtifactKind):
            raise TypeError("kind must be a ProtectedArtifactKind")
        object.__setattr__(self, "source_id", _text(self.source_id, "source_id", maximum=512))
        if not isinstance(self.integrity_sha256, str) or not _SHA256.fullmatch(
            self.integrity_sha256
        ):
            raise ValueError("integrity_sha256 must be lowercase SHA-256")
        _utc(self.observed_at, "observed_at")


@dataclass(frozen=True, slots=True)
class CaseMemoryInput:
    case_id: UUID
    confirmed_facts: Iterable[ConfirmedFact]
    active_hypotheses: Iterable[Hypothesis]
    hypothesis_expiry: Mapping[UUID, datetime]
    protected_artifacts: Iterable[ProtectedArtifactReference]
    notes: Iterable[str]

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, UUID):
            raise TypeError("case_id must be a UUID")
        facts = tuple(self.confirmed_facts)
        hypotheses = tuple(self.active_hypotheses)
        artifacts = tuple(self.protected_artifacts)
        notes = tuple(_text(item, "note") for item in self.notes)
        if any(not isinstance(item, ConfirmedFact) for item in facts):
            raise TypeError("confirmed_facts must contain ConfirmedFact values")
        if any(not isinstance(item, Hypothesis) for item in hypotheses):
            raise TypeError("active_hypotheses must contain Hypothesis values")
        if any(not isinstance(item, ProtectedArtifactReference) for item in artifacts):
            raise TypeError("protected_artifacts must contain protected references")
        for item in (*facts, *hypotheses):
            if any(reference.case_id != self.case_id for reference in item.references):
                raise MemoryBoundaryError("fact or hypothesis reference belongs to another case")
        if any(item.case_id != self.case_id for item in artifacts):
            raise MemoryBoundaryError("protected artifact belongs to another case")
        expiry = dict(self.hypothesis_expiry)
        known_hypotheses = {item.id for item in hypotheses}
        if set(expiry) != known_hypotheses:
            raise ValueError("hypothesis_expiry must cover every active hypothesis exactly")
        for value in expiry.values():
            _utc(value, "hypothesis expiry")
        object.__setattr__(self, "confirmed_facts", facts)
        object.__setattr__(self, "active_hypotheses", hypotheses)
        object.__setattr__(self, "protected_artifacts", artifacts)
        object.__setattr__(self, "notes", notes)
        object.__setattr__(self, "hypothesis_expiry", MappingProxyType(expiry))


@dataclass(frozen=True, slots=True)
class CompressedCaseMemory:
    case_id: UUID
    summary: str
    summary_references: tuple[Reference, ...]
    confirmed_facts: tuple[ConfirmedFact, ...]
    active_hypotheses: tuple[Hypothesis, ...]
    archived_hypotheses: tuple[Hypothesis, ...]
    protected_artifacts: tuple[ProtectedArtifactReference, ...]
    truncated: bool


class CaseMemoryCompressor:
    """Compress narrative only; never replace trusted facts or protected artifacts."""

    def compress(
        self, memory: CaseMemoryInput, *, now: datetime, max_summary_characters: int
    ) -> CompressedCaseMemory:
        if not isinstance(memory, CaseMemoryInput):
            raise TypeError("memory must be a CaseMemoryInput")
        _utc(now, "now")
        if not isinstance(max_summary_characters, int) or not 64 <= max_summary_characters <= 16384:
            raise ValueError("max_summary_characters must be between 64 and 16384")
        active: list[Hypothesis] = []
        archived: list[Hypothesis] = []
        for item in memory.active_hypotheses:
            target = active if memory.hypothesis_expiry[item.id] > now else archived
            target.append(item)
        statements = [f"Fact: {item.statement}" for item in memory.confirmed_facts]
        statements.extend(f"Hypothesis: {item.statement}" for item in active)
        statements.extend(f"Note: {item}" for item in memory.notes)
        full = "\n".join(statements) or "No narrative case memory."
        truncated = len(full) > max_summary_characters
        summary = full[:max_summary_characters].rstrip() if truncated else full
        refs: dict[tuple[str, UUID], Reference] = {}
        for item in (*memory.confirmed_facts, *active):
            for reference in item.references:
                refs[(reference.kind.value, reference.id)] = reference
        return CompressedCaseMemory(
            memory.case_id,
            summary,
            tuple(refs[key] for key in sorted(refs, key=lambda value: (value[0], str(value[1])))),
            tuple(memory.confirmed_facts),
            tuple(active),
            tuple(archived),
            tuple(memory.protected_artifacts),
            truncated,
        )


@dataclass(frozen=True, slots=True)
class ExperienceCandidate:
    source_case_id: UUID
    lesson: str
    references: Iterable[Reference]
    redacted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.source_case_id, UUID):
            raise TypeError("source_case_id must be a UUID")
        object.__setattr__(self, "lesson", _text(self.lesson, "lesson"))
        refs = _references(self.references)
        if not refs or any(item.case_id != self.source_case_id for item in refs):
            raise MemoryBoundaryError("experience requires same-case trusted references")
        object.__setattr__(self, "references", refs)
        if not isinstance(self.redacted, bool):
            raise TypeError("redacted must be a bool")


@dataclass(frozen=True, slots=True)
class HumanConfirmation:
    id: UUID
    source_case_id: UUID
    reviewer_id: UUID
    approved: bool
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if not all(
            isinstance(item, UUID) for item in (self.id, self.source_case_id, self.reviewer_id)
        ):
            raise TypeError("confirmation identifiers must be UUID values")
        if not isinstance(self.approved, bool):
            raise TypeError("approved must be a bool")
        _utc(self.confirmed_at, "confirmed_at")


@dataclass(frozen=True, slots=True)
class ExperienceRecord:
    id: UUID
    source_case_id: UUID
    lesson: str
    references: tuple[Reference, ...]
    confirmation_id: UUID
    created_at: datetime


class LongTermExperiencePort(Protocol):
    def publish(self, record: ExperienceRecord) -> None: ...


class ExperiencePromotionService:
    def __init__(self, port: LongTermExperiencePort) -> None:
        self._port = port

    def promote(
        self,
        candidate: ExperienceCandidate,
        confirmation: HumanConfirmation,
    ) -> ExperienceRecord:
        if not isinstance(candidate, ExperienceCandidate):
            raise TypeError("candidate must be an ExperienceCandidate")
        if not isinstance(confirmation, HumanConfirmation):
            raise TypeError("confirmation must be a HumanConfirmation")
        if not confirmation.approved or confirmation.source_case_id != candidate.source_case_id:
            raise MemoryBoundaryError("matching human approval is required")
        if not candidate.redacted:
            raise MemoryBoundaryError("experience must be redacted before promotion")
        sanitized = redact_sensitive_data(candidate.lesson)
        if not isinstance(sanitized, str) or sanitized != candidate.lesson:
            raise MemoryBoundaryError("experience still contains a sensitive value")
        record = ExperienceRecord(
            uuid4(),
            candidate.source_case_id,
            candidate.lesson,
            tuple(candidate.references),
            confirmation.id,
            confirmation.confirmed_at,
        )
        self._port.publish(record)
        return record
