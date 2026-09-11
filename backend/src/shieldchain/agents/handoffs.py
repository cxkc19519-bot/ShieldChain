"""Structured handoff creation with reference re-resolution and append-only persistence."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from shieldchain.agents.domain import AgentRole, HandoffPacket, Reference, TrustedReference
from shieldchain.rag.domain import AccessScope


class HandoffServiceError(RuntimeError):
    """A handoff failed its deterministic trust boundary."""


class HandoffClaimStatus(StrEnum):
    UNVERIFIED = "unverified"


def _utc(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be an aware UTC datetime")


def _text(value: str, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds maximum length {maximum}")
    return value.strip()


def _strings(values: Iterable[str], name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be iterable")
    try:
        frozen = tuple(_text(item, name) for item in values)
    except TypeError as error:
        raise TypeError(f"{name} must be iterable") from error
    return frozen


def _references(values: Iterable[Reference]) -> tuple[Reference, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError("references must be iterable")
    try:
        frozen = tuple(values)
    except TypeError as error:
        raise TypeError("references must be iterable") from error
    if not frozen or any(not isinstance(item, TrustedReference) for item in frozen):
        raise HandoffServiceError("handoff requires trusted references")
    return frozen


@dataclass(frozen=True, slots=True)
class HandoffDraft:
    id: UUID
    case_id: UUID
    sender: AgentRole
    receiver: AgentRole
    conclusion: str
    references: Iterable[Reference]
    confidence: float
    open_questions: Iterable[str]
    proposed_actions: Iterable[str]
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID) or not isinstance(self.case_id, UUID):
            raise TypeError("id and case_id must be UUID values")
        if not isinstance(self.sender, AgentRole) or not isinstance(self.receiver, AgentRole):
            raise TypeError("sender and receiver must be AgentRole values")
        if self.sender is self.receiver:
            raise ValueError("sender and receiver must be different")
        object.__setattr__(self, "conclusion", _text(self.conclusion, "conclusion"))
        refs = _references(self.references)
        if any(item.case_id != self.case_id for item in refs):
            raise HandoffServiceError("handoff reference belongs to another case")
        object.__setattr__(self, "references", refs)
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not math.isfinite(self.confidence)
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be between 0 and 1")
        object.__setattr__(self, "open_questions", _strings(self.open_questions, "open_questions"))
        actions = _strings(self.proposed_actions, "proposed_actions")
        if not actions:
            raise ValueError("proposed_actions must not be empty")
        object.__setattr__(self, "proposed_actions", actions)
        _utc(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class ReceivedHandoffClaim:
    packet: HandoffPacket
    status: HandoffClaimStatus = HandoffClaimStatus.UNVERIFIED
    confirmed_fact: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.packet, HandoffPacket):
            raise TypeError("packet must be a HandoffPacket")
        if self.status is not HandoffClaimStatus.UNVERIFIED or self.confirmed_fact is not False:
            raise HandoffServiceError("received handoff must remain an unverified claim")


class HandoffReferenceResolver(Protocol):
    def resolve(
        self,
        *,
        case_id: UUID,
        references: tuple[Reference, ...],
        knowledge_scope: AccessScope | None,
    ) -> tuple[Reference, ...]: ...


class AppendOnlyHandoffWriter(Protocol):
    def append_handoff(
        self,
        handoff: HandoffPacket,
        *,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None: ...


class StructuredHandoffService:
    def __init__(
        self,
        *,
        resolver: HandoffReferenceResolver,
        writer: AppendOnlyHandoffWriter,
    ) -> None:
        self._resolver = resolver
        self._writer = writer

    def submit(
        self,
        draft: HandoffDraft,
        *,
        acting_role: AgentRole,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> ReceivedHandoffClaim:
        if not isinstance(draft, HandoffDraft):
            raise TypeError("draft must be a HandoffDraft")
        if not isinstance(acting_role, AgentRole) or acting_role is not draft.sender:
            raise HandoffServiceError("only the declared sender may submit a handoff")
        request_id = _text(request_id, "request_id", maximum=256)
        resolved = self._resolver.resolve(
            case_id=draft.case_id,
            references=tuple(draft.references),
            knowledge_scope=knowledge_scope,
        )
        self._verify_resolution(draft, resolved)
        packet = HandoffPacket(
            draft.id,
            draft.case_id,
            draft.sender,
            draft.receiver,
            draft.conclusion,
            resolved,
            draft.confidence,
            draft.open_questions,
            draft.proposed_actions,
            draft.created_at,
        )
        self._writer.append_handoff(
            packet,
            request_id=request_id,
            knowledge_scope=knowledge_scope,
        )
        return ReceivedHandoffClaim(packet)

    @staticmethod
    def _verify_resolution(draft: HandoffDraft, resolved: tuple[Reference, ...]) -> None:
        if not isinstance(resolved, tuple) or not resolved:
            raise HandoffServiceError("references did not resolve")
        if any(not isinstance(item, TrustedReference) for item in resolved):
            raise HandoffServiceError("resolver returned an untrusted reference")
        expected = tuple(item.to_dict() for item in draft.references)
        actual = tuple(item.to_dict() for item in resolved)
        if expected != actual or any(item.case_id != draft.case_id for item in resolved):
            raise HandoffServiceError("resolved references do not match the submitted claim")
