"""Tenant-bounded persistence contracts for agent context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy.orm import Session

from shieldchain.agents.domain import (
    AgentOutput,
    AgentPrivateContext,
    AgentRole,
    ConfirmedFact,
    HandoffPacket,
    SharedCaseContext,
)
from shieldchain.rag.domain import AccessScope


class AgentContextError(RuntimeError):
    """Base class for fail-closed context persistence errors."""


class AgentRunNotFound(AgentContextError):
    pass


class AgentContextNotFound(AgentContextError):
    pass


class AgentContextAlreadyExists(AgentContextError):
    pass


class StaleContextRevision(AgentContextError):
    pass


class InvalidTrustedReference(AgentContextError):
    pass


class PrivateContextAccessDenied(AgentContextError):
    pass


@dataclass(frozen=True, slots=True)
class VersionedPrivateContext:
    context: AgentPrivateContext
    revision: int


class AgentContextRepository(Protocol):
    def create_shared(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        context: SharedCaseContext,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext: ...

    def get_shared(
        self, session: Session, *, tenant_id: UUID, run_id: UUID
    ) -> SharedCaseContext | None: ...

    def update_shared(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        context: SharedCaseContext,
        expected_revision: int,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> SharedCaseContext: ...

    def append_fact(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        fact: ConfirmedFact,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None: ...

    def get_private(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        acting_role: AgentRole,
        role: AgentRole,
    ) -> VersionedPrivateContext | None: ...

    def upsert_private(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        acting_role: AgentRole,
        context: AgentPrivateContext,
        expected_revision: int | None,
        knowledge_scope: AccessScope | None = None,
    ) -> VersionedPrivateContext: ...

    def append_handoff(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        handoff: HandoffPacket,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None: ...

    def append_output(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        output: AgentOutput,
        request_id: str,
        knowledge_scope: AccessScope | None = None,
    ) -> None: ...
