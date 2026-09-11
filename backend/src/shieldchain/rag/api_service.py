"""Injectable application boundary for the public knowledge API.

The default implementation is intentionally unavailable.  Production wiring must
provide the real storage/index/retrieval chain; local startup never fabricates a
successful cloud result.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from typing import Protocol
from uuid import UUID

from shieldchain.rag.schemas import (
    CreateKnowledgeBaseRequest,
    DocumentChunkListResponse,
    DocumentVersionListResponse,
    EvaluationRequest,
    EvaluationResponse,
    KnowledgeBaseDeleteResponse,
    KnowledgeBaseView,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentView,
    LifecycleOperationResponse,
    RetrievalRequest,
    RetrievalResponse,
    Sensitivity,
)


class KnowledgeApiError(Exception):
    """A categorized application error safe to translate at the HTTP boundary."""


class KnowledgeNotFound(KnowledgeApiError):
    pass


class KnowledgeAccessDenied(KnowledgeApiError):
    pass


class KnowledgeConflict(KnowledgeApiError):
    pass


class KnowledgeInputRejected(KnowledgeApiError):
    pass


class KnowledgeServiceUnavailable(KnowledgeApiError):
    pass


@dataclass(frozen=True, slots=True)
class UploadedDocument:
    filename: str
    media_type: str
    content: bytes
    sensitivity: Sensitivity
    permission_tags: tuple[str, ...]
    verified_at: date | None = None
    review_due_at: date | None = None
    source_tiers: tuple[str, ...] = ()
    source_urls: tuple[str, ...] = ()


class KnowledgeApiService(Protocol):
    def list_knowledge_bases(self, *, tenant_id: UUID) -> Sequence[KnowledgeBaseView]: ...

    def create_knowledge_base(
        self, payload: CreateKnowledgeBaseRequest, *, tenant_id: UUID
    ) -> KnowledgeBaseView: ...

    def delete_knowledge_base(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeBaseDeleteResponse: ...

    def upload_document(
        self, knowledge_base_id: UUID, upload: UploadedDocument, *, tenant_id: UUID
    ) -> KnowledgeDocumentView: ...

    def list_documents(
        self, knowledge_base_id: UUID, *, tenant_id: UUID
    ) -> KnowledgeDocumentListResponse: ...

    def list_versions(
        self, document_id: UUID, *, tenant_id: UUID
    ) -> DocumentVersionListResponse: ...

    def list_chunks(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> DocumentChunkListResponse: ...

    def publish(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse: ...

    def rollback(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse: ...

    def delete(self, document_id: UUID, *, tenant_id: UUID) -> LifecycleOperationResponse: ...

    def rebuild(
        self, document_id: UUID, version_id: UUID, *, tenant_id: UUID
    ) -> LifecycleOperationResponse: ...

    def retrieve(
        self, payload: RetrievalRequest, *, tenant_id: UUID, principal_id: UUID
    ) -> RetrievalResponse: ...

    def evaluate(
        self, payload: EvaluationRequest, *, tenant_id: UUID, principal_id: UUID
    ) -> EvaluationResponse: ...


class UnconfiguredKnowledgeApiService:
    """Fail-closed default used until real local/cloud adapters are wired."""

    @staticmethod
    def _unavailable() -> None:
        raise KnowledgeServiceUnavailable(
            "Knowledge service adapters are not configured for this local profile"
        )

    def __getattr__(self, _name: str):
        def unavailable(*_args: object, **_kwargs: object) -> None:
            self._unavailable()

        return unavailable
