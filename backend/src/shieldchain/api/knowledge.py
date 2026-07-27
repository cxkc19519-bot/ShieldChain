"""Tenant-bound, strict HTTP boundary for knowledge and RAG operations."""

from pathlib import PurePath
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request, status
from starlette.datastructures import UploadFile

from shieldchain.core.errors import ApiError
from shieldchain.rag.api_service import (
    KnowledgeAccessDenied,
    KnowledgeApiService,
    KnowledgeConflict,
    KnowledgeInputRejected,
    KnowledgeNotFound,
    KnowledgeServiceUnavailable,
    UploadedDocument,
)
from shieldchain.rag.schemas import (
    CreateKnowledgeBaseRequest,
    DocumentChunkListResponse,
    DocumentVersionListResponse,
    EvaluationRequest,
    EvaluationResponse,
    KnowledgeBaseDeleteResponse,
    KnowledgeBaseListResponse,
    KnowledgeBaseView,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentView,
    LifecycleOperationResponse,
    RetrievalRequest,
    RetrievalResponse,
)

router = APIRouter(tags=["knowledge"])
_UPLOAD_FIELDS = frozenset({"file", "sensitivity", "permission_tags"})
_SENSITIVITIES = frozenset({"public", "internal", "confidential", "restricted"})
_UPLOAD_MEDIA_TYPES = {
    ".pdf": frozenset({"application/pdf"}),
    ".docx": frozenset({"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}),
    ".md": frozenset({"text/markdown", "text/plain"}),
    ".txt": frozenset({"text/plain"}),
    ".html": frozenset({"text/html"}),
    ".csv": frozenset({"text/csv", "application/vnd.ms-excel"}),
    ".xlsx": frozenset({"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}),
}


def _service(request: Request) -> KnowledgeApiService:
    return cast(KnowledgeApiService, request.app.state.knowledge_api_service)


def _tenant_id(request: Request) -> UUID:
    return cast(UUID, request.app.state.rag_demo_tenant_id)


def _principal_id(request: Request) -> UUID:
    return cast(UUID, request.app.state.rag_demo_principal_id)


def _public_error(error: Exception) -> ApiError:
    if isinstance(error, (KnowledgeNotFound, KnowledgeAccessDenied)):
        return ApiError("knowledge_not_found", "Knowledge resource not found", 404)
    if isinstance(error, KnowledgeConflict):
        return ApiError("knowledge_conflict", "Knowledge operation conflicts with state", 409)
    if isinstance(error, KnowledgeInputRejected):
        return ApiError("knowledge_input_rejected", "Knowledge input was rejected", 400)
    if isinstance(error, KnowledgeServiceUnavailable):
        return ApiError(
            "knowledge_service_unconfigured",
            "Knowledge service is not configured for this profile",
            503,
        )
    raise error


def _call(operation):
    try:
        return operation()
    except Exception as error:
        raise _public_error(error) from None


@router.get("/knowledge-bases", response_model=KnowledgeBaseListResponse)
def list_knowledge_bases(request: Request) -> KnowledgeBaseListResponse:
    items = _call(lambda: _service(request).list_knowledge_bases(tenant_id=_tenant_id(request)))
    return KnowledgeBaseListResponse(items=list(items))


@router.post(
    "/knowledge-bases",
    status_code=status.HTTP_201_CREATED,
    response_model=KnowledgeBaseView,
)
def create_knowledge_base(
    payload: CreateKnowledgeBaseRequest, request: Request
) -> KnowledgeBaseView:
    return _call(
        lambda: _service(request).create_knowledge_base(payload, tenant_id=_tenant_id(request))
    )


@router.delete(
    "/knowledge-bases/{knowledge_base_id}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=KnowledgeBaseDeleteResponse,
)
def delete_knowledge_base(knowledge_base_id: UUID, request: Request) -> KnowledgeBaseDeleteResponse:
    return _call(
        lambda: _service(request).delete_knowledge_base(
            knowledge_base_id, tenant_id=_tenant_id(request)
        )
    )


@router.post(
    "/knowledge-bases/{knowledge_base_id}/documents",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=KnowledgeDocumentView,
)
async def upload_document(knowledge_base_id: UUID, request: Request) -> KnowledgeDocumentView:
    content_length = request.headers.get("content-length")
    maximum = request.app.state.settings.rag_max_upload_bytes
    if content_length is None:
        raise ApiError(
            "content_length_required",
            "Content-Length is required for bounded uploads",
            411,
        )
    try:
        declared_length = int(content_length)
    except ValueError:
        raise ApiError("invalid_content_length", "Content-Length is invalid", 400) from None
    if declared_length < 1:
        raise ApiError("invalid_content_length", "Content-Length is invalid", 400)
    if declared_length > maximum + 64 * 1024:
        raise ApiError("upload_too_large", "Upload exceeds configured limit", 413)
    try:
        form = await request.form(max_files=1, max_fields=3, max_part_size=maximum)
    except Exception as error:
        raise ApiError("invalid_multipart", "Multipart upload is invalid", 400) from error
    if set(form.keys()) - _UPLOAD_FIELDS or "file" not in form:
        raise ApiError("unsafe_upload_fields", "Upload contains unsupported fields", 422)
    file = form["file"]
    if not isinstance(file, UploadFile):
        raise ApiError("invalid_upload", "A multipart file is required", 422)
    filename = (file.filename or "").strip()
    if (
        not filename
        or "/" in filename
        or "\\" in filename
        or "://" in filename
        or filename.startswith(("~", "."))
    ):
        await file.close()
        raise ApiError("unsafe_filename", "Upload filename is unsafe", 422)
    sensitivity = str(form.get("sensitivity", "internal")).strip().casefold()
    if sensitivity not in _SENSITIVITIES:
        await file.close()
        raise ApiError("invalid_sensitivity", "Sensitivity is invalid", 422)
    raw_tags = str(form.get("permission_tags", "")).strip()
    tags = tuple(dict.fromkeys(tag.strip() for tag in raw_tags.split(",") if tag.strip()))
    if len(tags) > 32 or any(len(tag) > 64 for tag in tags):
        await file.close()
        raise ApiError("invalid_permission_tags", "Permission tags are invalid", 422)
    media_type = file.content_type or "application/octet-stream"
    extension = PurePath(filename).suffix.casefold()
    if (
        extension not in _UPLOAD_MEDIA_TYPES
        or media_type.casefold() not in (_UPLOAD_MEDIA_TYPES[extension])
    ):
        await file.close()
        raise ApiError("unsupported_document", "Document format is not supported", 422)
    content = await file.read(maximum + 1)
    await file.close()
    if not content:
        raise ApiError("empty_upload", "Upload must not be empty", 422)
    if len(content) > maximum:
        raise ApiError("upload_too_large", "Upload exceeds configured limit", 413)
    upload = UploadedDocument(filename, media_type, content, sensitivity, tags)  # type: ignore[arg-type]
    return _call(
        lambda: _service(request).upload_document(
            knowledge_base_id, upload, tenant_id=_tenant_id(request)
        )
    )


@router.get(
    "/knowledge-bases/{knowledge_base_id}/documents",
    response_model=KnowledgeDocumentListResponse,
)
def list_documents(knowledge_base_id: UUID, request: Request) -> KnowledgeDocumentListResponse:
    return _call(
        lambda: _service(request).list_documents(knowledge_base_id, tenant_id=_tenant_id(request))
    )


@router.get("/documents/{document_id}/versions", response_model=DocumentVersionListResponse)
def list_versions(document_id: UUID, request: Request) -> DocumentVersionListResponse:
    return _call(
        lambda: _service(request).list_versions(document_id, tenant_id=_tenant_id(request))
    )


@router.get(
    "/documents/{document_id}/versions/{version_id}/chunks",
    response_model=DocumentChunkListResponse,
)
def list_chunks(document_id: UUID, version_id: UUID, request: Request) -> DocumentChunkListResponse:
    return _call(
        lambda: _service(request).list_chunks(
            document_id, version_id, tenant_id=_tenant_id(request)
        )
    )


def _lifecycle(request: Request, method: str, document_id: UUID, version_id: UUID | None = None):
    service = _service(request)
    tenant_id = _tenant_id(request)
    if version_id is None:
        return _call(lambda: service.delete(document_id, tenant_id=tenant_id))
    operation = getattr(service, method)
    return _call(lambda: operation(document_id, version_id, tenant_id=tenant_id))


@router.post(
    "/documents/{document_id}/versions/{version_id}/publish",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LifecycleOperationResponse,
)
def publish(document_id: UUID, version_id: UUID, request: Request) -> LifecycleOperationResponse:
    return _lifecycle(request, "publish", document_id, version_id)


@router.post(
    "/documents/{document_id}/versions/{version_id}/rollback",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LifecycleOperationResponse,
)
def rollback(document_id: UUID, version_id: UUID, request: Request) -> LifecycleOperationResponse:
    return _lifecycle(request, "rollback", document_id, version_id)


@router.post(
    "/documents/{document_id}/versions/{version_id}/rebuild",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LifecycleOperationResponse,
)
def rebuild(document_id: UUID, version_id: UUID, request: Request) -> LifecycleOperationResponse:
    return _lifecycle(request, "rebuild", document_id, version_id)


@router.delete(
    "/documents/{document_id}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LifecycleOperationResponse,
)
def delete(document_id: UUID, request: Request) -> LifecycleOperationResponse:
    return _lifecycle(request, "delete", document_id)


@router.post("/rag/retrieval", response_model=RetrievalResponse)
def retrieve(payload: RetrievalRequest, request: Request) -> RetrievalResponse:
    return _call(
        lambda: _service(request).retrieve(
            payload, tenant_id=_tenant_id(request), principal_id=_principal_id(request)
        )
    )


@router.post("/rag/evaluations", response_model=EvaluationResponse)
def evaluate(payload: EvaluationRequest, request: Request) -> EvaluationResponse:
    return _call(
        lambda: _service(request).evaluate(
            payload, tenant_id=_tenant_id(request), principal_id=_principal_id(request)
        )
    )
