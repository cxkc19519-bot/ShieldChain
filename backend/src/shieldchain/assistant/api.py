"""HTTP boundary for the persistent grounded assistant."""

from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request, status

from shieldchain.core.errors import ApiError

from .schemas import (
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantConversationDetail,
    AssistantConversationListResponse,
    AssistantConversationPinRequest,
    AssistantConversationRenameRequest,
    AssistantConversationView,
    AssistantEvaluationRequest,
    AssistantEvaluationResponse,
)
from .service import (
    AssistantEvaluationRejected,
    AssistantUnavailable,
    GroundedAssistantService,
)
from .store import ConversationNotFound, LocalConversationStore

router = APIRouter(tags=["assistant"])


def _service(request: Request) -> GroundedAssistantService:
    return cast(GroundedAssistantService, request.app.state.grounded_assistant_service)


def _view(row: dict[str, object]) -> AssistantConversationView:
    return AssistantConversationView(
        id=UUID(str(row["id"])),
        title=str(row["title"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        memory_summary=str(row.get("memory_summary", "")),
        summary=str(row.get("summary") or row.get("title") or "新的安全咨询"),
        pinned=bool(row.get("pinned", False)),
        message_count=len(row.get("messages", [])),
    )


@router.get("/assistant/conversations", response_model=AssistantConversationListResponse)
def conversations(request: Request) -> AssistantConversationListResponse:
    return AssistantConversationListResponse(
        items=[_view(row) for row in _service(request).conversations()]
    )


@router.get(
    "/assistant/conversations/{conversation_id}",
    response_model=AssistantConversationDetail,
)
def conversation(conversation_id: UUID, request: Request) -> AssistantConversationDetail:
    try:
        row = _service(request).conversation(conversation_id)
    except ConversationNotFound:
        raise ApiError("conversation_not_found", "Conversation not found", 404) from None
    view = _view(row)
    return AssistantConversationDetail(
        **view.model_dump(),
        messages=LocalConversationStore.messages(row),
    )


@router.patch(
    "/assistant/conversations/{conversation_id}/title",
    response_model=AssistantConversationView,
)
def rename_conversation(
    conversation_id: UUID, payload: AssistantConversationRenameRequest, request: Request
) -> AssistantConversationView:
    try:
        return _view(_service(request).rename_conversation(conversation_id, payload.title))
    except ConversationNotFound:
        raise ApiError("conversation_not_found", "Conversation not found", 404) from None


@router.patch(
    "/assistant/conversations/{conversation_id}/pin",
    response_model=AssistantConversationView,
)
def pin_conversation(
    conversation_id: UUID, payload: AssistantConversationPinRequest, request: Request
) -> AssistantConversationView:
    try:
        return _view(_service(request).set_conversation_pinned(conversation_id, payload.pinned))
    except ConversationNotFound:
        raise ApiError("conversation_not_found", "Conversation not found", 404) from None

@router.delete("/assistant/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_conversation(conversation_id: UUID, request: Request) -> None:
    try:
        _service(request).delete_conversation(conversation_id)
    except ConversationNotFound:
        raise ApiError("conversation_not_found", "Conversation not found", 404) from None


@router.post("/assistant/chat", response_model=AssistantChatResponse)
async def chat(payload: AssistantChatRequest, request: Request) -> AssistantChatResponse:
    try:
        return await _service(request).chat(payload)
    except ConversationNotFound:
        raise ApiError("conversation_not_found", "Conversation not found", 404) from None
    except AssistantUnavailable as error:
        raise ApiError("assistant_unavailable", str(error), 503) from None


@router.post("/assistant/evaluations", response_model=AssistantEvaluationResponse)
async def evaluate_assistant(
    payload: AssistantEvaluationRequest, request: Request
) -> AssistantEvaluationResponse:
    try:
        return await _service(request).evaluate(payload)
    except AssistantEvaluationRejected as error:
        raise ApiError("assistant_evaluation_rejected", str(error), 422) from None
