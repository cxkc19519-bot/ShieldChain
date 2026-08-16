from typing import cast

from fastapi import APIRouter, Request

from shieldchain.core.errors import ApiError

from .schemas import (
    QwenExperienceChatRequest,
    QwenExperienceChatResponse,
    QwenExperienceStatusResponse,
)
from .service import QwenExperienceService, QwenExperienceUnavailable

router = APIRouter(prefix="/qwen", tags=["qwen-experience"])


def _service(request: Request) -> QwenExperienceService:
    return cast(QwenExperienceService, request.app.state.qwen_experience_service)


@router.get("/status", response_model=QwenExperienceStatusResponse)
async def status(request: Request) -> QwenExperienceStatusResponse:
    return await _service(request).status()


@router.post("/chat", response_model=QwenExperienceChatResponse)
async def chat(payload: QwenExperienceChatRequest, request: Request) -> QwenExperienceChatResponse:
    try:
        return await _service(request).chat(payload)
    except QwenExperienceUnavailable as error:
        raise ApiError("qwen_unavailable", str(error), 503) from None
