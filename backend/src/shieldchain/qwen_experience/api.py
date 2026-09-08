from typing import cast

from fastapi import APIRouter, Request

from shieldchain.core.errors import ApiError

from .model_control import ControlError, catalog, inference, select
from .schemas import (
    ModelSelectionRequest,
    QwenExperienceChatRequest,
    QwenExperienceChatResponse,
    QwenExperienceStatusResponse,
)
from .service import QwenExperienceService, QwenExperienceUnavailable

router = APIRouter(prefix="/qwen", tags=["qwen-experience"])


@router.get("/models")
def models():
    try:
        return catalog()
    except (ControlError, OSError):
        raise ApiError("model_control_unavailable", "模型切换服务暂不可用", 503) from None


@router.post("/select")
def select_model(payload: ModelSelectionRequest):
    try:
        return select(payload.model)
    except ControlError as error:
        raise ApiError("model_switch_conflict", str(error), 409) from None
    except OSError:
        raise ApiError("model_control_unavailable", "模型切换服务暂不可用", 503) from None


def _service(request: Request) -> QwenExperienceService:
    return cast(QwenExperienceService, request.app.state.qwen_experience_service)


@router.get("/status", response_model=QwenExperienceStatusResponse)
async def status(request: Request) -> QwenExperienceStatusResponse:
    return await _service(request).status()


@router.post("/chat", response_model=QwenExperienceChatResponse)
async def chat(payload: QwenExperienceChatRequest, request: Request) -> QwenExperienceChatResponse:
    try:
        if payload.model is not None:
            with inference(payload.model) as served_model:
                return await _service(request).chat(payload, model=served_model)
        return await _service(request).chat(payload)
    except ControlError as error:
        raise ApiError("model_not_ready", str(error), 409) from None
    except QwenExperienceUnavailable as error:
        raise ApiError("qwen_unavailable", str(error), 503) from None
