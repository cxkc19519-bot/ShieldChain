"""Schemas for the persistent grounded assistant."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssistantChatRequest(StrictModel):
    message: str = Field(min_length=1, max_length=4096)
    conversation_id: UUID | None = None

    @field_validator("message")
    @classmethod
    def non_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("message must not be blank")
        return value


class AssistantCitationView(StrictModel):
    index: int = Field(ge=1)
    document_title: str
    excerpt: str
    fusion_score: float = Field(ge=0, le=1)


class AssistantMessageView(StrictModel):
    id: UUID
    role: Literal["user", "assistant"]
    content: str
    citations: list[AssistantCitationView] = Field(default_factory=list)
    model: str | None = None
    created_at: datetime


class AssistantConversationView(StrictModel):
    id: UUID
    title: str
    created_at: datetime
    updated_at: datetime
    memory_summary: str
    summary: str
    message_count: int = Field(ge=0)


class AssistantConversationDetail(AssistantConversationView):
    messages: list[AssistantMessageView] = Field(default_factory=list)


class AssistantConversationListResponse(StrictModel):
    items: list[AssistantConversationView] = Field(default_factory=list)


class AssistantChatResponse(StrictModel):
    conversation_id: UUID
    answer: str
    model: str | None = None
    citations: list[AssistantCitationView] = Field(default_factory=list)
    report_documents_synced: int = Field(ge=0)
    memory_summary: str
