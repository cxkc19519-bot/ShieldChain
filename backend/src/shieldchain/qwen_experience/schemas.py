from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QwenExperienceMessage(StrictModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class QwenExperienceChatRequest(StrictModel):
    messages: list[QwenExperienceMessage] = Field(min_length=1, max_length=20)
    temperature: float = Field(default=0.7, ge=0, le=1.5)
    max_tokens: int = Field(default=1024, ge=64, le=2048)

    @model_validator(mode="after")
    def validate_conversation(self) -> QwenExperienceChatRequest:
        if self.messages[-1].role != "user":
            raise ValueError("the final message must be from the user")
        if self.messages[0].role != "user":
            raise ValueError("the conversation must start with a user message")
        if any(left.role == right.role for left, right in zip(self.messages, self.messages[1:])):
            raise ValueError("message roles must alternate")
        if sum(len(message.content) for message in self.messages) > 24_000:
            raise ValueError("conversation content is too large")
        return self


class QwenExperienceChatResponse(StrictModel):
    content: str
    model: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)


class QwenExperienceStatusResponse(StrictModel):
    ready: bool
    model: str
    provider: Literal["local-qwen", "configured-openai-compatible"]
