from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

ChatRole = Literal["system", "user", "assistant"]
VALID_CHAT_ROLES = frozenset({"system", "user", "assistant"})


class LlmError(Exception):
    """Base error raised by an LLM adapter."""


class LlmAuthenticationError(LlmError):
    """The configured LLM credentials were rejected."""


class LlmRateLimitError(LlmError):
    """The LLM remained rate limited after bounded retries."""


class LlmUnavailableError(LlmError):
    """The LLM remained unavailable after bounded retries."""


class LlmResponseError(LlmError):
    """The LLM returned an invalid or unsupported response."""


@dataclass(frozen=True)
class ChatMessage:
    role: ChatRole
    content: str

    def __post_init__(self) -> None:
        if self.role not in VALID_CHAT_ROLES:
            raise ValueError("invalid role")
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("content must not be empty")


@dataclass(frozen=True)
class ChatRequest:
    messages: tuple[ChatMessage, ...]
    temperature: float = 0.0
    max_tokens: int = 1024

    def __post_init__(self) -> None:
        try:
            messages = tuple(self.messages)
        except TypeError:
            raise ValueError("messages must be iterable") from None
        object.__setattr__(self, "messages", messages)
        if not self.messages:
            raise ValueError("at least one message is required")
        if not all(isinstance(message, ChatMessage) for message in self.messages):
            raise ValueError("messages must contain ChatMessage values")
        if not isinstance(self.temperature, int | float) or isinstance(self.temperature, bool):
            raise ValueError("temperature must be between 0 and 2")
        if not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")
        if not isinstance(self.max_tokens, int) or isinstance(self.max_tokens, bool):
            raise ValueError("max_tokens must be between 1 and 8192")
        if not 1 <= self.max_tokens <= 8192:
            raise ValueError("max_tokens must be between 1 and 8192")


@dataclass(frozen=True)
class ChatResponse:
    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int


class LlmClient(Protocol):
    @property
    def model(self) -> str: ...

    async def chat(self, request: ChatRequest) -> ChatResponse: ...
