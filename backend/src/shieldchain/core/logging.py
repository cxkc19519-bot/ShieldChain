import logging
import re
import sys
from collections.abc import Mapping
from typing import Any

import structlog

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_KEY_PARTS = (
    "authorization",
    "api_key",
    "token",
    "password",
    "secret",
    "cookie",
    "tenant_id",
    "principal_id",
    "actor_subject_id",
    "raw_prompt",
    "system_prompt",
    "chain_of_thought",
    "reasoning_trace",
    "raw_payload",
    "evidence_payload",
)

_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*"
        r"[^\s,;]+"
    ),
)


def _is_sensitive_key(key: object) -> bool:
    normalized_key = str(key).lower()
    return any(part in normalized_key for part in SENSITIVE_KEY_PARTS)


def redact_sensitive_data(value: object) -> object:
    """Recursively redact sensitive keys and common inline credential forms."""
    if isinstance(value, Mapping):
        return {
            key: REDACTED_VALUE if _is_sensitive_key(key) else redact_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        for pattern in _SENSITIVE_VALUE_PATTERNS:
            value = pattern.sub(REDACTED_VALUE, value)
    return value


def redact_sensitive_fields(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, object],
) -> dict[str, object]:
    return {
        key: REDACTED_VALUE if _is_sensitive_key(key) else redact_sensitive_data(value)
        for key, value in event_dict.items()
    }


def configure_logging(environment: str) -> None:
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        redact_sensitive_fields,
    ]

    if environment.lower() == "test":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer(
            colors=False,
            pad_event_to=0,
            sort_keys=True,
        )
    else:
        shared_processors.append(structlog.processors.TimeStamper(fmt="iso", utc=True))
        renderer = structlog.processors.JSONRenderer(sort_keys=True)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )
