import logging
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
)


def _is_sensitive_key(key: object) -> bool:
    normalized_key = str(key).lower()
    return any(part in normalized_key for part in SENSITIVE_KEY_PARTS)


def _redact(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            key: REDACTED_VALUE if _is_sensitive_key(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    return value


def redact_sensitive_fields(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, object],
) -> dict[str, object]:
    return {
        key: REDACTED_VALUE if _is_sensitive_key(key) else _redact(value)
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
