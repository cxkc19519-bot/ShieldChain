from __future__ import annotations

import structlog

from shieldchain.core.logging import REDACTED_VALUE, configure_logging, redact_sensitive_fields


def test_redaction_removes_sensitive_values_embedded_in_strings() -> None:
    secret = "sk-live-1234567890abcdef"
    bearer = "header.payload.signature-secret"
    event = {
        "event": f"provider failed api_key={secret}",
        "detail": [f"Authorization: Bearer {bearer}", "safe diagnostic"],
    }

    result = redact_sensitive_fields(None, "error", event)
    serialized = repr(result)
    assert secret not in serialized
    assert bearer not in serialized
    assert REDACTED_VALUE in serialized
    assert "safe diagnostic" in serialized


def test_configured_logging_does_not_leak_embedded_bearer_value(capsys) -> None:
    configure_logging("test")
    secret = "very-sensitive-bearer-token"

    structlog.get_logger().warning("upstream failed", detail=f"Bearer {secret}")

    output = capsys.readouterr().out
    assert secret not in output
    assert REDACTED_VALUE in output


def test_redaction_removes_private_identity_prompt_reasoning_and_raw_payloads() -> None:
    event = {
        "tenant_id": "tenant-private",
        "principal_id": "principal-private",
        "actor_subject_id": "actor-private",
        "raw_prompt": "prompt-private",
        "chain_of_thought": "reasoning-private",
        "evidence_payload": {"raw": "evidence-private"},
        "request_id": "req-safe",
        "status": 200,
    }
    result = redact_sensitive_fields(None, "info", event)
    serialized = repr(result)
    for forbidden in (
        "tenant-private",
        "principal-private",
        "actor-private",
        "prompt-private",
        "reasoning-private",
        "evidence-private",
    ):
        assert forbidden not in serialized
    assert result["request_id"] == "req-safe"
    assert result["status"] == 200
