import json

import structlog

from shieldchain.core.logging import configure_logging, redact_sensitive_fields


def test_redaction_removes_nested_secrets_and_preserves_safe_values() -> None:
    event = {
        "authorization": "Bearer abc",
        "payload": {
            "api_key": "test-secret",
            "query": "safe",
            "items": [
                {"password": "hidden", "name": "first"},
                {"details": {"token": "hidden-too", "count": 2}},
            ],
        },
    }

    result = redact_sensitive_fields(None, "info", event)

    assert result == {
        "authorization": "[REDACTED]",
        "payload": {
            "api_key": "[REDACTED]",
            "query": "safe",
            "items": [
                {"password": "[REDACTED]", "name": "first"},
                {"details": {"token": "[REDACTED]", "count": 2}},
            ],
        },
    }


def test_redaction_matches_mixed_case_and_containing_key_variants() -> None:
    event = {
        "AuthorizationHeader": "Bearer abc",
        "service_API_KEY_value": "key-value",
        "refreshToken": "token-value",
        "dbPASSWORDHash": "password-value",
        "ClientSecretName": "secret-value",
        "sessionCOOKIEValue": "cookie-value",
        "safe_key": "preserved",
    }

    result = redact_sensitive_fields(None, "info", event)

    assert result == {
        "AuthorizationHeader": "[REDACTED]",
        "service_API_KEY_value": "[REDACTED]",
        "refreshToken": "[REDACTED]",
        "dbPASSWORDHash": "[REDACTED]",
        "ClientSecretName": "[REDACTED]",
        "sessionCOOKIEValue": "[REDACTED]",
        "safe_key": "preserved",
    }


def test_configured_log_output_redacts_secret_values(capsys) -> None:
    configure_logging("test")
    logger = structlog.get_logger("shieldchain.test")

    logger.info(
        "redaction_check",
        authorization="Bearer abc",
        payload={"client_secret": "test-secret", "result": "safe"},
    )

    output = capsys.readouterr().out
    assert "Bearer abc" not in output
    assert "test-secret" not in output
    assert "[REDACTED]" in output
    assert "safe" in output


def test_non_test_environment_emits_json(capsys) -> None:
    configure_logging("production")

    structlog.get_logger("shieldchain.test").info("json_check", result="safe")

    event = json.loads(capsys.readouterr().out)
    assert event["event"] == "json_check"
    assert event["result"] == "safe"
    assert event["level"] == "info"
    assert "timestamp" in event
