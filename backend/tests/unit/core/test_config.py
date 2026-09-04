from pathlib import Path

import pytest
from pydantic import AnyHttpUrl, ValidationError

from shieldchain.core.config import Settings, get_settings


def test_settings_use_safe_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment == "development"
    assert settings.database_url == "sqlite:///./data/shieldchain.db"
    assert settings.deepseek_base_url == AnyHttpUrl("https://api.deepseek.com")
    assert settings.deepseek_model == "deepseek-chat"
    assert settings.deepseek_api_key.get_secret_value() == ""
    assert settings.simulation_step_delay_ms == 600
    assert settings.simulation_shutdown_timeout_seconds == 5.0
    assert settings.http_allowed_hosts == ("127.0.0.1", "localhost", "testserver")
    assert settings.http_allowed_origins == ("http://127.0.0.1:5173", "http://localhost:5173")
    assert settings.http_max_request_bytes == 26 * 1024 * 1024
    assert settings.mcp_server_enabled is False
    assert settings.mcp_auth_max_token_lifetime_seconds == 900
    assert settings.mcp_remote_config_path is None
    assert settings.mcp_remote_snapshot_ttl_seconds == 3600
    assert settings.mcp_remote_max_tools == 100
    assert settings.rag_evaluation_root == Path("sample_docs/security_vertical/evaluation")


def test_remote_mcp_limits_are_bounded_and_empty_path_is_disabled() -> None:
    assert Settings(_env_file=None, mcp_remote_config_path="").mcp_remote_config_path is None
    for field, value in (
        ("mcp_remote_snapshot_ttl_seconds", 86_401),
        ("mcp_remote_discovery_timeout_seconds", 31),
        ("mcp_remote_max_discovery_pages", 11),
        ("mcp_remote_max_tools", 101),
        ("mcp_remote_max_schema_bytes", 65_537),
        ("mcp_remote_max_catalog_schema_bytes", 1_048_577),
        ("mcp_remote_max_request_bytes", 262_145),
        ("mcp_remote_max_response_bytes", 2_097_153),
        ("mcp_remote_max_public_result_bytes", 65_537),
        ("mcp_remote_call_timeout_seconds", 31),
        ("mcp_remote_max_calls_per_run", 11),
        ("mcp_remote_peer_concurrency", 5),
        ("mcp_remote_peer_calls_per_minute", 121),
        ("mcp_remote_circuit_failure_threshold", 11),
        ("mcp_remote_circuit_open_seconds", 301),
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("simulation_step_delay_ms", -1),
        ("simulation_step_delay_ms", 2001),
        ("simulation_shutdown_timeout_seconds", 0.9),
        ("simulation_shutdown_timeout_seconds", 30.1),
    ],
)
def test_simulation_settings_enforce_bounds(field, value) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("http_allowed_hosts", ()),
        ("http_allowed_hosts", ("https://example.com",)),
        ("http_allowed_origins", ()),
        ("http_allowed_origins", ("https://example.com/path",)),
        ("http_max_request_bytes", 100),
    ],
)
def test_http_settings_reject_unsafe_values(field, value) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_production_rejects_wildcard_trust_but_development_can_explicitly_use_it() -> None:
    development = Settings(
        _env_file=None,
        environment="development",
        http_allowed_hosts=("*",),
        http_allowed_origins=("*",),
    )
    assert development.http_allowed_hosts == ("*",)
    with pytest.raises(ValidationError, match="wildcards"):
        Settings(
            _env_file=None,
            environment="production",
            http_allowed_hosts=("*",),
        )


def test_production_rejects_mcp_server_until_authorization_is_implemented() -> None:
    with pytest.raises(ValidationError, match="authorization"):
        Settings(
            _env_file=None,
            environment="production",
            mcp_server_enabled=True,
        )


def test_testing_can_enable_mcp_without_oauth_but_development_cannot() -> None:
    testing = Settings(
        _env_file=None,
        environment="testing",
        mcp_server_enabled=True,
    )
    assert testing.mcp_auth_mode == "disabled"
    with pytest.raises(ValidationError, match="testing"):
        Settings(
            _env_file=None,
            environment="development",
            mcp_server_enabled=True,
        )


def test_production_accepts_only_complete_https_mcp_oauth_configuration() -> None:
    values = {
        "environment": "production",
        "mcp_server_enabled": True,
        "mcp_auth_mode": "oauth",
        "mcp_auth_issuer": "https://identity.example.test",
        "mcp_auth_resource": "https://shieldchain.example.test/mcp",
        "mcp_auth_jwks_url": "https://identity.example.test/.well-known/jwks.json",
        "mcp_auth_audience": "shieldchain-mcp",
        "mcp_auth_subject_principals": {
            "security-operator": "00000000-0000-4000-8000-000000000010"
        },
    }
    settings = Settings(_env_file=None, **values)
    assert settings.mcp_auth_mode == "oauth"
    with pytest.raises(ValidationError, match="HTTPS"):
        Settings(
            _env_file=None,
            **{**values, "mcp_auth_jwks_url": "http://identity.example.test/jwks"},
        )
    with pytest.raises(ValidationError, match="subject"):
        Settings(
            _env_file=None,
            **{**values, "mcp_auth_subject_principals": {}},
        )


def test_enabled_mcp_server_rejects_wildcard_http_trust() -> None:
    with pytest.raises(ValidationError, match="MCP trust"):
        Settings(
            _env_file=None,
            mcp_server_enabled=True,
            http_allowed_hosts=("*",),
        )


def test_settings_load_secret_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-secret")

    settings = Settings(_env_file=None)

    assert settings.deepseek_api_key.get_secret_value() == "test-secret"
    assert "test-secret" not in repr(settings)


def test_get_settings_returns_cached_instance(monkeypatch) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "testing")

    first = get_settings()
    second = get_settings()

    assert first is second
    assert first.environment == "testing"
    get_settings.cache_clear()
