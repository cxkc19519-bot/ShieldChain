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
