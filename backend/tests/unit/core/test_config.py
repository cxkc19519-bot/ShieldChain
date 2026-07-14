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
