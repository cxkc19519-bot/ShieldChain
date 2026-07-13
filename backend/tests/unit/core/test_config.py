from pydantic import AnyHttpUrl

from shieldchain.core.config import Settings, get_settings


def test_settings_use_safe_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment == "development"
    assert settings.database_url == "sqlite:///./data/shieldchain.db"
    assert settings.deepseek_base_url == AnyHttpUrl("https://api.deepseek.com")
    assert settings.deepseek_model == "deepseek-chat"
    assert settings.deepseek_api_key.get_secret_value() == ""


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
