from functools import lru_cache

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./data/shieldchain.db"
    deepseek_base_url: AnyHttpUrl = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_api_key: SecretStr = SecretStr("")
    simulation_step_delay_ms: int = Field(600, ge=0, le=2000)
    simulation_shutdown_timeout_seconds: float = Field(5.0, ge=1.0, le=30.0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
