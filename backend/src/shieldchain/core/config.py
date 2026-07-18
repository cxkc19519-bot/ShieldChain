from functools import lru_cache
from pathlib import Path

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
    rag_content_root: Path = Path("data/knowledge")
    rag_max_upload_bytes: int = Field(25 * 1024 * 1024, ge=1, le=25 * 1024 * 1024)
    rag_max_expanded_bytes: int = Field(100 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)
    rag_max_compression_ratio: int = Field(100, ge=1, le=100)
    rag_max_extracted_characters: int = Field(2_000_000, ge=1, le=2_000_000)
    rag_max_zip_members: int = Field(10_000, ge=1, le=10_000)
    rag_max_upload_chunks: int = Field(100_000, ge=1, le=262_144)
    rag_max_parse_pages: int = Field(10_000, ge=1, le=10_000)
    rag_max_parse_rows: int = Field(200_000, ge=1, le=200_000)
    rag_max_parse_cells: int = Field(1_000_000, ge=1, le=1_000_000)
    rag_max_parse_elements: int = Field(100_000, ge=1, le=100_000)
    rag_parse_timeout_seconds: float = Field(15.0, ge=0.001, le=30.0)


@lru_cache
def get_settings() -> Settings:
    return Settings()
