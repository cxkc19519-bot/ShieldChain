from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "testing", "production"] = "development"
    http_allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    http_allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )
    http_max_request_bytes: int = Field(26 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    mcp_server_enabled: bool = False
    database_url: str = "sqlite:///./data/shieldchain.db"
    deepseek_base_url: AnyHttpUrl = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_api_key: SecretStr = SecretStr("")
    simulation_step_delay_ms: int = Field(600, ge=0, le=2000)
    simulation_shutdown_timeout_seconds: float = Field(5.0, ge=1.0, le=30.0)
    wazuh_webhook_token: SecretStr = SecretStr("")
    wazuh_review_min_severity: int = Field(12, ge=0, le=15)
    wazuh_review_correlation_window_seconds: int = Field(900, ge=60, le=86_400)
    rag_content_root: Path = Path("data/knowledge")
    assistant_data_root: Path = Path("data/assistant")
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
    # Local demo identity is server-owned. HTTP payloads can never override these values.
    rag_demo_tenant_id: UUID = UUID("00000000-0000-4000-8000-000000000001")
    rag_demo_principal_id: UUID = UUID("00000000-0000-4000-8000-000000000002")

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        normalized = value.strip().casefold()
        if normalized == "test":
            return "testing"
        return normalized

    @field_validator("http_allowed_hosts")
    @classmethod
    def validate_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(item.strip().casefold() for item in value))
        if not normalized or any(
            not item or "://" in item or "/" in item or len(item) > 253 for item in normalized
        ):
            raise ValueError("http_allowed_hosts contains an invalid host")
        return normalized

    @field_validator("http_allowed_origins")
    @classmethod
    def validate_origins(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(item.strip() for item in value))
        if not normalized:
            raise ValueError("http_allowed_origins must not be empty")
        for item in normalized:
            if item == "*":
                continue
            try:
                parsed = AnyHttpUrl(item)
            except ValueError as error:
                raise ValueError("http_allowed_origins contains an invalid origin") from error
            if (
                parsed.path not in {None, "/"}
                or parsed.query is not None
                or parsed.fragment is not None
            ):
                raise ValueError("http_allowed_origins must contain origins without paths")
        return normalized

    @model_validator(mode="after")
    def validate_network_boundaries(self) -> Settings:
        if self.environment == "production" and (
            "*" in self.http_allowed_hosts or "*" in self.http_allowed_origins
        ):
            raise ValueError("production HTTP trust must not contain wildcards")
        if self.mcp_server_enabled and (
            "*" in self.http_allowed_hosts or "*" in self.http_allowed_origins
        ):
            raise ValueError("MCP trust must not contain wildcards")
        if self.environment == "production" and self.mcp_server_enabled:
            raise ValueError("production MCP server requires authorization")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
