from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
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
    mcp_auth_mode: Literal["disabled", "oauth"] = "disabled"
    mcp_auth_issuer: str = ""
    mcp_auth_resource: str = ""
    mcp_auth_jwks_url: str = ""
    mcp_auth_audience: str = ""
    mcp_auth_algorithm: Literal["RS256", "ES256"] = "RS256"
    mcp_auth_max_token_lifetime_seconds: int = Field(900, ge=60, le=3600)
    mcp_auth_subject_principals: dict[str, UUID] = Field(default_factory=dict)
    mcp_remote_config_path: Path | None = None
    mcp_remote_snapshot_ttl_seconds: int = Field(3600, ge=60, le=86_400)
    mcp_remote_discovery_timeout_seconds: float = Field(30.0, ge=1.0, le=30.0)
    mcp_remote_max_discovery_pages: int = Field(5, ge=1, le=10)
    mcp_remote_max_tools: int = Field(100, ge=1, le=100)
    mcp_remote_max_schema_bytes: int = Field(64 * 1024, ge=1024, le=64 * 1024)
    mcp_remote_max_catalog_schema_bytes: int = Field(1024 * 1024, ge=64 * 1024, le=1024 * 1024)
    mcp_remote_max_request_bytes: int = Field(256 * 1024, ge=1024, le=256 * 1024)
    mcp_remote_max_response_bytes: int = Field(2 * 1024 * 1024, ge=64 * 1024, le=2 * 1024 * 1024)
    mcp_remote_max_public_result_bytes: int = Field(64 * 1024, ge=1024, le=64 * 1024)
    mcp_remote_call_timeout_seconds: float = Field(30.0, ge=1.0, le=30.0)
    mcp_remote_max_calls_per_run: int = Field(10, ge=1, le=10)
    mcp_remote_peer_concurrency: int = Field(4, ge=1, le=4)
    mcp_remote_peer_calls_per_minute: int = Field(30, ge=1, le=120)
    mcp_remote_circuit_failure_threshold: int = Field(5, ge=1, le=10)
    mcp_remote_circuit_open_seconds: int = Field(60, ge=10, le=300)
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
    security_vertical_pack_root: Path = Path("sample_docs/security_vertical")
    rag_evaluation_root: Path = Path("sample_docs/security_vertical/evaluation")
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

    @field_validator("mcp_remote_config_path", mode="before")
    @classmethod
    def normalize_optional_path(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

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
        if self.mcp_server_enabled and self.mcp_auth_mode == "disabled":
            if self.environment != "testing":
                raise ValueError("MCP authorization can be disabled only in testing")
            return self
        if self.mcp_server_enabled:
            required = {
                "issuer": self.mcp_auth_issuer,
                "resource": self.mcp_auth_resource,
                "JWKS URL": self.mcp_auth_jwks_url,
                "audience": self.mcp_auth_audience,
            }
            missing = [name for name, value in required.items() if not value.strip()]
            if missing:
                raise ValueError("MCP OAuth configuration is incomplete: " + ", ".join(missing))
            for name, value in (
                ("issuer", self.mcp_auth_issuer),
                ("resource", self.mcp_auth_resource),
                ("JWKS URL", self.mcp_auth_jwks_url),
            ):
                parsed = urlsplit(value)
                if (
                    parsed.scheme != "https"
                    or not parsed.netloc
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.fragment
                ):
                    raise ValueError(f"MCP OAuth {name} must be an absolute HTTPS URL")
            if not self.mcp_auth_resource.endswith("/mcp"):
                raise ValueError("MCP OAuth resource must identify the /mcp endpoint")
            if (
                self.mcp_auth_audience != self.mcp_auth_audience.strip()
                or len(self.mcp_auth_audience) > 256
            ):
                raise ValueError("MCP OAuth audience is invalid")
            if not self.mcp_auth_subject_principals:
                raise ValueError("MCP OAuth subject mapping must not be empty")
            if any(
                not subject.strip() or len(subject) > 256
                for subject in self.mcp_auth_subject_principals
            ):
                raise ValueError("MCP OAuth subject mapping contains an invalid subject")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
