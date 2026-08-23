from __future__ import annotations

import re
from ipaddress import ip_network
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CONFIG_MAX_BYTES = 1024 * 1024
_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_ALIAS = re.compile(r"^external\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")

AgentRole = Literal[
    "superagent",
    "alert_triage",
    "threat_investigation",
    "knowledge_retrieval",
    "response_planning",
    "verification",
    "reporting",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BearerEnvironmentAuth(_StrictModel):
    mode: Literal["bearer_env"]
    token_env: str

    @field_validator("token_env")
    @classmethod
    def validate_token_env(cls, value: str) -> str:
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("token_env must be an uppercase environment variable name")
        return value


class AllowedRemoteTool(_StrictModel):
    remote_name: str
    alias: str
    schema_revision: str
    classification: Literal["read_only"]
    allowed_roles: tuple[AgentRole, ...] = Field(min_length=1, max_length=7)

    @field_validator("remote_name")
    @classmethod
    def validate_remote_name(cls, value: str) -> str:
        if not _REMOTE_NAME.fullmatch(value):
            raise ValueError("remote_name is invalid")
        return value

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if len(value) > 128 or not _ALIAS.fullmatch(value):
            raise ValueError("alias is invalid")
        return value

    @field_validator("schema_revision")
    @classmethod
    def validate_schema_revision(cls, value: str) -> str:
        if not _REVISION.fullmatch(value):
            raise ValueError("schema_revision is invalid")
        return value

    @field_validator("allowed_roles")
    @classmethod
    def unique_roles(cls, value: tuple[AgentRole, ...]) -> tuple[AgentRole, ...]:
        if len(set(value)) != len(value):
            raise ValueError("allowed_roles contains duplicates")
        return value


class McpPeerConfig(_StrictModel):
    id: str
    enabled: bool
    transport: Literal["streamable_http"]
    endpoint: str
    auth: BearerEnvironmentAuth
    network_policy: Literal["public_https", "internal_https"]
    allowed_cidrs: tuple[str, ...] = Field(default=(), max_length=32)
    tls_ca_bundle: Path | None = None
    allowed_tools: tuple[AllowedRemoteTool, ...] = Field(min_length=1, max_length=100)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("server id is invalid")
        return value

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if (
            len(value) > 2048
            or value != value.strip()
            or any(ord(character) < 33 or ord(character) == 127 for character in value)
        ):
            raise ValueError("endpoint is invalid")
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTPS URL")
        try:
            parsed.hostname.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("endpoint host must use an ASCII IDNA name") from error
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("endpoint must not contain user information")
        if parsed.query:
            raise ValueError("endpoint query is not allowed")
        if parsed.fragment:
            raise ValueError("endpoint fragment is not allowed")
        if parsed.port not in {None, 443}:
            raise ValueError("endpoint must use port 443")
        if not parsed.path.endswith("/mcp"):
            raise ValueError("endpoint must identify a fixed /mcp path")
        return value

    @field_validator("allowed_cidrs")
    @classmethod
    def validate_allowed_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        try:
            normalized = tuple(str(ip_network(item, strict=False)) for item in value)
        except ValueError as error:
            raise ValueError("allowed_cidrs contains an invalid network") from error
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_cidrs contains duplicates")
        return normalized

    @field_validator("tls_ca_bundle")
    @classmethod
    def validate_ca_bundle(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("tls_ca_bundle must be an absolute path")
        return value

    @model_validator(mode="after")
    def validate_policy_and_tools(self) -> McpPeerConfig:
        if self.network_policy == "public_https" and self.allowed_cidrs:
            raise ValueError("public_https must not declare allowed_cidrs")
        if self.network_policy == "internal_https" and not self.allowed_cidrs:
            raise ValueError("internal_https requires allowed_cidrs")
        names = [tool.remote_name for tool in self.allowed_tools]
        aliases = [tool.alias for tool in self.allowed_tools]
        if len(set(names)) != len(names):
            raise ValueError("duplicate remote tool name")
        if len(set(aliases)) != len(aliases):
            raise ValueError("duplicate remote tool alias")
        return self


class McpRemoteConfig(_StrictModel):
    version: Literal[1]
    servers: tuple[McpPeerConfig, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def unique_server_ids(self) -> McpRemoteConfig:
        identifiers = [server.id for server in self.servers]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate server id")
        aliases = [tool.alias for server in self.servers for tool in server.allowed_tools]
        if len(set(aliases)) != len(aliases):
            raise ValueError("duplicate remote tool alias across servers")
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: _UniqueKeyLoader, node, deep: bool = False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_mcp_remote_config(path: Path) -> McpRemoteConfig:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("MCP remote configuration cannot be read") from error
    if len(raw) > _CONFIG_MAX_BYTES:
        raise ValueError("MCP remote configuration exceeds 1 MiB")
    try:
        text = raw.decode("utf-8")
        payload = yaml.load(text, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("MCP remote configuration must be strict UTF-8 YAML") from error
    if not isinstance(payload, dict):
        raise ValueError("MCP remote configuration must be an object")
    try:
        return McpRemoteConfig.model_validate(payload)
    except ValueError as error:
        raise ValueError(f"invalid MCP remote configuration: {error}") from error
