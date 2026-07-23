"""Fixed-version trusted tool registry and built-in parameter schemas."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from ipaddress import IPv4Address
from types import MappingProxyType

from shieldchain.agents.domain import AgentRole
from shieldchain.tools.domain import (
    ToolDefinition,
    ToolRisk,
    ToolScalar,
    ToolTargetType,
    TrustedToolRequest,
)

_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ToolRegistryError(ValueError):
    """Base class for public-safe registry failures."""


class DuplicateToolRegistration(ToolRegistryError):
    pass


class ToolNotRegistered(ToolRegistryError):
    pass


class ToolParameterRejected(ToolRegistryError):
    pass


class UnsafeToolRegistration(ToolRegistryError):
    pass


class ToolParameterSchema(StrEnum):
    FIREWALL_QUERY_V1 = "firewall_query_v1"
    BLOCK_IP_V1 = "block_ip_v1"
    ENDPOINT_QUERY_V1 = "endpoint_query_v1"
    ISOLATE_ENDPOINT_V1 = "isolate_endpoint_v1"
    ACCOUNT_QUERY_V1 = "account_query_v1"
    DISABLE_ACCOUNT_V1 = "disable_account_v1"


@dataclass(frozen=True, slots=True)
class ToolRegistration:
    definition: ToolDefinition
    parameter_schema: ToolParameterSchema

    def __post_init__(self) -> None:
        if not isinstance(self.definition, ToolDefinition):
            raise TypeError("definition must be a ToolDefinition")
        if not isinstance(self.parameter_schema, ToolParameterSchema):
            raise TypeError("parameter_schema must be a ToolParameterSchema")
        expected_target = {
            ToolParameterSchema.FIREWALL_QUERY_V1: ToolTargetType.IPV4,
            ToolParameterSchema.BLOCK_IP_V1: ToolTargetType.IPV4,
            ToolParameterSchema.ENDPOINT_QUERY_V1: ToolTargetType.ENDPOINT,
            ToolParameterSchema.ISOLATE_ENDPOINT_V1: ToolTargetType.ENDPOINT,
            ToolParameterSchema.ACCOUNT_QUERY_V1: ToolTargetType.ACCOUNT,
            ToolParameterSchema.DISABLE_ACCOUNT_V1: ToolTargetType.ACCOUNT,
        }[self.parameter_schema]
        if self.definition.target_type is not expected_target:
            raise UnsafeToolRegistration("parameter schema and target type do not match")


@dataclass(frozen=True, slots=True)
class BoundToolRequest:
    registration: ToolRegistration
    request: TrustedToolRequest

    @property
    def request_digest(self) -> str:
        return self.request.request_digest

    @property
    def arguments_digest(self) -> str:
        encoded = json.dumps(
            dict(self.request.arguments),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _exact(values: Mapping[str, ToolScalar], expected: frozenset[str], *, label: str) -> None:
    if set(values) != expected:
        raise ToolParameterRejected(f"{label} fields do not match the registered schema")


def _ipv4(value: ToolScalar) -> str:
    if not isinstance(value, str):
        raise ToolParameterRejected("target_ip must be a string")
    try:
        address = IPv4Address(value.strip())
    except ValueError:
        raise ToolParameterRejected("target_ip must be a valid IPv4 address") from None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ToolParameterRejected("target_ip is not an allowed unicast target")
    return str(address)


def _resource(value: ToolScalar, name: str) -> str:
    if not isinstance(value, str) or not _RESOURCE_ID.fullmatch(value.strip()):
        raise ToolParameterRejected(f"{name} is invalid")
    return value.strip()


def _positive_int(value: ToolScalar, name: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ToolParameterRejected(f"{name} must be between {minimum} and {maximum}")
    return value


def _reason(value: ToolScalar, allowed: frozenset[str]) -> str:
    reason = _resource(value, "reason_code")
    if reason not in allowed:
        raise ToolParameterRejected("reason_code is not allowed")
    return reason


def _parse_arguments(
    schema: ToolParameterSchema, values: Mapping[str, ToolScalar]
) -> Mapping[str, ToolScalar]:
    if schema is ToolParameterSchema.FIREWALL_QUERY_V1:
        _exact(values, frozenset({"target_ip"}), label="arguments")
        result = {"target_ip": _ipv4(values["target_ip"])}
    elif schema is ToolParameterSchema.BLOCK_IP_V1:
        _exact(values, frozenset({"target_ip", "rule_ttl_seconds"}), label="arguments")
        result = {
            "rule_ttl_seconds": _positive_int(
                values["rule_ttl_seconds"], "rule_ttl_seconds", minimum=60, maximum=86_400
            ),
            "target_ip": _ipv4(values["target_ip"]),
        }
    elif schema is ToolParameterSchema.ENDPOINT_QUERY_V1:
        _exact(values, frozenset({"endpoint_id"}), label="arguments")
        result = {"endpoint_id": _resource(values["endpoint_id"], "endpoint_id")}
    elif schema is ToolParameterSchema.ISOLATE_ENDPOINT_V1:
        _exact(values, frozenset({"endpoint_id", "reason_code"}), label="arguments")
        result = {
            "endpoint_id": _resource(values["endpoint_id"], "endpoint_id"),
            "reason_code": _reason(
                values["reason_code"],
                frozenset({"confirmed_compromise", "containment_required"}),
            ),
        }
    elif schema is ToolParameterSchema.ACCOUNT_QUERY_V1:
        _exact(values, frozenset({"account_id"}), label="arguments")
        result = {"account_id": _resource(values["account_id"], "account_id")}
    else:
        _exact(values, frozenset({"account_id", "reason_code"}), label="arguments")
        result = {
            "account_id": _resource(values["account_id"], "account_id"),
            "reason_code": _reason(
                values["reason_code"],
                frozenset({"confirmed_compromise", "credential_abuse"}),
            ),
        }
    return MappingProxyType(dict(sorted(result.items())))


def _parse_expected_state(
    schema: ToolParameterSchema, values: Mapping[str, ToolScalar]
) -> Mapping[str, ToolScalar]:
    if schema in {ToolParameterSchema.FIREWALL_QUERY_V1, ToolParameterSchema.BLOCK_IP_V1}:
        field, allowed = "firewall_status", {"blocked", "not_blocked"}
    elif schema in {
        ToolParameterSchema.ENDPOINT_QUERY_V1,
        ToolParameterSchema.ISOLATE_ENDPOINT_V1,
    }:
        field, allowed = "isolation_status", {"isolated", "connected"}
    else:
        field, allowed = "account_status", {"disabled", "enabled"}
    _exact(values, frozenset({field}), label="expected_state")
    value = values[field]
    if not isinstance(value, str) or value not in allowed:
        raise ToolParameterRejected(f"{field} is invalid")
    return MappingProxyType({field: value})


class TrustedToolRegistry:
    def __init__(self, registrations: tuple[ToolRegistration, ...]) -> None:
        items: dict[tuple[str, str], ToolRegistration] = {}
        for registration in registrations:
            if not isinstance(registration, ToolRegistration):
                raise TypeError("registrations must contain ToolRegistration values")
            identity = registration.definition.identity
            if identity in items:
                raise DuplicateToolRegistration(f"duplicate tool registration: {identity}")
            items[identity] = registration
        if not items:
            raise ValueError("at least one tool must be registered")
        for registration in items.values():
            verifier = registration.definition.verifier_name
            if verifier is None:
                continue
            candidates = [item for item in items.values() if item.definition.name == verifier]
            if len(candidates) != 1:
                raise UnsafeToolRegistration("verifier must resolve to exactly one registered tool")
            verifier_definition = candidates[0].definition
            if (
                verifier_definition.mutates_state
                or verifier_definition.risk is not ToolRisk.READ_ONLY
                or verifier_definition.target_type is not registration.definition.target_type
            ):
                raise UnsafeToolRegistration("verifier must be read-only and target-compatible")
        self._items = MappingProxyType(items)

    @property
    def registrations(self) -> tuple[ToolRegistration, ...]:
        return tuple(self._items.values())

    def resolve(self, name: str, version: str) -> ToolRegistration:
        try:
            return self._items[(name, version)]
        except KeyError:
            raise ToolNotRegistered("tool name or version is not registered") from None

    def bind(self, request: TrustedToolRequest) -> BoundToolRequest:
        registration = self.resolve(request.tool_name, request.tool_version)
        normalized = replace(
            request,
            arguments=_parse_arguments(registration.parameter_schema, request.arguments),
            expected_state=_parse_expected_state(
                registration.parameter_schema, request.expected_state
            ),
        )
        return BoundToolRequest(registration, normalized)


def _definition(
    name: str,
    target: ToolTargetType,
    risk: ToolRisk,
    roles: frozenset[AgentRole],
    *,
    mutates: bool,
    verifier: str | None,
) -> ToolDefinition:
    return ToolDefinition(
        name,
        "1",
        target,
        risk,
        roles,
        5.0 if mutates else 2.0,
        0 if mutates else 2,
        mutates,
        verifier,
    )


def default_tool_registry() -> TrustedToolRegistry:
    read_roles = frozenset(
        {AgentRole.SUPERAGENT, AgentRole.RESPONSE_PLANNING, AgentRole.VERIFICATION}
    )
    write_roles = frozenset({AgentRole.RESPONSE_PLANNING})
    registrations = (
        ToolRegistration(
            _definition(
                "query_firewall_state",
                ToolTargetType.IPV4,
                ToolRisk.READ_ONLY,
                read_roles,
                mutates=False,
                verifier=None,
            ),
            ToolParameterSchema.FIREWALL_QUERY_V1,
        ),
        ToolRegistration(
            _definition(
                "block_ip",
                ToolTargetType.IPV4,
                ToolRisk.HIGH,
                write_roles,
                mutates=True,
                verifier="query_firewall_state",
            ),
            ToolParameterSchema.BLOCK_IP_V1,
        ),
        ToolRegistration(
            _definition(
                "query_endpoint_state",
                ToolTargetType.ENDPOINT,
                ToolRisk.READ_ONLY,
                read_roles,
                mutates=False,
                verifier=None,
            ),
            ToolParameterSchema.ENDPOINT_QUERY_V1,
        ),
        ToolRegistration(
            _definition(
                "isolate_endpoint",
                ToolTargetType.ENDPOINT,
                ToolRisk.HIGH,
                write_roles,
                mutates=True,
                verifier="query_endpoint_state",
            ),
            ToolParameterSchema.ISOLATE_ENDPOINT_V1,
        ),
        ToolRegistration(
            _definition(
                "query_account_state",
                ToolTargetType.ACCOUNT,
                ToolRisk.READ_ONLY,
                read_roles,
                mutates=False,
                verifier=None,
            ),
            ToolParameterSchema.ACCOUNT_QUERY_V1,
        ),
        ToolRegistration(
            _definition(
                "disable_account",
                ToolTargetType.ACCOUNT,
                ToolRisk.CRITICAL,
                write_roles,
                mutates=True,
                verifier="query_account_state",
            ),
            ToolParameterSchema.DISABLE_ACCOUNT_V1,
        ),
    )
    return TrustedToolRegistry(registrations)
