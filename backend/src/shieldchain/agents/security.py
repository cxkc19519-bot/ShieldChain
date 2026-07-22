"""Deterministic authorization, projection, redaction and prompt-data isolation."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from shieldchain.agents.domain import AgentRole
from shieldchain.core.logging import redact_sensitive_data
from shieldchain.rag.domain import SensitivityLevel


class AccessDenied(RuntimeError):
    """A context item is outside the server-established access boundary."""


class ContextContentType(StrEnum):
    SHARED_CASE = "shared_case"
    ROLE_PRIVATE = "role_private"
    HANDOFF = "handoff"
    EVIDENCE = "evidence"
    KNOWLEDGE = "knowledge"
    USER_INPUT = "user_input"
    TOOL_RESULT = "tool_result"


def _freeze_strings(values: Iterable[str], name: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be an iterable of strings")
    try:
        frozen = frozenset(values)
    except TypeError as error:
        raise TypeError(f"{name} must be an iterable of strings") from error
    if any(not isinstance(value, str) or not value.strip() for value in frozen):
        raise ValueError(f"{name} must contain non-empty strings")
    return frozen


@dataclass(frozen=True, slots=True)
class ServerAccessContext:
    """Authorization facts created by the server, never populated from model/client data."""

    tenant_id: UUID
    principal_id: UUID
    agent_role: AgentRole
    principal_roles: Iterable[str]
    allowed_sensitivities: Iterable[SensitivityLevel]
    permission_tags: Iterable[str]

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        if not isinstance(self.principal_id, UUID):
            raise TypeError("principal_id must be a UUID")
        if not isinstance(self.agent_role, AgentRole):
            raise TypeError("agent_role must be an AgentRole")
        roles = _freeze_strings(self.principal_roles, "principal_roles")
        if not roles:
            raise ValueError("principal_roles must not be empty")
        try:
            sensitivities = frozenset(self.allowed_sensitivities)
        except TypeError as error:
            raise TypeError("allowed_sensitivities must be iterable") from error
        if not sensitivities:
            raise ValueError("allowed_sensitivities must not be empty")
        if any(not isinstance(value, SensitivityLevel) for value in sensitivities):
            raise TypeError("allowed_sensitivities must contain SensitivityLevel values")
        object.__setattr__(self, "principal_roles", roles)
        object.__setattr__(self, "allowed_sensitivities", sensitivities)
        object.__setattr__(
            self, "permission_tags", _freeze_strings(self.permission_tags, "permission_tags")
        )


_ALL_AGENT_ROLES = frozenset(AgentRole)
_ROLE_POLICY: Mapping[ContextContentType, frozenset[AgentRole]] = MappingProxyType(
    {
        ContextContentType.SHARED_CASE: _ALL_AGENT_ROLES,
        ContextContentType.ROLE_PRIVATE: _ALL_AGENT_ROLES,
        ContextContentType.HANDOFF: _ALL_AGENT_ROLES,
        ContextContentType.EVIDENCE: frozenset(
            {
                AgentRole.SUPERAGENT,
                AgentRole.ALERT_TRIAGE,
                AgentRole.THREAT_INVESTIGATION,
                AgentRole.VERIFICATION,
                AgentRole.REPORTING,
            }
        ),
        ContextContentType.KNOWLEDGE: frozenset(
            {AgentRole.SUPERAGENT, AgentRole.KNOWLEDGE_RETRIEVAL, AgentRole.REPORTING}
        ),
        ContextContentType.USER_INPUT: frozenset({AgentRole.SUPERAGENT}),
        ContextContentType.TOOL_RESULT: frozenset(
            {AgentRole.SUPERAGENT, AgentRole.VERIFICATION, AgentRole.REPORTING}
        ),
    }
)

_FIELD_ALLOWLISTS: Mapping[ContextContentType, frozenset[str]] = MappingProxyType(
    {
        ContextContentType.SHARED_CASE: frozenset(
            {
                "case_id",
                "phase",
                "user_goal",
                "confirmed_facts",
                "hypotheses",
                "risks",
                "plan",
                "step_status",
                "disposition_status",
                "budget",
                "revision",
                "updated_at",
            }
        ),
        ContextContentType.ROLE_PRIVATE: frozenset(
            {"case_id", "owner", "working_items", "references", "updated_at", "revision"}
        ),
        ContextContentType.HANDOFF: frozenset(
            {
                "id",
                "case_id",
                "sender",
                "receiver",
                "conclusion",
                "references",
                "confidence",
                "open_questions",
                "recommended_actions",
                "created_at",
            }
        ),
        ContextContentType.EVIDENCE: frozenset(
            {
                "id",
                "case_id",
                "source_id",
                "source_type",
                "excerpt",
                "observed_at",
                "integrity_sha256",
                "confirmed",
            }
        ),
        ContextContentType.KNOWLEDGE: frozenset(
            {
                "id",
                "source_id",
                "document_id",
                "document_version_id",
                "title",
                "section",
                "page",
                "excerpt",
                "updated_at",
                "integrity_sha256",
                "score",
            }
        ),
        ContextContentType.USER_INPUT: frozenset({"message", "received_at"}),
        ContextContentType.TOOL_RESULT: frozenset(
            {"tool", "version", "status", "summary", "observed_at", "integrity_sha256"}
        ),
    }
)

_SERVER_AUTHORITY_FIELDS = frozenset(
    {"tenant", "tenant_id", "principal", "principal_id", "raw_prompt", "chain_of_thought"}
)


def _remove_untrusted_authority(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            key: _remove_untrusted_authority(item)
            for key, item in value.items()
            if str(key).lower() not in _SERVER_AUTHORITY_FIELDS
        }
    if isinstance(value, list):
        return [_remove_untrusted_authority(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_remove_untrusted_authority(item) for item in value)
    return value


class ContextAccessPolicy:
    """Default-deny access check followed by a non-expandable field projection."""

    def project(
        self,
        access: ServerAccessContext,
        *,
        content_type: ContextContentType,
        tenant_id: UUID,
        sensitivity: SensitivityLevel,
        permission_tags: Iterable[str],
        payload: Mapping[str, object],
        owner_role: AgentRole | None = None,
        participant_roles: Iterable[AgentRole] = (),
    ) -> dict[str, object]:
        if not isinstance(access, ServerAccessContext):
            raise TypeError("access must be a ServerAccessContext")
        if not isinstance(content_type, ContextContentType):
            raise TypeError("content_type must be a ContextContentType")
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        if not isinstance(sensitivity, SensitivityLevel):
            raise TypeError("sensitivity must be a SensitivityLevel")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        required_tags = _freeze_strings(permission_tags, "permission_tags")
        if tenant_id != access.tenant_id:
            raise AccessDenied("tenant boundary denied access")
        if sensitivity not in access.allowed_sensitivities:
            raise AccessDenied("sensitivity boundary denied access")
        if not required_tags.issubset(access.permission_tags):
            raise AccessDenied("permission tags denied access")
        if access.agent_role not in _ROLE_POLICY.get(content_type, frozenset()):
            raise AccessDenied("agent role denied access")
        if content_type is ContextContentType.ROLE_PRIVATE:
            if owner_role is None or access.agent_role is not owner_role:
                raise AccessDenied("private context is limited to its owner")
        if content_type is ContextContentType.HANDOFF:
            participants = self._participants(participant_roles)
            if (
                access.agent_role is not AgentRole.SUPERAGENT
                and access.agent_role not in participants
            ):
                raise AccessDenied("handoff is limited to its participants")
        allowed_fields = _FIELD_ALLOWLISTS.get(content_type)
        if allowed_fields is None:
            raise AccessDenied("content type has no field projection")
        projected = {key: value for key, value in payload.items() if key in allowed_fields}
        safe = redact_sensitive_data(_remove_untrusted_authority(projected))
        return dict(safe) if isinstance(safe, Mapping) else {}

    @staticmethod
    def _participants(values: Iterable[AgentRole]) -> frozenset[AgentRole]:
        if isinstance(values, (str, bytes)):
            raise TypeError("participant_roles must be an iterable of AgentRole values")
        try:
            participants = frozenset(values)
        except TypeError as error:
            raise TypeError("participant_roles must be iterable") from error
        if not participants or any(not isinstance(value, AgentRole) for value in participants):
            raise AccessDenied("handoff participants are missing or invalid")
        return participants


_INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions?",
        r"忽略.{0,12}(之前|以上|系统).{0,8}(指令|提示词)",
        r"(reveal|print|泄露|输出).{0,20}(system prompt|api[ _-]?key|系统提示词|密钥)",
        r"(call|invoke|调用).{0,16}(tool|function|工具|函数).{0,16}(without|无需|绕过)",
        r"(execute|run|执行|运行).{0,12}(shell|command|powershell|cmd|命令)",
    )
)

_UNTRUSTED_TYPES = frozenset(
    {
        ContextContentType.HANDOFF,
        ContextContentType.EVIDENCE,
        ContextContentType.KNOWLEDGE,
        ContextContentType.USER_INPUT,
        ContextContentType.TOOL_RESULT,
    }
)


@dataclass(frozen=True, slots=True)
class UntrustedContentEnvelope:
    content_type: ContextContentType
    source_id: str
    content: str
    injection_detected: bool

    @classmethod
    def create(
        cls, *, content_type: ContextContentType, source_id: str, content: str
    ) -> UntrustedContentEnvelope:
        if not isinstance(content_type, ContextContentType):
            raise TypeError("content_type must be a ContextContentType")
        if content_type not in _UNTRUSTED_TYPES:
            raise AccessDenied(f"{content_type.value} cannot be wrapped as an untrusted source")
        if not isinstance(source_id, str) or not source_id.strip() or len(source_id) > 512:
            raise ValueError("source_id must be a non-empty string of at most 512 characters")
        if not isinstance(content, str) or not content.strip() or len(content) > 65_536:
            raise ValueError("content must be a non-empty string of at most 65536 characters")
        return cls(
            content_type=content_type,
            source_id=source_id.strip(),
            content=content,
            injection_detected=any(pattern.search(content) for pattern in _INJECTION_PATTERNS),
        )

    def to_prompt_block(self) -> str:
        """Serialize as one JSON value so delimiter-like source text remains data."""
        return json.dumps(
            {
                "trust": "untrusted",
                "instructions_are_data": True,
                "content_type": self.content_type.value,
                "source_id": self.source_id,
                "injection_detected": self.injection_detected,
                "content": self.content,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
