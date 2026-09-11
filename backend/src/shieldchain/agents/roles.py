"""Strict professional-role ports and deterministic offline implementations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from shieldchain.agents.context import AssembledContext, ContextSectionName
from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    EvidenceReference,
    KnowledgeReference,
    Risk,
    TerminationReason,
)
from shieldchain.incidents.domain import Conclusion, Evidence
from shieldchain.incidents.rules import assess
from shieldchain.rag.answering import GroundedAnswer
from shieldchain.rag.domain import StructuredRefusal


class RoleExecutionStatus(StrEnum):
    COMPLETED = "completed"
    REFUSED = "refused"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INVALID_OUTPUT = "invalid_output"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class RoleExecutionRequest:
    role: AgentRole
    case_id: UUID
    context: AssembledContext
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.role, AgentRole):
            raise TypeError("role must be an AgentRole")
        if not isinstance(self.case_id, UUID):
            raise TypeError("case_id must be a UUID")
        if not isinstance(self.context, AssembledContext):
            raise TypeError("context must be an AssembledContext")
        if (
            not isinstance(self.created_at, datetime)
            or self.created_at.tzinfo is None
            or self.created_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("created_at must be an aware UTC datetime")


@dataclass(frozen=True, slots=True)
class RoleExecutionResult:
    status: RoleExecutionStatus
    output: AgentOutput | None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, RoleExecutionStatus):
            raise TypeError("status must be a RoleExecutionStatus")
        if self.status is RoleExecutionStatus.COMPLETED:
            if not isinstance(self.output, AgentOutput) or self.error_code is not None:
                raise ValueError("completed result requires output and no error")
        elif self.output is not None or not isinstance(self.error_code, str) or not self.error_code:
            raise ValueError("failed result requires error_code and no output")


class ProfessionalRole(Protocol):
    role: AgentRole

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult: ...


class IncidentEvidencePort(Protocol):
    def fetch(self, *, case_id: UUID, source_ids: tuple[str, ...]) -> tuple[Evidence, ...]: ...


KnowledgeDecision = GroundedAnswer | StructuredRefusal


class AgentKnowledgePort(Protocol):
    def retrieve(self, *, case_id: UUID, query: str) -> KnowledgeDecision: ...


class RoleModelPort(Protocol):
    def complete(
        self,
        *,
        role: AgentRole,
        prompt: str,
        output_schema: Mapping[str, object],
    ) -> Mapping[str, object]: ...


def _source_ids(context: AssembledContext, section: ContextSectionName) -> tuple[str, ...]:
    return tuple(
        source_id for item in context.section(section).items for source_id in item.source_ids
    )


def _evidence_references(case_id: UUID, evidence: tuple[Evidence, ...]):
    return tuple(
        EvidenceReference(
            item.id,
            case_id,
            item.raw_reference,
            item.observed_at,
            item.integrity_sha256,
        )
        for item in evidence
    )


def _completed(output: AgentOutput) -> RoleExecutionResult:
    return RoleExecutionResult(RoleExecutionStatus.COMPLETED, output)


def _failed(status: RoleExecutionStatus, code: str) -> RoleExecutionResult:
    return RoleExecutionResult(status, None, code)


class _BaseOfflineRole:
    role: AgentRole

    def _output(
        self,
        request: RoleExecutionRequest,
        summary: str,
        *,
        references=(),
        risks=(),
        actions=(),
        termination_reason: TerminationReason = TerminationReason.COMPLETED,
    ) -> RoleExecutionResult:
        if request.role is not self.role:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "role_mismatch")
        return _completed(
            AgentOutput(
                self.role,
                request.case_id,
                summary,
                references,
                (),
                risks,
                actions,
                request.created_at,
                termination_reason,
            )
        )


class OfflineSuperagentRole(_BaseOfflineRole):
    role = AgentRole.SUPERAGENT

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        return self._output(
            request, "Prepared deterministic role coordination from bounded context."
        )


class OfflineEvidenceRole(_BaseOfflineRole):
    def __init__(self, role: AgentRole, evidence_port: IncidentEvidencePort) -> None:
        if role not in {AgentRole.ALERT_TRIAGE, AgentRole.THREAT_INVESTIGATION}:
            raise ValueError("offline evidence role is only valid for triage or investigation")
        self.role = role
        self._evidence_port = evidence_port

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        if request.role is not self.role:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "role_mismatch")
        try:
            evidence = self._evidence_port.fetch(
                case_id=request.case_id,
                source_ids=_source_ids(request.context, ContextSectionName.EVIDENCE),
            )
        except TimeoutError:
            return _failed(RoleExecutionStatus.TIMED_OUT, "evidence_timeout")
        except Exception:
            return _failed(RoleExecutionStatus.DEPENDENCY_UNAVAILABLE, "evidence_unavailable")
        decision = assess(evidence)
        references = _evidence_references(request.case_id, evidence)
        if decision.conclusion is Conclusion.INSUFFICIENT_EVIDENCE:
            return self._output(
                request,
                decision.explanation,
                references=references,
                termination_reason=TerminationReason.NEEDS_REVIEW,
            )
        risk = Risk(
            uuid5(NAMESPACE_URL, f"shieldchain:{request.case_id}:{self.role.value}:risk"),
            "Confirmed phishing chain requires containment planning.",
            "high",
            references,
        )
        actions = (decision.recommended_action,) if decision.recommended_action else ()
        return self._output(
            request,
            decision.explanation,
            references=references,
            risks=(risk,),
            actions=actions,
        )


class OfflineKnowledgeRole(_BaseOfflineRole):
    role = AgentRole.KNOWLEDGE_RETRIEVAL

    def __init__(self, knowledge_port: AgentKnowledgePort) -> None:
        self._knowledge_port = knowledge_port

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        if request.role is not self.role:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "role_mismatch")
        query = "\n".join(
            item.content for item in request.context.section(ContextSectionName.CURRENT_TASK).items
        )
        try:
            decision = self._knowledge_port.retrieve(case_id=request.case_id, query=query)
        except TimeoutError:
            return _failed(RoleExecutionStatus.TIMED_OUT, "rag_timeout")
        except Exception:
            return _failed(RoleExecutionStatus.DEPENDENCY_UNAVAILABLE, "rag_unavailable")
        if isinstance(decision, StructuredRefusal):
            return _failed(RoleExecutionStatus.REFUSED, f"rag_{decision.reason.value}")
        if not isinstance(decision, GroundedAnswer):
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "rag_invalid_output")
        references = tuple(
            KnowledgeReference(
                citation.chunk_id,
                request.case_id,
                f"knowledge:{citation.document_id}:{citation.document_version_id}",
                citation.updated_at,
                citation.integrity_sha256,
            )
            for citation in decision.citations
        )
        return self._output(request, decision.answer, references=references)


class OfflineResponsePlanningRole(_BaseOfflineRole):
    role = AgentRole.RESPONSE_PLANNING

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        actions = tuple(
            f"proposed:{item.content}"
            for item in request.context.section(ContextSectionName.ALLOWED_ACTIONS).items
        )
        if not actions:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "allowed_actions_missing")
        return self._output(
            request,
            "Prepared proposed actions only; no tool was invoked.",
            actions=actions,
        )


class OfflineVerificationRole(_BaseOfflineRole):
    role = AgentRole.VERIFICATION

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        case_text = "\n".join(
            item.content for item in request.context.section(ContextSectionName.CASE_SUMMARY).items
        )
        if "confirmed_facts" not in case_text:
            return _failed(RoleExecutionStatus.REFUSED, "trusted_facts_missing")
        return self._output(request, "Compared expected state with trusted case observations.")


class OfflineReportingRole(_BaseOfflineRole):
    role = AgentRole.REPORTING

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        case_text = "\n".join(
            item.content for item in request.context.section(ContextSectionName.CASE_SUMMARY).items
        )
        if "confirmed_facts" not in case_text:
            return _failed(RoleExecutionStatus.REFUSED, "trusted_facts_missing")
        return self._output(
            request, "Generated report structure from trusted facts and audit summary."
        )


class StrictModelRole(_BaseOfflineRole):
    """Optional LLM adapter that cannot create trusted references or tool authority."""

    _SCHEMA = {"summary": "string", "recommended_actions": ["string"]}

    def __init__(self, role: AgentRole, model: RoleModelPort) -> None:
        self.role = role
        if role is AgentRole.KNOWLEDGE_RETRIEVAL:
            raise ValueError("knowledge role must use the grounded RAG port")
        self._model = model

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        if request.role is not self.role:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "role_mismatch")
        try:
            value = self._model.complete(
                role=self.role,
                prompt=request.context.to_prompt(),
                output_schema=self._SCHEMA,
            )
        except TimeoutError:
            return _failed(RoleExecutionStatus.TIMED_OUT, "model_timeout")
        except Exception:
            return _failed(RoleExecutionStatus.DEPENDENCY_UNAVAILABLE, "model_unavailable")
        if not isinstance(value, Mapping) or set(value) != {"summary", "recommended_actions"}:
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "model_schema_invalid")
        summary = value.get("summary")
        actions = value.get("recommended_actions")
        if (
            not isinstance(summary, str)
            or not summary.strip()
            or not isinstance(actions, list)
            or any(not isinstance(item, str) or not item.strip() for item in actions)
        ):
            return _failed(RoleExecutionStatus.INVALID_OUTPUT, "model_schema_invalid")
        bounded_actions = tuple(actions)
        if self.role is AgentRole.RESPONSE_PLANNING:
            bounded_actions = tuple(
                item if item.startswith("proposed:") else f"proposed:{item}" for item in actions
            )

        return self._output(request, summary.strip(), actions=bounded_actions)


class DeterministicFakeRoleModel:
    def complete(self, **_kwargs) -> Mapping[str, object]:
        return {"summary": "Deterministic offline model result.", "recommended_actions": []}


class ProfessionalRoleRegistry:
    def __init__(self, roles: Mapping[AgentRole, ProfessionalRole]) -> None:
        if set(roles) != set(AgentRole):
            raise ValueError("registry must contain every agent role exactly once")
        if any(role is not adapter.role for role, adapter in roles.items()):
            raise ValueError("registry role key does not match adapter")
        self._roles = dict(roles)

    def execute(self, request: RoleExecutionRequest) -> RoleExecutionResult:
        return self._roles[request.role].execute(request)


def build_offline_role_registry(
    *, evidence_port: IncidentEvidencePort, knowledge_port: AgentKnowledgePort
) -> ProfessionalRoleRegistry:
    return ProfessionalRoleRegistry(
        {
            AgentRole.SUPERAGENT: OfflineSuperagentRole(),
            AgentRole.ALERT_TRIAGE: OfflineEvidenceRole(AgentRole.ALERT_TRIAGE, evidence_port),
            AgentRole.THREAT_INVESTIGATION: OfflineEvidenceRole(
                AgentRole.THREAT_INVESTIGATION, evidence_port
            ),
            AgentRole.KNOWLEDGE_RETRIEVAL: OfflineKnowledgeRole(knowledge_port),
            AgentRole.RESPONSE_PLANNING: OfflineResponsePlanningRole(),
            AgentRole.VERIFICATION: OfflineVerificationRole(),
            AgentRole.REPORTING: OfflineReportingRole(),
        }
    )
