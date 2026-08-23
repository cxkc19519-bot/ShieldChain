from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.agents.persistence import AgentRunRow, CaseContextRow
from shieldchain.incidents.persistence import EvidenceRecordRow, InvestigationRunRow
from shieldchain.tools.domain import ToolTargetType, TrustedToolRequest
from shieldchain.tools.registry import (
    ToolNotRegistered,
    ToolParameterRejected,
    ToolRegistration,
    TrustedToolRegistry,
    default_tool_registry,
)

from .candidate import CandidateAction, ResponsePlanCandidate, parse_response_plan_candidate
from .domain import ResponsePlanStatus
from .persistence import (
    ResponsePlanActionRow,
    ResponsePlanEventRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)


class ResponsePlanScopeError(LookupError):
    pass


class _CompilationRejected(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ResponsePlanCompileContext:
    tenant_id: UUID
    run_id: UUID
    case_id: UUID | None
    model_id: str | None
    prompt_policy_version: str
    now: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "run_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if self.case_id is not None and not isinstance(self.case_id, UUID):
            raise TypeError("case_id must be a UUID or None")
        if self.now.tzinfo is None or self.now.utcoffset() != UTC.utcoffset(self.now):
            raise ValueError("now must be an aware UTC datetime")
        _safe_text(self.prompt_policy_version, 64, "prompt_policy_version")
        if self.model_id is not None:
            _safe_text(self.model_id, 128, "model_id")


@dataclass(frozen=True, slots=True)
class CompiledResponsePlan:
    plan_id: UUID
    revision_id: UUID
    revision: int
    status: ResponsePlanStatus
    reason_code: str | None
    action_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class _CompiledAction:
    id: UUID
    client_action_id: str
    tool_name: str
    tool_version: str
    target_reference_id: UUID
    target_type: str
    target_identifier: str
    arguments: dict[str, object]
    expected_state: dict[str, object]
    depends_on: list[str]
    evidence_ids: list[str]
    public_reason: str
    verification_tool: str | None
    verification_version: str | None
    rollback_strategy: str
    assessed_risk: str
    approval_required: bool


class ResponsePlanCompiler:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        registry: TrustedToolRegistry | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._registry = registry or default_tool_registry()

    def compile_json(
        self,
        raw_candidate: str,
        context: ResponsePlanCompileContext,
    ) -> CompiledResponsePlan:
        with self._session_factory.begin() as session:
            self._validate_scope(session, context)
            try:
                candidate = parse_response_plan_candidate(raw_candidate)
            except (TypeError, ValueError):
                return self._save_failure(session, context, "candidate_invalid")
            try:
                compiled_actions = self._compile_actions(session, candidate, context)
            except _CompilationRejected as error:
                return self._save_failure(session, context, error.reason_code)
            return self._save_success(session, candidate, compiled_actions, context)

    @staticmethod
    def _validate_scope(session: Session, context: ResponsePlanCompileContext) -> None:
        run = session.scalar(
            select(AgentRunRow).where(
                AgentRunRow.id == str(context.run_id),
                AgentRunRow.tenant_id == str(context.tenant_id),
            )
        )
        if run is None:
            raise ResponsePlanScopeError("run not found in tenant")
        case = session.scalar(
            select(CaseContextRow).where(
                CaseContextRow.run_id == str(context.run_id),
                CaseContextRow.tenant_id == str(context.tenant_id),
            )
        )
        if context.case_id is None:
            if case is not None:
                raise ResponsePlanScopeError("case_id is required for a case-bound run")
        elif case is None or case.id != str(context.case_id):
            raise ResponsePlanScopeError("case not found in tenant and run")
        else:
            investigation = session.scalar(
                select(InvestigationRunRow).where(
                    InvestigationRunRow.id == str(context.run_id),
                    InvestigationRunRow.tenant_id == str(context.tenant_id),
                    InvestigationRunRow.incident_id == str(context.case_id),
                )
            )
            if investigation is None:
                raise ResponsePlanScopeError("case is not bound to the investigation run")

    def _compile_actions(
        self,
        session: Session,
        candidate: ResponsePlanCandidate,
        context: ResponsePlanCompileContext,
    ) -> tuple[_CompiledAction, ...]:
        registrations = {
            action.client_action_id: self._registration(action.tool) for action in candidate.actions
        }
        evidence_cache: dict[UUID, EvidenceRecordRow] = {}
        for assumption in candidate.assumptions:
            for evidence_id in assumption.evidence_ids:
                self._evidence(session, evidence_id, context, evidence_cache)
        if candidate.actions and context.case_id is None:
            raise _CompilationRejected("case_binding_required")

        action_ids = {item.client_action_id: uuid4() for item in candidate.actions}
        compiled = []
        for action in candidate.actions:
            compiled.append(
                self._compile_action(
                    session,
                    action,
                    registrations[action.client_action_id],
                    action_ids,
                    context,
                    evidence_cache,
                )
            )
        return tuple(compiled)

    def _registration(self, tool_name: str) -> ToolRegistration:
        registrations = tuple(
            item for item in self._registry.registrations if item.definition.name == tool_name
        )
        if len(registrations) != 1:
            raise _CompilationRejected("tool_not_registered")
        registration = registrations[0]
        if AgentRole.RESPONSE_PLANNING not in registration.definition.allowed_roles:
            raise _CompilationRejected("tool_not_allowed_for_role")
        return registration

    def _compile_action(
        self,
        session: Session,
        candidate: CandidateAction,
        registration: ToolRegistration,
        action_ids: dict[str, UUID],
        context: ResponsePlanCompileContext,
        evidence_cache: dict[UUID, EvidenceRecordRow],
    ) -> _CompiledAction:
        definition = registration.definition
        evidence = self._evidence(session, candidate.target_reference_id, context, evidence_cache)
        target_field, target_identifier = _target(definition.target_type, evidence.payload_json)
        if target_field in candidate.arguments:
            raise _CompilationRejected("model_target_forbidden")
        arguments = {**candidate.arguments, target_field: target_identifier}
        verification_tool = None
        verification_version = None
        if definition.verifier_name is None:
            if candidate.verification is not None:
                raise _CompilationRejected("verification_not_allowed")
        else:
            if (
                candidate.verification is None
                or candidate.verification.tool != definition.verifier_name
                or candidate.verification.expected_state != candidate.expected_state
            ):
                raise _CompilationRejected("verification_invalid")
            verifiers = tuple(
                item
                for item in self._registry.registrations
                if item.definition.name == definition.verifier_name
            )
            if len(verifiers) != 1:
                raise _CompilationRejected("verification_invalid")
            verification_tool = verifiers[0].definition.name
            verification_version = verifiers[0].definition.version

        action_id = action_ids[candidate.client_action_id]
        reference = EvidenceReference(
            candidate.target_reference_id,
            context.case_id,  # type: ignore[arg-type]
            evidence.raw_reference,
            _utc(evidence.observed_at),
            evidence.integrity_sha256,
        )
        request = TrustedToolRequest(
            action_id,
            context.case_id,  # type: ignore[arg-type]
            context.run_id,
            UUID(int=0),
            f"plan:{context.run_id}:{action_id}",
            AgentRole.RESPONSE_PLANNING,
            definition.name,
            definition.version,
            arguments,
            candidate.expected_state,
            candidate.rollback_note,
            (reference,),
            context.now,
        )
        try:
            bound = self._registry.bind(request)
        except (ToolNotRegistered, ToolParameterRejected, TypeError, ValueError) as error:
            raise _CompilationRejected("tool_parameters_invalid") from error
        return _CompiledAction(
            id=action_id,
            client_action_id=candidate.client_action_id,
            tool_name=definition.name,
            tool_version=definition.version,
            target_reference_id=candidate.target_reference_id,
            target_type=definition.target_type.value,
            target_identifier=target_identifier,
            arguments=dict(bound.request.arguments),
            expected_state=dict(bound.request.expected_state),
            depends_on=[str(action_ids[item]) for item in candidate.depends_on],
            evidence_ids=[str(candidate.target_reference_id)],
            public_reason=candidate.public_reason,
            verification_tool=verification_tool,
            verification_version=verification_version,
            rollback_strategy=candidate.rollback_note,
            assessed_risk=definition.risk.value,
            approval_required=definition.mutates_state,
        )

    @staticmethod
    def _evidence(
        session: Session,
        evidence_id: UUID,
        context: ResponsePlanCompileContext,
        cache: dict[UUID, EvidenceRecordRow],
    ) -> EvidenceRecordRow:
        if evidence_id in cache:
            return cache[evidence_id]
        row = session.scalar(
            select(EvidenceRecordRow).where(
                EvidenceRecordRow.id == str(evidence_id),
                EvidenceRecordRow.run_id == str(context.run_id),
                EvidenceRecordRow.confirmed.is_(True),
            )
        )
        if row is None:
            raise _CompilationRejected("evidence_invalid")
        observed_at = _utc(row.observed_at)
        if observed_at > context.now + timedelta(minutes=5) or (
            context.now - observed_at > timedelta(days=31)
        ):
            raise _CompilationRejected("evidence_stale")
        cache[evidence_id] = row
        return row

    def _save_success(
        self,
        session: Session,
        candidate: ResponsePlanCandidate,
        actions: tuple[_CompiledAction, ...],
        context: ResponsePlanCompileContext,
    ) -> CompiledResponsePlan:
        status = ResponsePlanStatus.PROPOSED if actions else ResponsePlanStatus.COMPLETED_ADVISORY
        plan, revision, revision_id = self._next_revision(session, context, status)
        session.add(
            ResponsePlanRevisionRow(
                id=str(revision_id),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=revision,
                parent_revision=revision - 1 if revision else None,
                public_summary=candidate.public_summary,
                assumptions_json=[item.model_dump(mode="json") for item in candidate.assumptions],
                stop_conditions_json=list(candidate.stop_conditions),
                operator_notes_json=list(candidate.operator_notes),
                reason_code=None,
                model_id=context.model_id,
                prompt_policy_version=context.prompt_policy_version,
                created_at=context.now,
            )
        )
        session.flush()
        session.add_all(
            ResponsePlanActionRow(
                id=str(action.id),
                plan_revision_id=str(revision_id),
                tenant_id=plan.tenant_id,
                sequence=index,
                client_action_id=action.client_action_id,
                tool_name=action.tool_name,
                tool_version=action.tool_version,
                target_reference_id=str(action.target_reference_id),
                target_type=action.target_type,
                target_identifier=action.target_identifier,
                arguments_json=action.arguments,
                expected_state_json=action.expected_state,
                depends_on_json=action.depends_on,
                evidence_ids_json=action.evidence_ids,
                public_reason=action.public_reason,
                verification_tool=action.verification_tool,
                verification_version=action.verification_version,
                rollback_strategy=action.rollback_strategy,
                assessed_risk=action.assessed_risk,
                approval_required=action.approval_required,
                status="proposed",
                created_at=context.now,
            )
            for index, action in enumerate(actions, start=1)
        )
        session.add(
            ResponsePlanEventRow(
                id=str(uuid4()),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=revision,
                event_type="plan_compiled",
                reason_code=None,
                public_summary="响应计划候选已通过服务端编译。",
                created_at=context.now,
            )
        )
        return CompiledResponsePlan(
            UUID(plan.id), revision_id, revision, status, None, tuple(item.id for item in actions)
        )

    def _save_failure(
        self,
        session: Session,
        context: ResponsePlanCompileContext,
        reason_code: str,
    ) -> CompiledResponsePlan:
        plan, revision, revision_id = self._next_revision(
            session, context, ResponsePlanStatus.NEEDS_REVIEW
        )
        session.add(
            ResponsePlanRevisionRow(
                id=str(revision_id),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=revision,
                parent_revision=revision - 1 if revision else None,
                public_summary="响应计划候选未通过服务端编译，需人工复核。",
                assumptions_json=[],
                stop_conditions_json=["候选格式、证据或工具绑定无效。"],
                operator_notes_json=[],
                reason_code=reason_code,
                model_id=context.model_id,
                prompt_policy_version=context.prompt_policy_version,
                created_at=context.now,
            )
        )
        session.add(
            ResponsePlanEventRow(
                id=str(uuid4()),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=revision,
                event_type="plan_compilation_failed",
                reason_code=reason_code,
                public_summary="响应计划候选未通过服务端编译。",
                created_at=context.now,
            )
        )
        return CompiledResponsePlan(
            UUID(plan.id),
            revision_id,
            revision,
            ResponsePlanStatus.NEEDS_REVIEW,
            reason_code,
            (),
        )

    @staticmethod
    def _next_revision(
        session: Session,
        context: ResponsePlanCompileContext,
        status: ResponsePlanStatus,
    ) -> tuple[ResponsePlanRow, int, UUID]:
        plan = session.scalar(
            select(ResponsePlanRow)
            .where(
                ResponsePlanRow.run_id == str(context.run_id),
                ResponsePlanRow.tenant_id == str(context.tenant_id),
            )
            .with_for_update()
        )
        if plan is None:
            plan = ResponsePlanRow(
                id=str(uuid4()),
                tenant_id=str(context.tenant_id),
                run_id=str(context.run_id),
                case_id=str(context.case_id) if context.case_id else None,
                status=status.value,
                current_revision=0,
                created_by_role=AgentRole.RESPONSE_PLANNING.value,
                created_at=context.now,
                updated_at=context.now,
            )
            session.add(plan)
            session.flush()
            return plan, 0, uuid4()
        if plan.case_id != (str(context.case_id) if context.case_id else None):
            raise ResponsePlanScopeError("existing plan case binding differs")
        revision = plan.current_revision + 1
        plan.current_revision = revision
        plan.status = status.value
        plan.created_by_role = AgentRole.RESPONSE_PLANNING.value
        plan.updated_at = context.now
        return plan, revision, uuid4()


def _target(target_type: ToolTargetType, payload: dict[str, object]) -> tuple[str, str]:
    fields = {
        ToolTargetType.IPV4: ("target_ip", "source_ip", "destination_ip"),
        ToolTargetType.ENDPOINT: ("endpoint_id", "agent_id"),
        ToolTargetType.ACCOUNT: ("account_id", "user_id", "username"),
    }[target_type]
    value = next(
        (payload.get(field) for field in fields if isinstance(payload.get(field), str)),
        None,
    )
    if not isinstance(value, str) or not value.strip():
        raise _CompilationRejected("target_unavailable")
    normalized = value.strip()
    if target_type is ToolTargetType.IPV4:
        try:
            address = IPv4Address(normalized)
        except ValueError as error:
            raise _CompilationRejected("target_invalid") from error
        if address.is_loopback or address.is_multicast or address.is_unspecified:
            raise _CompilationRejected("target_invalid")
        normalized = str(address)
    target_field = {
        ToolTargetType.IPV4: "target_ip",
        ToolTargetType.ENDPOINT: "endpoint_id",
        ToolTargetType.ACCOUNT: "account_id",
    }[target_type]
    return target_field, normalized


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _safe_text(value: str, maximum: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(f"{name} is invalid")
    return value.strip()
