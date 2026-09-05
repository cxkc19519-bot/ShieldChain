"""Compile accepted response-plan actions into tenant-bound trusted tool calls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import AgentRole, EvidenceReference
from shieldchain.response_planning.persistence import (
    ResponsePlanActionRow,
    ResponsePlanEventRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)
from shieldchain.tools.domain import (
    PolicyOutcome,
    ToolTargetType,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
)
from shieldchain.tools.persistence import ToolAutomationControlRow, TrustedToolCallRow
from shieldchain.tools.policy import (
    DeterministicToolPolicy,
    ToolExecutionMode,
    ToolPolicyContext,
)
from shieldchain.tools.registry import (
    ToolRegistryError,
    TrustedToolRegistry,
    default_tool_registry,
)
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository, _call
from shieldchain.tools.schemas import ResponsePlanMutationView, ResponsePlanToolCallView
from shieldchain.wazuh.evidence import confirmed_evidence


class ResponsePlanDecisionNotFound(RuntimeError):
    pass


class ResponsePlanDecisionConflict(RuntimeError):
    pass


class ResponsePlanToolService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        registry: TrustedToolRegistry | None = None,
    ) -> None:
        self._sessions = sessions
        self._registry = registry or default_tool_registry()
        self._policy = DeterministicToolPolicy()

    def decide(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        plan_id: UUID,
        outcome: str,
        reason: str,
        now: datetime,
        expected_revision: int | None = None,
    ) -> ResponsePlanMutationView:
        if outcome not in {"accepted", "rejected"}:
            raise ValueError("response plan outcome is invalid")
        reason = _reason(reason)
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("response plan decision time must be aware UTC")
        with self._sessions.begin() as session:
            plan = session.execute(
                select(ResponsePlanRow)
                .where(
                    ResponsePlanRow.id == str(plan_id),
                    ResponsePlanRow.tenant_id == str(tenant_id),
                )
                .with_for_update()
            ).scalar_one_or_none()
            if plan is None:
                raise ResponsePlanDecisionNotFound("response plan not found in tenant")
            if expected_revision is not None and plan.current_revision != expected_revision:
                raise ResponsePlanDecisionConflict("response plan decision is stale")
            if outcome == "rejected":
                return self._reject(session, plan, actor_id, reason, now)
            return self._accept(session, plan, actor_id, reason, now)

    def _accept(
        self,
        session: Session,
        plan: ResponsePlanRow,
        actor_id: UUID,
        reason: str,
        now: datetime,
    ) -> ResponsePlanMutationView:
        revision = self._current_revision(session, plan)
        actions = list(
            session.scalars(
                select(ResponsePlanActionRow)
                .where(
                    ResponsePlanActionRow.plan_revision_id == revision.id,
                    ResponsePlanActionRow.tenant_id == plan.tenant_id,
                )
                .order_by(ResponsePlanActionRow.sequence)
            )
        )
        existing = self._linked_calls(session, plan, revision)
        if (
            plan.status in {"awaiting_execution", "needs_review"}
            and actions
            and (len(existing) == len(actions))
        ):
            return self._view(session, plan, existing)
        if plan.status != "proposed" or not actions or plan.case_id is None:
            raise ResponsePlanDecisionConflict("response plan is not an actionable proposal")
        seen: set[str] = set()
        for action in actions:
            if any(str(dependency) not in seen for dependency in action.depends_on_json):
                raise ResponsePlanDecisionConflict("response plan action dependencies are invalid")
            seen.add(action.id)
        changed = session.execute(
            update(ResponsePlanRow)
            .where(
                ResponsePlanRow.id == plan.id,
                ResponsePlanRow.tenant_id == plan.tenant_id,
                ResponsePlanRow.status == "proposed",
                ResponsePlanRow.current_revision == revision.revision,
            )
            .values(status="awaiting_execution", updated_at=now)
        )
        if changed.rowcount != 1:
            raise ResponsePlanDecisionConflict("response plan decision is stale")

        calls = [
            self._create_call(session, plan, revision, action, actor_id, now) for action in actions
        ]
        final_status = (
            "needs_review"
            if any(call.status is TrustedToolCallStatus.REJECTED for call in calls)
            else "awaiting_execution"
        )
        plan.status = final_status
        plan.updated_at = now
        self._event(
            session,
            plan,
            actor_id,
            "plan_accepted",
            "operator_accepted",
            f"响应计划已由操作员接受：{reason}",
            now,
        )
        session.flush()
        return self._view(session, plan, calls)

    def _reject(
        self,
        session: Session,
        plan: ResponsePlanRow,
        actor_id: UUID,
        reason: str,
        now: datetime,
    ) -> ResponsePlanMutationView:
        if plan.status == "rejected":
            return ResponsePlanMutationView(
                plan_id=UUID(plan.id),
                status=plan.status,
                revision=plan.current_revision,
                calls=[],
            )
        if plan.status != "proposed":
            raise ResponsePlanDecisionConflict("response plan cannot be rejected in this state")
        changed = session.execute(
            update(ResponsePlanRow)
            .where(
                ResponsePlanRow.id == plan.id,
                ResponsePlanRow.tenant_id == plan.tenant_id,
                ResponsePlanRow.status == "proposed",
                ResponsePlanRow.current_revision == plan.current_revision,
            )
            .values(status="rejected", updated_at=now)
        )
        if changed.rowcount != 1:
            raise ResponsePlanDecisionConflict("response plan decision is stale")
        plan.status = "rejected"
        plan.updated_at = now
        self._event(
            session,
            plan,
            actor_id,
            "plan_rejected",
            "operator_rejected",
            f"响应计划已由操作员拒绝：{reason}",
            now,
        )
        return ResponsePlanMutationView(
            plan_id=UUID(plan.id),
            status=plan.status,
            revision=plan.current_revision,
            calls=[],
        )

    def _create_call(
        self,
        session: Session,
        plan: ResponsePlanRow,
        revision: ResponsePlanRevisionRow,
        action: ResponsePlanActionRow,
        actor_id: UUID,
        now: datetime,
    ) -> TrustedToolCall:
        if action.status != "proposed":
            raise ResponsePlanDecisionConflict("response plan action is not proposed")
        try:
            registration = self._registry.resolve(action.tool_name, action.tool_version)
        except ToolRegistryError as error:
            raise ResponsePlanDecisionConflict("response plan tool binding is stale") from error
        definition = registration.definition
        if (
            AgentRole.RESPONSE_PLANNING not in definition.allowed_roles
            or definition.target_type.value != action.target_type
            or definition.risk.value != action.assessed_risk
            or definition.mutates_state != action.approval_required
            or definition.verifier_name != action.verification_tool
            or (definition.verifier_name is None and action.verification_version is not None)
        ):
            raise ResponsePlanDecisionConflict("response plan action binding is stale")
        if action.verification_tool is not None:
            try:
                verifier = self._registry.resolve(
                    action.verification_tool,
                    action.verification_version or "",
                )
            except ToolRegistryError as error:
                raise ResponsePlanDecisionConflict(
                    "response plan verifier binding is stale"
                ) from error
            if verifier.definition.name != definition.verifier_name:
                raise ResponsePlanDecisionConflict("response plan verifier binding is stale")

        evidence = self._evidence(session, plan, action, now)
        request = TrustedToolRequest(
            uuid4(),
            UUID(plan.case_id),  # type: ignore[arg-type]
            UUID(plan.run_id),
            UUID(plan.id),
            f"plan-action:{action.id}:v{action.tool_version}",
            AgentRole.RESPONSE_PLANNING,
            action.tool_name,
            action.tool_version,
            dict(action.arguments_json),
            dict(action.expected_state_json),
            action.rollback_strategy,
            evidence,
            now,
        )
        try:
            bound = self._registry.bind(request)
        except (ToolRegistryError, TypeError, ValueError) as error:
            raise ResponsePlanDecisionConflict("response plan parameters are stale") from error
        target_field = {
            ToolTargetType.IPV4: "target_ip",
            ToolTargetType.ENDPOINT: "endpoint_id",
            ToolTargetType.ACCOUNT: "account_id",
        }[definition.target_type]
        if bound.request.arguments.get(target_field) != action.target_identifier:
            raise ResponsePlanDecisionConflict("response plan target binding is stale")

        existing_count = int(
            session.scalar(
                select(func.count())
                .select_from(TrustedToolCallRow)
                .where(
                    TrustedToolCallRow.tenant_id == plan.tenant_id,
                    TrustedToolCallRow.run_id == plan.run_id,
                )
            )
            or 0
        )
        recent_count = int(
            session.scalar(
                select(func.count())
                .select_from(TrustedToolCallRow)
                .where(
                    TrustedToolCallRow.tenant_id == plan.tenant_id,
                    TrustedToolCallRow.run_id == plan.run_id,
                    TrustedToolCallRow.created_at >= now - timedelta(minutes=1),
                )
            )
            or 0
        )
        repo = SqlAlchemyTrustedToolRepository()
        call, created = repo.create_or_get(
            session,
            tenant_id=UUID(plan.tenant_id),
            bound=bound,
            request_id=f"plan-accept:{plan.id}:{action.sequence}",
            plan_revision_id=UUID(revision.id),
            plan_action_id=UUID(action.id),
        )
        if not created:
            return call
        control = session.get(ToolAutomationControlRow, plan.tenant_id)
        context = ToolPolicyContext(
            tenant_id=UUID(plan.tenant_id),
            principal_id=actor_id,
            case_id=UUID(plan.case_id),  # type: ignore[arg-type]
            run_id=UUID(plan.run_id),
            role=AgentRole.RESPONSE_PLANNING,
            mode=ToolExecutionMode.REAL,
            automation_enabled=control.automation_enabled if control else True,
            emergency_stop_active=control.emergency_stop_active if control else False,
            allowed_tools=frozenset({definition.identity}),
            allowed_targets={definition.target_type: frozenset({action.target_identifier})},
            confirmed_evidence_ids=frozenset(item.id for item in evidence),
            tool_calls_used=existing_count,
            tool_call_limit=8,
            calls_in_window=recent_count,
            rate_limit=8,
            simulation_auto_approve_critical=False,
            now=now,
        )
        policy = self._policy.evaluate(bound, context)
        repo.append_policy(session, tenant_id=UUID(plan.tenant_id), decision=policy)
        call = repo.transition(
            session,
            tenant_id=UUID(plan.tenant_id),
            current=call,
            target=TrustedToolCallStatus.POLICY_CHECKED,
            now=now,
            request_id=f"plan-policy:{action.id}",
            reason=policy.reason,
        )
        target = {
            PolicyOutcome.DENY: TrustedToolCallStatus.REJECTED,
            PolicyOutcome.APPROVAL_REQUIRED: TrustedToolCallStatus.AWAITING_APPROVAL,
            PolicyOutcome.ALLOW: TrustedToolCallStatus.APPROVED,
        }[policy.outcome]
        return repo.transition(
            session,
            tenant_id=UUID(plan.tenant_id),
            current=call,
            target=target,
            now=now,
            request_id=f"plan-policy-result:{action.id}",
            reason=policy.reason,
        )

    @staticmethod
    def _current_revision(session: Session, plan: ResponsePlanRow) -> ResponsePlanRevisionRow:
        revision = session.execute(
            select(ResponsePlanRevisionRow).where(
                ResponsePlanRevisionRow.plan_id == plan.id,
                ResponsePlanRevisionRow.tenant_id == plan.tenant_id,
                ResponsePlanRevisionRow.revision == plan.current_revision,
                ResponsePlanRevisionRow.reason_code.is_(None),
            )
        ).scalar_one_or_none()
        if revision is None:
            raise ResponsePlanDecisionConflict("current response plan revision is invalid")
        return revision

    @staticmethod
    def _evidence(
        session: Session,
        plan: ResponsePlanRow,
        action: ResponsePlanActionRow,
        now: datetime,
    ) -> tuple[EvidenceReference, ...]:
        references = []
        for evidence_id in action.evidence_ids_json:
            row = confirmed_evidence(
                session, run_id=plan.run_id, evidence_id=evidence_id
            )
            if row is None or plan.case_id is None:
                raise ResponsePlanDecisionConflict("response plan evidence is no longer valid")
            observed_at = _utc(row.observed_at)
            if observed_at > now + timedelta(minutes=5) or now - observed_at > timedelta(days=31):
                raise ResponsePlanDecisionConflict("response plan evidence is stale")
            references.append(
                EvidenceReference(
                    UUID(row.id),
                    UUID(plan.case_id),
                    row.raw_reference,
                    _utc(row.observed_at),
                    row.integrity_sha256,
                )
            )
        if not references or str(action.target_reference_id) not in {
            str(item.id) for item in references
        }:
            raise ResponsePlanDecisionConflict("response plan target evidence is missing")
        target_row = confirmed_evidence(
            session, run_id=plan.run_id, evidence_id=action.target_reference_id
        )
        if target_row is None:
            raise ResponsePlanDecisionConflict("response plan target evidence is missing")
        target_fields = {
            "ipv4": ("target_ip", "source_ip", "destination_ip"),
            "endpoint": ("endpoint_id", "agent_id"),
            "account": ("account_id", "user_id", "username"),
        }.get(action.target_type, ())
        current_target = next(
            (
                str(target_row.payload_json[field]).strip()
                for field in target_fields
                if isinstance(target_row.payload_json.get(field), str)
                and str(target_row.payload_json[field]).strip()
            ),
            None,
        )
        if current_target != action.target_identifier:
            raise ResponsePlanDecisionConflict("response plan target evidence has changed")
        return tuple(references)

    @staticmethod
    def _linked_calls(
        session: Session,
        plan: ResponsePlanRow,
        revision: ResponsePlanRevisionRow,
    ) -> list[TrustedToolCall]:
        rows = list(
            session.scalars(
                select(TrustedToolCallRow)
                .join(
                    ResponsePlanActionRow,
                    TrustedToolCallRow.plan_action_id == ResponsePlanActionRow.id,
                )
                .where(
                    TrustedToolCallRow.tenant_id == plan.tenant_id,
                    TrustedToolCallRow.plan_revision_id == revision.id,
                )
                .order_by(ResponsePlanActionRow.sequence)
            )
        )
        return [_call(row) for row in rows]

    @staticmethod
    def _event(
        session: Session,
        plan: ResponsePlanRow,
        actor_id: UUID,
        event_type: str,
        reason_code: str,
        summary: str,
        now: datetime,
    ) -> None:
        session.add(
            ResponsePlanEventRow(
                id=str(uuid4()),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=plan.current_revision,
                event_type=event_type,
                reason_code=reason_code,
                public_summary=summary[:1000],
                actor_subject_id=str(actor_id),
                created_at=now,
            )
        )

    @staticmethod
    def _view(
        session: Session,
        plan: ResponsePlanRow,
        calls: list[TrustedToolCall],
    ) -> ResponsePlanMutationView:
        call_ids = [str(call.request.id) for call in calls]
        rows = (
            list(
                session.scalars(
                    select(TrustedToolCallRow).where(
                        TrustedToolCallRow.tenant_id == plan.tenant_id,
                        TrustedToolCallRow.id.in_(call_ids),
                    )
                )
            )
            if call_ids
            else []
        )
        action_ids = {row.id: row.plan_action_id for row in rows}
        if len(action_ids) != len(calls) or any(value is None for value in action_ids.values()):
            raise ResponsePlanDecisionConflict("trusted tool plan action binding is missing")
        return ResponsePlanMutationView(
            plan_id=UUID(plan.id),
            status=plan.status,
            revision=plan.current_revision,
            calls=[
                ResponsePlanToolCallView(
                    action_id=UUID(str(action_ids[str(call.request.id)])),
                    call_id=call.request.id,
                    tool_name=call.request.tool_name,
                    tool_version=call.request.tool_version,
                    status=call.status.value,
                    request_digest=call.request.request_digest,
                )
                for call in calls
            ],
        )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _reason(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("response plan decision reason must be a string")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 512:
        raise ValueError("response plan decision reason is invalid")
    return normalized
