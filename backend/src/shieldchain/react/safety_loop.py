"""Recoverable orchestration from trusted tool calls to verified response outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import AgentRole, BudgetSnapshot
from shieldchain.agents.persistence import AgentExecutionRow, AgentRunRow, CaseContextRow
from shieldchain.incidents.persistence import IncidentRow, InvestigationRunRow
from shieldchain.react.budget import ReactConsumption
from shieldchain.react.classification import TrustedFailureInput
from shieldchain.react.domain import (
    FailureCategory,
    ObservationSource,
    PlanRevision,
    ProposedAction,
    ReactDecision,
    ReactLoop,
    ReactLoopStatus,
    ReactObservation,
)
from shieldchain.react.persistence import ReactLoopRow, ReactObservationRow
from shieldchain.react.repositories import SqlAlchemyReactRepository
from shieldchain.react.service import ControlledReactService, SqlAlchemyReactStepStore
from shieldchain.response_planning.persistence import (
    ResponsePlanActionRow,
    ResponsePlanEventRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)
from shieldchain.tools.approval_store import SqlAlchemyApprovalStore
from shieldchain.tools.domain import (
    ApprovalDecision,
    ApprovalOutcome,
    ExecutionOutcome,
    PolicyDecision,
    PolicyOutcome,
    PolicyReason,
    ToolExecutionAttempt,
    ToolRisk,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.execution_store import (
    ExecutionLeaseConflict,
    ExecutionLeaseNotFound,
    SqlAlchemyExecutionStore,
)
from shieldchain.tools.gateway import (
    AdapterExecution,
    GatewayResult,
    TrustedToolAdapter,
    TrustedToolGateway,
)
from shieldchain.tools.gateway_store import SqlAlchemyGatewayStore
from shieldchain.tools.persistence import (
    ToolAutomationControlRow,
    ToolExecutionAttemptRow,
    ToolPolicyDecisionRow,
    ToolVerificationRow,
    TrustedToolCallRow,
)
from shieldchain.tools.policy import ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import BoundToolRequest, TrustedToolRegistry, default_tool_registry
from shieldchain.tools.repositories import SqlAlchemyTrustedToolRepository, _call
from shieldchain.tools.simulation import OfflineSimulationAdapter

_SYSTEM_ACTOR = UUID("00000000-0000-4000-8000-000000000006")


class SafetyLoopConflict(RuntimeError):
    pass


class AdapterProvider(Protocol):
    def for_run(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        now: datetime,
    ) -> TrustedToolAdapter | None: ...


@dataclass(frozen=True, slots=True)
class SafetyLoopResult:
    plan_id: UUID
    plan_status: str
    loop_id: UUID
    loop_status: ReactLoopStatus
    processed_call_ids: tuple[UUID, ...]
    reason_code: str


class SimulationAdapterPool:
    """Process-local adapter pool restricted to existing simulation investigations."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._items: dict[UUID, OfflineSimulationAdapter] = {}

    def for_run(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        now: datetime,
    ) -> TrustedToolAdapter | None:
        investigation = session.execute(
            select(InvestigationRunRow).where(
                InvestigationRunRow.id == str(run_id),
                InvestigationRunRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if investigation is None:
            return None
        incident = session.execute(
            select(IncidentRow).where(
                IncidentRow.id == investigation.incident_id,
                IncidentRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if incident is None:
            return None
        with self._lock:
            existing = self._items.get(run_id)
            if existing is not None:
                return existing
            calls = list(
                session.scalars(
                    select(TrustedToolCallRow).where(
                        TrustedToolCallRow.tenant_id == str(tenant_id),
                        TrustedToolCallRow.run_id == str(run_id),
                    )
                )
            )
            firewall = {
                str(row.arguments_json["target_ip"])
                for row in calls
                if "target_ip" in row.arguments_json
            }
            endpoints = {
                str(row.arguments_json["endpoint_id"])
                for row in calls
                if "endpoint_id" in row.arguments_json
            }
            accounts = {
                str(row.arguments_json["account_id"])
                for row in calls
                if "account_id" in row.arguments_json
            }
            adapter = OfflineSimulationAdapter(
                initialized_at=now,
                firewall_targets=frozenset(firewall | {incident.source_ip, incident.remote_ip}),
                endpoint_targets=frozenset(endpoints | {incident.endpoint}),
                account_targets=frozenset(accounts | {incident.username}),
            )
            self._items[run_id] = adapter
            return adapter


class ResponseSafetyLoopService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        registry: TrustedToolRegistry | None = None,
        adapters: AdapterProvider | None = None,
    ) -> None:
        self._sessions = sessions
        self._registry = registry or default_tool_registry()
        self._adapters = adapters or SimulationAdapterPool()
        self._gateway = TrustedToolGateway()
        self._react = ControlledReactService()

    def advance_plan(
        self,
        *,
        tenant_id: UUID,
        plan_id: UUID,
        now: datetime,
        adapter: TrustedToolAdapter | None = None,
    ) -> SafetyLoopResult:
        _require_utc(now)
        with self._sessions.begin() as session:
            plan, revision, actions = self._plan(session, tenant_id, plan_id)
            loop = self._ensure_loop(session, tenant_id, plan, now)
            if plan.status == "completed":
                return self._result(plan, loop, (), "plan_already_completed")
            if plan.status in {"needs_review", "rejected", "cancelled"}:
                if loop.status in {
                    ReactLoopStatus.RUNNING,
                    ReactLoopStatus.AWAITING_EXECUTION,
                }:
                    loop = self._set_loop(
                        session,
                        tenant_id,
                        loop,
                        ReactLoopStatus.AWAITING_HUMAN,
                        now,
                    )
                return self._result(plan, loop, (), "plan_requires_operator")
            selected_adapter = adapter or self._adapters.for_run(
                session,
                tenant_id=tenant_id,
                run_id=UUID(plan.run_id),
                now=now,
            )
            if selected_adapter is None:
                loop = self._manual_without_call(
                    session,
                    tenant_id,
                    plan,
                    loop,
                    FailureCategory.DEPENDENCY_UNAVAILABLE,
                    "trusted_adapter_unavailable",
                    now,
                )
                return self._result(plan, loop, (), "trusted_adapter_unavailable")

            linked = self._linked_calls(session, plan, revision)
            if len(linked) != len(actions):
                raise SafetyLoopConflict(
                    "current plan actions are not fully linked to trusted calls"
                )
            processed: list[UUID] = []
            for index, (action, call_row) in enumerate(zip(actions, linked, strict=True)):
                call = _call(call_row)
                verification = self._latest_verification(session, tenant_id, call.request.id)
                if self._verified(call, verification):
                    if not self._observation_exists(session, call.request.id, verification.id):
                        loop, decision = self._record_terminal(
                            session,
                            tenant_id,
                            plan,
                            revision,
                            actions,
                            loop,
                            action,
                            call,
                            self._latest_attempt(session, tenant_id, call.request.id),
                            verification,
                            completion_is_final=index == len(actions) - 1,
                            now=now,
                        )
                        processed.append(call.request.id)
                        if decision is not ReactDecision.CONTINUE_VERIFICATION:
                            return self._after_decision(
                                session,
                                tenant_id,
                                plan,
                                loop,
                                call,
                                action,
                                decision,
                                selected_adapter,
                                processed,
                                now,
                            )
                    if loop.status is ReactLoopStatus.AWAITING_EXECUTION:
                        loop = self._set_loop(
                            session, tenant_id, loop, ReactLoopStatus.RUNNING, now
                        )
                    continue

                if call.status is TrustedToolCallStatus.AWAITING_APPROVAL:
                    approval = SqlAlchemyApprovalStore(session).latest(
                        tenant_id=tenant_id,
                        request_id=call.request.id,
                    )
                    if approval is None or approval.outcome is not ApprovalOutcome.APPROVED:
                        loop = self._waiting(session, tenant_id, plan, loop, now)
                        return self._result(plan, loop, tuple(processed), "tool_approval_required")
                    if not _budget_allows_dispatch(loop, now):
                        loop = self._manual_without_call(
                            session,
                            tenant_id,
                            plan,
                            loop,
                            FailureCategory.BUDGET_EXHAUSTED,
                            "budget_exhausted",
                            now,
                        )
                        return self._result(plan, loop, tuple(processed), "budget_exhausted")
                    try:
                        result = self._execute_approved(
                            session,
                            tenant_id,
                            call,
                            approval,
                            selected_adapter,
                            now,
                        )
                    except (ExecutionLeaseConflict, ValueError):
                        loop, reason = self._dispatch_stopped(session, tenant_id, plan, loop, now)
                        return self._result(plan, loop, tuple(processed), reason)
                elif call.status is TrustedToolCallStatus.APPROVED:
                    if not _budget_allows_dispatch(loop, now):
                        loop = self._manual_without_call(
                            session,
                            tenant_id,
                            plan,
                            loop,
                            FailureCategory.BUDGET_EXHAUSTED,
                            "budget_exhausted",
                            now,
                        )
                        return self._result(plan, loop, tuple(processed), "budget_exhausted")
                    try:
                        result = self._execute_prepared(
                            session, tenant_id, call, selected_adapter, now
                        )
                    except (ExecutionLeaseConflict, ValueError):
                        loop, reason = self._dispatch_stopped(session, tenant_id, plan, loop, now)
                        return self._result(plan, loop, tuple(processed), reason)
                elif call.status is TrustedToolCallStatus.VERIFYING:
                    try:
                        result = self._recover_verification(
                            session, tenant_id, call, selected_adapter, now
                        )
                    except ValueError:
                        loop, reason = self._dispatch_stopped(session, tenant_id, plan, loop, now)
                        return self._result(plan, loop, tuple(processed), reason)
                elif call.status is TrustedToolCallStatus.EXECUTING:
                    result = self._recover_execution(
                        session, tenant_id, call, selected_adapter, now
                    )
                    if result is None:
                        call = SqlAlchemyTrustedToolRepository().get(
                            session, tenant_id=tenant_id, tool_call_id=call.request.id
                        )
                        assert call is not None
                        attempt = self._latest_attempt(session, tenant_id, call.request.id)
                        verification = self._latest_verification(
                            session, tenant_id, call.request.id
                        )
                        loop, decision = self._record_terminal(
                            session,
                            tenant_id,
                            plan,
                            revision,
                            actions,
                            loop,
                            action,
                            call,
                            attempt,
                            verification,
                            completion_is_final=False,
                            now=now,
                        )
                        processed.append(call.request.id)
                        return self._after_decision(
                            session,
                            tenant_id,
                            plan,
                            loop,
                            call,
                            action,
                            decision,
                            selected_adapter,
                            processed,
                            now,
                        )
                elif call.status in {
                    TrustedToolCallStatus.FAILED,
                    TrustedToolCallStatus.NEEDS_REVIEW,
                    TrustedToolCallStatus.REJECTED,
                    TrustedToolCallStatus.EMERGENCY_STOPPED,
                }:
                    result = GatewayResult(
                        call,
                        False,
                        attempt=self._latest_attempt(session, tenant_id, call.request.id),
                        verification=verification,
                    )
                else:
                    loop = self._manual_without_call(
                        session,
                        tenant_id,
                        plan,
                        loop,
                        FailureCategory.UNCLASSIFIED_FAILURE,
                        "trusted_call_not_dispatchable",
                        now,
                    )
                    return self._result(
                        plan, loop, tuple(processed), "trusted_call_not_dispatchable"
                    )

                processed.append(result.call.request.id)
                loop, decision = self._record_terminal(
                    session,
                    tenant_id,
                    plan,
                    revision,
                    actions,
                    loop,
                    action,
                    result.call,
                    result.attempt
                    or self._latest_attempt(session, tenant_id, result.call.request.id),
                    result.verification
                    or self._latest_verification(session, tenant_id, result.call.request.id),
                    completion_is_final=index == len(actions) - 1,
                    now=now,
                )
                if decision is ReactDecision.CONTINUE_VERIFICATION:
                    loop = self._set_loop(session, tenant_id, loop, ReactLoopStatus.RUNNING, now)
                    continue
                return self._after_decision(
                    session,
                    tenant_id,
                    plan,
                    loop,
                    result.call,
                    action,
                    decision,
                    selected_adapter,
                    processed,
                    now,
                )

            self._complete(session, plan, loop, now)
            return self._result(plan, loop, tuple(processed), "plan_verified_completed")

    def recover_stale(
        self,
        *,
        tenant_id: UUID,
        now: datetime,
        stale_after: timedelta = timedelta(seconds=30),
    ) -> tuple[SafetyLoopResult, ...]:
        _require_utc(now)
        with self._sessions() as session:
            plan_ids = [
                UUID(value)
                for value in session.scalars(
                    select(ResponsePlanRow.id)
                    .join(ReactLoopRow, ReactLoopRow.run_id == ResponsePlanRow.run_id)
                    .where(
                        ResponsePlanRow.tenant_id == str(tenant_id),
                        ResponsePlanRow.status.in_({"awaiting_execution", "executing"}),
                        ReactLoopRow.tenant_id == str(tenant_id),
                        ReactLoopRow.status == ReactLoopStatus.RUNNING.value,
                        ReactLoopRow.updated_at <= now - stale_after,
                    )
                )
            ]
        results = []
        for plan_id in plan_ids:
            results.append(self.advance_plan(tenant_id=tenant_id, plan_id=plan_id, now=now))
        return tuple(results)

    def _execute_prepared(
        self,
        session: Session,
        tenant_id: UUID,
        call: TrustedToolCall,
        adapter: TrustedToolAdapter,
        now: datetime,
    ) -> GatewayResult:
        bound = self._registry.bind(call.request)
        policy = self._latest_policy(session, tenant_id, call.request.id)
        if policy is None:
            raise SafetyLoopConflict("trusted call policy is missing")
        return self._gateway.execute_prepared(
            bound=bound,
            call=call,
            policy=policy,
            context=self._policy_context(session, tenant_id, bound, now),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id=f"safety-dispatch:{call.request.id}",
        )

    def _execute_approved(
        self,
        session: Session,
        tenant_id: UUID,
        call: TrustedToolCall,
        approval: ApprovalDecision,
        adapter: TrustedToolAdapter,
        now: datetime,
    ) -> GatewayResult:
        bound = self._registry.bind(call.request)
        policy = self._latest_policy(session, tenant_id, call.request.id)
        if policy is None:
            raise SafetyLoopConflict("trusted call policy is missing")
        return self._gateway.execute_after_approval(
            bound=bound,
            call=call,
            policy=policy,
            approval=approval,
            context=self._policy_context(session, tenant_id, bound, now),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id=f"safety-approved:{call.request.id}",
        )

    def _recover_verification(
        self,
        session: Session,
        tenant_id: UUID,
        call: TrustedToolCall,
        adapter: TrustedToolAdapter,
        now: datetime,
    ) -> GatewayResult:
        attempt = self._latest_attempt(session, tenant_id, call.request.id)
        if attempt is None or attempt.outcome is not ExecutionOutcome.SUCCEEDED:
            raise SafetyLoopConflict("successful attempt is missing for recovery verification")
        execution = AdapterExecution(attempt.outcome, attempt.result_summary, None)
        bound = self._registry.bind(call.request)
        return self._gateway.verify_after_recovery(
            bound=bound,
            call=call,
            execution=execution,
            context=self._policy_context(session, tenant_id, bound, now),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id=f"safety-recover-verification:{call.request.id}",
        )

    def _recover_execution(
        self,
        session: Session,
        tenant_id: UUID,
        call: TrustedToolCall,
        adapter: TrustedToolAdapter,
        now: datetime,
    ) -> GatewayResult | None:
        execution = SqlAlchemyExecutionStore(session)
        try:
            execution.expire_active_lease(
                tenant_id=tenant_id,
                call=call,
                now=now,
                request_id=f"safety-expire:{call.request.id}",
            )
        except ExecutionLeaseNotFound as error:
            raise SafetyLoopConflict("in-flight call has no expired lease") from error
        repo = SqlAlchemyTrustedToolRepository()
        call = repo.transition(
            session,
            tenant_id=tenant_id,
            current=call,
            target=TrustedToolCallStatus.NEEDS_REVIEW,
            now=now,
            request_id=f"safety-unknown:{call.request.id}",
            reason=PolicyReason.EXECUTION_OUTCOME_UNKNOWN,
        )
        if not self._registry.bind(call.request).registration.definition.mutates_state:
            self._run_recovery_query(session, tenant_id, call, adapter, now, retry_same=True)
        return None

    def _record_terminal(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        revision: ResponsePlanRevisionRow,
        actions: list[ResponsePlanActionRow],
        loop: ReactLoop,
        action: ResponsePlanActionRow,
        call: TrustedToolCall,
        attempt: ToolExecutionAttempt | None,
        verification: ToolVerification | None,
        *,
        completion_is_final: bool,
        now: datetime,
    ) -> tuple[ReactLoop, ReactDecision]:
        if loop.status is ReactLoopStatus.AWAITING_EXECUTION:
            loop = self._set_loop(session, tenant_id, loop, ReactLoopStatus.RUNNING, now)
        if loop.status is not ReactLoopStatus.RUNNING:
            raise SafetyLoopConflict("react loop is not ready for a terminal observation")
        observation = self._observation(loop, call, verification, now)
        current_plan, action_map = self._react_plan(session, plan, revision, actions, loop)
        failed_action = action_map.get(UUID(action.id))
        if failed_action is None:
            raise SafetyLoopConflict("response action is missing from the ReAct plan")
        control = session.get(ToolAutomationControlRow, str(tenant_id))
        failure = TrustedFailureInput(
            observation,
            call=call,
            attempt=attempt,
            verification=verification,
            automation_enabled=control.automation_enabled if control else True,
            emergency_stop_active=control.emergency_stop_active if control else False,
        )
        result = self._react.step(
            tenant_id=tenant_id,
            loop=loop,
            current_plan=current_plan,
            failure=failure,
            failed_action=failed_action,
            failed_tool_name=call.request.tool_name,
            candidates=tuple(item for key, item in action_map.items() if key != UUID(action.id)),
            consumption=ReactConsumption(tool_calls=1),
            registry=self._registry,
            now=now,
            store=SqlAlchemyReactStepStore(session),
            completion_is_final=completion_is_final,
        )
        return result.loop, result.decision.decision

    def _after_decision(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        loop: ReactLoop,
        call: TrustedToolCall,
        action: ResponsePlanActionRow,
        decision: ReactDecision,
        adapter: TrustedToolAdapter,
        processed: list[UUID],
        now: datetime,
    ) -> SafetyLoopResult:
        if decision is ReactDecision.COMPLETE:
            self._complete(session, plan, loop, now)
            return self._result(plan, loop, tuple(processed), "plan_verified_completed")
        if decision in {ReactDecision.QUERY_STATUS, ReactDecision.RETRY_READ_ONLY}:
            recovery = self._run_recovery_query(
                session,
                tenant_id,
                call,
                adapter,
                now,
                retry_same=decision is ReactDecision.RETRY_READ_ONLY,
            )
            processed.append(recovery.call.request.id)
            repository = SqlAlchemyReactRepository()
            repository.append_observation(
                session,
                tenant_id=tenant_id,
                loop=loop,
                observation=self._observation(
                    loop,
                    recovery.call,
                    recovery.verification,
                    now,
                ),
            )
        category = _failure_category(
            call, self._latest_verification(session, tenant_id, call.request.id)
        )
        self._append_failure_revision(session, plan, category, now)
        if loop.status is not ReactLoopStatus.AWAITING_HUMAN:
            loop = self._set_loop(session, tenant_id, loop, ReactLoopStatus.AWAITING_HUMAN, now)
        self._sync_run(session, plan, "needs_review", now)
        return self._result(plan, loop, tuple(processed), f"{category.value}_requires_operator")

    def _run_recovery_query(
        self,
        session: Session,
        tenant_id: UUID,
        original: TrustedToolCall,
        adapter: TrustedToolAdapter,
        now: datetime,
        *,
        retry_same: bool = False,
    ) -> GatewayResult:
        original_bound = self._registry.bind(original.request)
        definition = original_bound.registration.definition
        tool_name = definition.name if retry_same else definition.verifier_name
        if tool_name is None:
            raise SafetyLoopConflict("state-changing call has no registered status query")
        registration = next(
            item for item in self._registry.registrations if item.definition.name == tool_name
        )
        target_field = {
            "ipv4": "target_ip",
            "endpoint": "endpoint_id",
            "account": "account_id",
        }[registration.definition.target_type.value]
        arguments = {target_field: original.request.arguments[target_field]}
        request = TrustedToolRequest(
            uuid4(),
            original.request.case_id,
            original.request.run_id,
            original.request.plan_id,
            f"safety-query:{original.request.id}:{original.revision}",
            AgentRole.RESPONSE_PLANNING,
            registration.definition.name,
            registration.definition.version,
            arguments,
            dict(original.request.expected_state),
            "Read-only recovery query requires no rollback.",
            original.request.evidence,
            now,
        )
        bound = self._registry.bind(request)
        return self._gateway.submit(
            bound=bound,
            context=self._policy_context(session, tenant_id, bound, now),
            store=SqlAlchemyGatewayStore(session),
            adapter=adapter,
            request_id=f"safety-query:{original.request.id}",
        )

    def _policy_context(
        self,
        session: Session,
        tenant_id: UUID,
        bound: BoundToolRequest,
        now: datetime,
    ) -> ToolPolicyContext:
        control = session.get(ToolAutomationControlRow, str(tenant_id))
        definition = bound.registration.definition
        target = next(
            str(bound.request.arguments[key])
            for key in ("target_ip", "endpoint_id", "account_id")
            if key in bound.request.arguments
        )
        call_count = int(
            session.scalar(
                select(func.count())
                .select_from(TrustedToolCallRow)
                .where(
                    TrustedToolCallRow.tenant_id == str(tenant_id),
                    TrustedToolCallRow.run_id == str(bound.request.run_id),
                )
            )
            or 0
        )
        return ToolPolicyContext(
            tenant_id=tenant_id,
            principal_id=_SYSTEM_ACTOR,
            case_id=bound.request.case_id,
            run_id=bound.request.run_id,
            role=AgentRole.RESPONSE_PLANNING,
            mode=ToolExecutionMode.REAL,
            automation_enabled=control.automation_enabled if control else True,
            emergency_stop_active=control.emergency_stop_active if control else False,
            allowed_tools=frozenset({definition.identity}),
            allowed_targets={definition.target_type: frozenset({target})},
            confirmed_evidence_ids=frozenset(item.id for item in bound.request.evidence),
            tool_calls_used=max(call_count - 1, 0),
            tool_call_limit=16,
            calls_in_window=0,
            rate_limit=16,
            simulation_auto_approve_critical=False,
            now=now,
        )

    def _ensure_loop(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        now: datetime,
    ) -> ReactLoop:
        repository = SqlAlchemyReactRepository()
        existing = repository.get_by_run(session, tenant_id=tenant_id, run_id=UUID(plan.run_id))
        if existing is not None:
            return existing
        loop = ReactLoop(
            uuid5(NAMESPACE_URL, f"shieldchain:safety-loop:{plan.run_id}"),
            UUID(plan.case_id),  # type: ignore[arg-type]
            UUID(plan.run_id),
            ReactLoopStatus.RUNNING,
            0,
            BudgetSnapshot(16, 0, 8, 0, 900, 0, 1000, 0, 1.0, 0.0, 16, 0),
            (),
            now,
            now,
        )
        return repository.create(session, tenant_id=tenant_id, loop=loop)

    def _set_loop(
        self,
        session: Session,
        tenant_id: UUID,
        loop: ReactLoop,
        target: ReactLoopStatus,
        now: datetime,
    ) -> ReactLoop:
        if loop.status is target:
            return loop
        return SqlAlchemyReactRepository().transition_status(
            session,
            tenant_id=tenant_id,
            current=loop,
            target=target,
            now=now,
        )

    def _waiting(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        loop: ReactLoop,
        now: datetime,
    ) -> ReactLoop:
        if loop.status is ReactLoopStatus.RUNNING:
            loop = self._set_loop(session, tenant_id, loop, ReactLoopStatus.AWAITING_EXECUTION, now)
        plan.status = "awaiting_execution"
        plan.updated_at = now
        self._sync_run(session, plan, "awaiting_approval", now)
        return loop

    def _manual_without_call(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        loop: ReactLoop,
        category: FailureCategory,
        reason_code: str,
        now: datetime,
    ) -> ReactLoop:
        self._append_failure_revision(session, plan, category, now)
        if loop.status is not ReactLoopStatus.AWAITING_HUMAN:
            loop = self._set_loop(session, tenant_id, loop, ReactLoopStatus.AWAITING_HUMAN, now)
        self._event(session, plan, "safety_loop_stopped", reason_code, now)
        self._sync_run(session, plan, "needs_review", now)
        return loop

    def _dispatch_stopped(
        self,
        session: Session,
        tenant_id: UUID,
        plan: ResponsePlanRow,
        loop: ReactLoop,
        now: datetime,
    ) -> tuple[ReactLoop, str]:
        control = session.get(ToolAutomationControlRow, str(tenant_id))
        if control is not None and control.emergency_stop_active:
            category = FailureCategory.EMERGENCY_STOPPED
            reason = "emergency_stopped"
        elif control is not None and not control.automation_enabled:
            category = FailureCategory.AUTOMATION_DISABLED
            reason = "automation_disabled"
        else:
            category = FailureCategory.DEPENDENCY_UNAVAILABLE
            reason = "trusted_dispatch_unavailable"
        return (
            self._manual_without_call(
                session,
                tenant_id,
                plan,
                loop,
                category,
                reason,
                now,
            ),
            reason,
        )

    def _complete(
        self,
        session: Session,
        plan: ResponsePlanRow,
        loop: ReactLoop,
        now: datetime,
    ) -> None:
        plan.status = "completed"
        plan.updated_at = now
        self._event(session, plan, "plan_verified_completed", None, now)
        self._sync_run(session, plan, "completed", now)
        if loop.status is not ReactLoopStatus.COMPLETED:
            raise SafetyLoopConflict("verified plan did not complete its ReAct loop")

    def _append_failure_revision(
        self,
        session: Session,
        plan: ResponsePlanRow,
        category: FailureCategory,
        now: datetime,
    ) -> None:
        latest = session.execute(
            select(ResponsePlanRevisionRow).where(
                ResponsePlanRevisionRow.plan_id == plan.id,
                ResponsePlanRevisionRow.revision == plan.current_revision,
            )
        ).scalar_one()
        if plan.status == "needs_review" and latest.reason_code == category.value:
            return
        revision_number = plan.current_revision + 1
        session.add(
            ResponsePlanRevisionRow(
                id=str(uuid4()),
                plan_id=plan.id,
                tenant_id=plan.tenant_id,
                revision=revision_number,
                parent_revision=plan.current_revision,
                public_summary=("执行闭环未能安全确认计划完成；已停止自动化并要求人工复核。"),
                assumptions_json=[],
                stop_conditions_json=["执行或验证结果未满足安全完成条件"],
                operator_notes_json=["未重放结果未知的状态变更动作"],
                reason_code=category.value,
                model_id=None,
                prompt_policy_version="deterministic-safety-loop-v1",
                created_at=now,
            )
        )
        plan.current_revision = revision_number
        plan.status = "needs_review"
        plan.updated_at = now
        self._event(session, plan, "plan_replanning_stopped", category.value, now)

    @staticmethod
    def _sync_run(
        session: Session,
        plan: ResponsePlanRow,
        status: str,
        now: datetime,
    ) -> None:
        agent = session.get(AgentRunRow, plan.run_id)
        investigation = session.get(InvestigationRunRow, plan.run_id)
        context = session.execute(
            select(CaseContextRow).where(
                CaseContextRow.run_id == plan.run_id,
                CaseContextRow.tenant_id == plan.tenant_id,
            )
        ).scalar_one_or_none()
        if agent is not None:
            agent.status = status
            agent.revision += 1
            agent.updated_at = now
            if status == "completed":
                agent.completed_at = now
        if investigation is not None:
            investigation.status = {
                "awaiting_approval": "action_planned",
                "needs_review": "needs_review",
                "completed": "closed",
            }[status]
            investigation.updated_at = now
            if status == "completed":
                investigation.completed_at = now
        if context is not None:
            context.phase = {
                "awaiting_approval": "awaiting_execution",
                "needs_review": "needs_review",
                "completed": "closed",
            }[status]
            context.revision += 1
            steps = dict(context.step_status_json)
            steps.update(
                {
                    "trusted_execution": "verified"
                    if status == "completed"
                    else "needs_review"
                    if status == "needs_review"
                    else "awaiting_approval",
                    "verification": "completed"
                    if status == "completed"
                    else "needs_review"
                    if status == "needs_review"
                    else "pending",
                    "reporting": "completed" if status == "completed" else "pending",
                }
            )
            context.step_status_json = steps
            context.disposition_status = {
                "awaiting_approval": "响应计划等待独立工具审批，尚未执行",
                "needs_review": "执行或验证未能安全完成，需要人工复核",
                "completed": "所有必需动作已经执行后验证",
            }[status]
            context.updated_at = now
        reporting = session.execute(
            select(AgentExecutionRow)
            .where(
                AgentExecutionRow.run_id == plan.run_id,
                AgentExecutionRow.tenant_id == plan.tenant_id,
                AgentExecutionRow.role == AgentRole.REPORTING.value,
            )
            .order_by(AgentExecutionRow.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if reporting is not None and status in {"needs_review", "completed"}:
            reporting.summary = (
                "闭环事实：所有必需计划动作均已有执行后验证记录。"
                if status == "completed"
                else "闭环事实：执行或验证存在失败、未知或不一致，未报告处置成功。"
            )
            reporting.termination_reason = "completed" if status == "completed" else "needs_review"

    def _react_plan(
        self,
        session: Session,
        plan: ResponsePlanRow,
        revision: ResponsePlanRevisionRow,
        actions: list[ResponsePlanActionRow],
        loop: ReactLoop,
    ) -> tuple[PlanRevision, dict[UUID, ProposedAction]]:
        call_rows = {
            row.plan_action_id: _call(row)
            for row in session.scalars(
                select(TrustedToolCallRow).where(
                    TrustedToolCallRow.tenant_id == plan.tenant_id,
                    TrustedToolCallRow.plan_revision_id == revision.id,
                    TrustedToolCallRow.plan_action_id.is_not(None),
                )
            )
        }
        action_map = {
            UUID(action.id): ProposedAction(
                UUID(action.id),
                f"proposed:{action.tool_name}",
                action.target_identifier,
                dict(action.expected_state_json),
                call_rows[action.id].request.evidence,
            )
            for action in actions
        }
        current = PlanRevision(
            UUID(revision.id),
            loop.id,
            loop.case_id,
            loop.run_id,
            revision.revision,
            revision.parent_revision,
            (),
            (),
            tuple(action_map.values()),
            FailureCategory.PLAN_ACCEPTED,
            _utc(revision.created_at),
        )
        return current, action_map

    @staticmethod
    def _observation(
        loop: ReactLoop,
        call: TrustedToolCall,
        verification: ToolVerification | None,
        now: datetime,
    ) -> ReactObservation:
        reason = (
            "verification_verified"
            if verification is not None and verification.outcome is VerificationOutcome.VERIFIED
            else call.reason.value
            if call.reason is not None
            else call.status.value
        )
        return ReactObservation(
            uuid5(
                NAMESPACE_URL,
                f"shieldchain:safety-observation:{call.request.id}:{call.revision}:"
                f"{verification.id if verification else 'none'}",
            ),
            loop.id,
            loop.case_id,
            loop.run_id,
            loop.revision + 1,
            ObservationSource.TOOL_VERIFICATION
            if verification is not None
            else ObservationSource.TOOL_CALL,
            call.status.value,
            reason,
            call.request.evidence,
            now,
            tool_call_id=call.request.id,
            verification_id=verification.id if verification else None,
        )

    @staticmethod
    def _plan(
        session: Session,
        tenant_id: UUID,
        plan_id: UUID,
    ) -> tuple[ResponsePlanRow, ResponsePlanRevisionRow, list[ResponsePlanActionRow]]:
        plan = session.execute(
            select(ResponsePlanRow)
            .where(
                ResponsePlanRow.id == str(plan_id),
                ResponsePlanRow.tenant_id == str(tenant_id),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if plan is None or plan.case_id is None:
            raise SafetyLoopConflict("actionable response plan not found in tenant")
        revision = session.execute(
            select(ResponsePlanRevisionRow).where(
                ResponsePlanRevisionRow.plan_id == plan.id,
                ResponsePlanRevisionRow.revision == plan.current_revision,
                ResponsePlanRevisionRow.reason_code.is_(None),
            )
        ).scalar_one_or_none()
        if revision is None:
            if plan.status in {"completed", "needs_review"}:
                revision = session.execute(
                    select(ResponsePlanRevisionRow)
                    .where(ResponsePlanRevisionRow.plan_id == plan.id)
                    .order_by(ResponsePlanRevisionRow.revision.desc())
                    .limit(1)
                ).scalar_one()
                return plan, revision, []
            raise SafetyLoopConflict("current response plan revision is invalid")
        actions = list(
            session.scalars(
                select(ResponsePlanActionRow)
                .where(ResponsePlanActionRow.plan_revision_id == revision.id)
                .order_by(ResponsePlanActionRow.sequence)
            )
        )
        return plan, revision, actions

    @staticmethod
    def _linked_calls(
        session: Session,
        plan: ResponsePlanRow,
        revision: ResponsePlanRevisionRow,
    ) -> list[TrustedToolCallRow]:
        return list(
            session.scalars(
                select(TrustedToolCallRow)
                .join(
                    ResponsePlanActionRow,
                    ResponsePlanActionRow.id == TrustedToolCallRow.plan_action_id,
                )
                .where(
                    TrustedToolCallRow.tenant_id == plan.tenant_id,
                    TrustedToolCallRow.plan_revision_id == revision.id,
                )
                .order_by(ResponsePlanActionRow.sequence)
            )
        )

    @staticmethod
    def _latest_policy(session: Session, tenant_id: UUID, call_id: UUID) -> PolicyDecision | None:
        row = session.execute(
            select(ToolPolicyDecisionRow)
            .where(
                ToolPolicyDecisionRow.tenant_id == str(tenant_id),
                ToolPolicyDecisionRow.tool_call_id == str(call_id),
            )
            .order_by(ToolPolicyDecisionRow.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            return None
        return PolicyDecision(
            call_id,
            PolicyOutcome(row.outcome),
            PolicyReason(row.reason),
            row.policy_version,
            ToolRisk(row.assessed_risk),
            _utc(row.created_at),
            _utc(row.expires_at),
        )

    @staticmethod
    def _latest_attempt(
        session: Session, tenant_id: UUID, call_id: UUID
    ) -> ToolExecutionAttempt | None:
        row = session.execute(
            select(ToolExecutionAttemptRow)
            .where(
                ToolExecutionAttemptRow.tenant_id == str(tenant_id),
                ToolExecutionAttemptRow.tool_call_id == str(call_id),
            )
            .order_by(ToolExecutionAttemptRow.attempt_number.desc())
            .limit(1)
        ).scalar_one_or_none()
        return (
            ToolExecutionAttempt(
                UUID(row.id),
                call_id,
                row.attempt_number,
                ExecutionOutcome(row.outcome),
                row.result_summary,
                row.error_category,
                _utc(row.started_at),
                _utc(row.completed_at),
            )
            if row
            else None
        )

    @staticmethod
    def _latest_verification(
        session: Session, tenant_id: UUID, call_id: UUID
    ) -> ToolVerification | None:
        row = session.execute(
            select(ToolVerificationRow)
            .where(
                ToolVerificationRow.tenant_id == str(tenant_id),
                ToolVerificationRow.tool_call_id == str(call_id),
            )
            .order_by(ToolVerificationRow.verified_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if row is None:
            return None
        call = session.get(TrustedToolCallRow, str(call_id))
        assert call is not None
        return ToolVerification(
            UUID(row.id),
            call_id,
            VerificationOutcome(row.outcome),
            dict(row.observed_state_json),
            _call(call).request.evidence,
            PolicyReason(row.reason) if row.reason else None,
            _utc(row.verified_at),
        )

    @staticmethod
    def _verified(call: TrustedToolCall, verification: ToolVerification | None) -> bool:
        return (
            call.status is TrustedToolCallStatus.SUCCEEDED
            and verification is not None
            and verification.outcome is VerificationOutcome.VERIFIED
        )

    @staticmethod
    def _observation_exists(
        session: Session,
        call_id: UUID,
        verification_id: UUID,
    ) -> bool:
        return (
            session.scalar(
                select(func.count())
                .select_from(ReactObservationRow)
                .where(
                    ReactObservationRow.tool_call_id == str(call_id),
                    ReactObservationRow.verification_id == str(verification_id),
                )
            )
            or 0
        ) > 0

    @staticmethod
    def _event(
        session: Session,
        plan: ResponsePlanRow,
        event_type: str,
        reason_code: str | None,
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
                public_summary={
                    "plan_verified_completed": "所有必需计划动作已通过执行后验证。",
                    "plan_replanning_stopped": "闭环已停止自动化并生成需人工复核的新 revision。",
                    "safety_loop_stopped": "闭环因安全边界停止并转人工复核。",
                }.get(event_type, "响应安全闭环状态已更新。"),
                actor_subject_id=None,
                created_at=now,
            )
        )

    @staticmethod
    def _result(
        plan: ResponsePlanRow,
        loop: ReactLoop,
        processed: tuple[UUID, ...],
        reason: str,
    ) -> SafetyLoopResult:
        return SafetyLoopResult(UUID(plan.id), plan.status, loop.id, loop.status, processed, reason)


def _failure_category(
    call: TrustedToolCall,
    verification: ToolVerification | None,
) -> FailureCategory:
    if verification is not None:
        if verification.outcome is VerificationOutcome.FAILED:
            return FailureCategory.VERIFICATION_FAILED
        if verification.outcome is VerificationOutcome.INCONCLUSIVE:
            return FailureCategory.VERIFICATION_INCONCLUSIVE
    if call.reason is PolicyReason.APPROVAL_REJECTED:
        return FailureCategory.APPROVAL_REJECTED
    if call.reason is PolicyReason.EXECUTION_OUTCOME_UNKNOWN:
        return FailureCategory.EXECUTION_OUTCOME_UNKNOWN
    if call.reason is PolicyReason.EXECUTION_FAILED:
        return FailureCategory.EXECUTION_FAILED
    return FailureCategory.UNCLASSIFIED_FAILURE


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("safety loop time must be aware UTC")


def _budget_allows_dispatch(loop: ReactLoop, now: datetime) -> bool:
    budget = loop.budget
    elapsed = (now - loop.started_at).total_seconds()
    return all(
        used < limit
        for used, limit in (
            (budget.steps_used, budget.step_limit),
            (budget.loops_used, budget.loop_limit),
            (max(budget.time_used_seconds, elapsed), budget.time_limit_seconds),
            (budget.tokens_used, budget.token_limit),
            (budget.cost_used_usd, budget.cost_limit_usd),
            (budget.tool_calls_used, budget.tool_call_limit),
        )
    )
