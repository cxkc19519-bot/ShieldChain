"""Offline Phase 6 bounded ReAct loop and human-takeover smoke harness."""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from shieldchain.agents.domain import AgentRole, BudgetSnapshot, EvidenceReference
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.react.api_service import ReactApiService
from shieldchain.react.budget import ReactBudgetSupervisor, ReactConsumption
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
from shieldchain.react.repositories import SqlAlchemyReactRepository
from shieldchain.react.service import ControlledReactService, SqlAlchemyReactStepStore
from shieldchain.tools.domain import (
    PolicyReason,
    ToolTargetType,
    ToolVerification,
    TrustedToolCall,
    TrustedToolCallStatus,
    TrustedToolRequest,
    VerificationOutcome,
)
from shieldchain.tools.gateway import TrustedToolGateway
from shieldchain.tools.gateway_store import SqlAlchemyGatewayStore
from shieldchain.tools.policy import ToolExecutionMode, ToolPolicyContext
from shieldchain.tools.registry import default_tool_registry
from shieldchain.tools.simulation import OfflineSimulationAdapter

NOW = datetime(2026, 7, 23, 23, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
ACTOR = UUID("00000000-0000-4000-8000-000000000002")
CASE, RUN, SIMULATION, EVIDENCE, LOOP = (UUID(int=value) for value in range(8101, 8106))
SHA = "f" * 64


class MemoryStore:
    def commit_step(self, *, tenant_id, bundle):
        if tenant_id != TENANT:
            raise RuntimeError("cross-tenant smoke commit")
        return bundle.changed


def budget(**changes) -> BudgetSnapshot:
    values = {
        "step_limit": 10,
        "steps_used": 0,
        "loop_limit": 4,
        "loops_used": 0,
        "time_limit_seconds": 60,
        "time_used_seconds": 0,
        "token_limit": 1000,
        "tokens_used": 0,
        "cost_limit_usd": 1,
        "cost_used_usd": 0,
        "tool_call_limit": 5,
        "tool_calls_used": 0,
    }
    values.update(changes)
    return BudgetSnapshot(**values)


def reference() -> EvidenceReference:
    return EvidenceReference(EVIDENCE, CASE, "siem:phase6", NOW, SHA)


def action(number: int, name: str, target: str) -> ProposedAction:
    expected = {
        "block_ip": {"firewall_status": "blocked"},
        "isolate_endpoint": {"isolation_status": "isolated"},
        "disable_account": {"account_status": "disabled"},
    }[name]
    return ProposedAction(
        UUID(int=number), f"proposed:{name}", target, expected, (reference(),)
    )


def loop(number: int, *, value: BudgetSnapshot | None = None) -> ReactLoop:
    return ReactLoop(
        UUID(int=number),
        CASE,
        RUN,
        ReactLoopStatus.RUNNING,
        0,
        value or budget(),
        (),
        NOW,
        NOW,
    )


def plan(value: ReactLoop, failed: ProposedAction) -> PlanRevision:
    return PlanRevision(
        UUID(int=value.id.int + 100),
        value.id,
        CASE,
        RUN,
        0,
        None,
        (),
        (),
        (failed,),
        FailureCategory.VERIFICATION_FAILED,
        NOW,
    )


def failed_call(number: int, key: str, status, reason) -> TrustedToolCall:
    request = TrustedToolRequest(
        UUID(int=number),
        CASE,
        RUN,
        UUID(int=number + 1),
        key,
        AgentRole.RESPONSE_PLANNING,
        "block_ip",
        "1",
        {"target_ip": "203.0.113.8", "rule_ttl_seconds": 3600},
        {"firewall_status": "blocked"},
        "Remove exact scoped rule.",
        (reference(),),
        NOW,
    )
    return TrustedToolCall(request, status, 3, reason, NOW)


def observed_failure(value: ReactLoop, call: TrustedToolCall, *, verification=None):
    source = (
        ObservationSource.TOOL_VERIFICATION
        if verification is not None
        else ObservationSource.TOOL_CALL
    )
    observation = ReactObservation(
        UUID(int=call.request.id.int + 10),
        value.id,
        CASE,
        RUN,
        1,
        source,
        call.status.value,
        call.reason.value,
        (reference(),),
        NOW,
        tool_call_id=call.request.id,
        verification_id=verification.id if verification else None,
    )
    return TrustedFailureInput(observation, call=call, verification=verification)


def seed(session: Session) -> None:
    session.add(
        SimulationInstanceRow(
            id=str(SIMULATION),
            scenario_key="phase6-smoke",
            generation=1,
            environment="simulation",
            connection_status="active",
            firewall_status="not_blocked",
            fail_block_consumed=False,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    session.add(
        IncidentRow(
            id=str(CASE),
            tenant_id=str(TENANT),
            external_id="INC-PHASE6",
            simulation_instance_id=str(SIMULATION),
            alert_id="ALT-PHASE6",
            alert_status="open",
            endpoint="endpoint-42",
            username="user-42",
            source_ip="10.0.0.5",
            remote_ip="203.0.113.8",
            remote_port=443,
            process_name="powershell.exe",
            parent_process_name="outlook.exe",
            command_summary="fixed simulation",
            threat_label="phishing",
            created_at=NOW,
        )
    )
    session.flush()
    session.add(
        InvestigationRunRow(
            id=str(RUN),
            tenant_id=str(TENANT),
            incident_id=str(CASE),
            simulation_instance_id=str(SIMULATION),
            status="action_planned",
            mode="normal",
            created_at=NOW,
            updated_at=NOW,
        )
    )
    session.flush()
    session.add(
        EvidenceRecordRow(
            id=str(EVIDENCE),
            run_id=str(RUN),
            evidence_type="network",
            source="siem",
            observed_at=NOW,
            summary="confirmed malicious target",
            raw_reference="siem:phase6",
            integrity_sha256=SHA,
            confidence=1,
            confirmed=True,
            payload_json={},
            created_at=NOW,
        )
    )


def policy() -> ToolPolicyContext:
    registry = default_tool_registry()
    return ToolPolicyContext(
        tenant_id=TENANT,
        principal_id=ACTOR,
        case_id=CASE,
        run_id=RUN,
        role=AgentRole.RESPONSE_PLANNING,
        mode=ToolExecutionMode.SIMULATION,
        automation_enabled=True,
        emergency_stop_active=False,
        allowed_tools=frozenset(
            item.definition.identity for item in registry.registrations
        ),
        allowed_targets={ToolTargetType.ENDPOINT: frozenset({"endpoint-42"})},
        confirmed_evidence_ids=frozenset({EVIDENCE}),
        tool_calls_used=0,
        tool_call_limit=5,
        calls_in_window=0,
        rate_limit=5,
        simulation_auto_approve_critical=False,
        now=NOW,
    )


def step_scenario(
    label: str, value: ReactLoop, current: PlanRevision, failure, failed, candidates
):
    result = ControlledReactService().step(
        tenant_id=TENANT,
        loop=value,
        current_plan=current,
        failure=failure,
        failed_action=failed,
        failed_tool_name="block_ip",
        candidates=candidates,
        consumption=ReactConsumption(tool_calls=1),
        registry=default_tool_registry(),
        now=NOW,
        store=MemoryStore(),
    )
    print(label)
    return result


def run(database: Path) -> None:
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    factory = sessionmaker(bind=engine)
    failed = action(8201, "block_ip", "203.0.113.8")
    candidate = action(8202, "isolate_endpoint", "endpoint-42")
    main_loop = loop(LOOP.int)
    current_plan = plan(main_loop, failed)
    failed_tool = failed_call(
        8210,
        "phase6:verified-replan",
        TrustedToolCallStatus.FAILED,
        PolicyReason.VERIFICATION_FAILED,
    )
    verification = ToolVerification(
        UUID(int=8212),
        failed_tool.request.id,
        VerificationOutcome.FAILED,
        {"firewall_status": "not_blocked"},
        (reference(),),
        PolicyReason.VERIFICATION_FAILED,
        NOW,
    )
    with factory.begin() as session:
        seed(session)
        SqlAlchemyReactRepository().create(session, tenant_id=TENANT, loop=main_loop)
        replanned = ControlledReactService().step(
            tenant_id=TENANT,
            loop=main_loop,
            current_plan=current_plan,
            failure=observed_failure(main_loop, failed_tool, verification=verification),
            failed_action=failed,
            failed_tool_name="block_ip",
            candidates=(candidate,),
            consumption=ReactConsumption(tool_calls=1),
            registry=default_tool_registry(),
            now=NOW,
            store=SqlAlchemyReactStepStore(session),
        )
        if (
            replanned.decision.decision is not ReactDecision.REPLAN
            or replanned.plan is None
        ):
            raise RuntimeError(
                "verification failure did not create a deterministic replan"
            )
        selected = replanned.plan.added_actions[0]
        request = TrustedToolRequest(
            UUID(int=8220),
            CASE,
            RUN,
            selected.id,
            "phase6:replanned-tool",
            AgentRole.RESPONSE_PLANNING,
            selected.action.removeprefix("proposed:"),
            "1",
            {
                "endpoint_id": selected.target,
                "reason_code": "containment_required",
            },
            dict(selected.expected_state),
            "Release endpoint isolation after review.",
            selected.references,
            NOW,
        )
        bound = default_tool_registry().bind(request)
        outcome = TrustedToolGateway().submit(
            bound=bound,
            context=policy(),
            store=SqlAlchemyGatewayStore(session),
            adapter=OfflineSimulationAdapter(
                initialized_at=NOW,
                firewall_targets=frozenset({"203.0.113.8"}),
                endpoint_targets=frozenset({"endpoint-42"}),
                account_targets=frozenset({"user-42"}),
            ),
            request_id="phase6-replanned-tool",
        )
        if (
            outcome.call.status is not TrustedToolCallStatus.SUCCEEDED
            or outcome.verification is None
        ):
            raise RuntimeError(
                "replanned proposed action did not pass trusted verification"
            )

    unknown_loop = loop(8301)
    unknown_call = failed_call(
        8310,
        "phase6:unknown-query",
        TrustedToolCallStatus.NEEDS_REVIEW,
        PolicyReason.EXECUTION_OUTCOME_UNKNOWN,
    )
    unknown = step_scenario(
        "phase6:unknown-query",
        unknown_loop,
        plan(unknown_loop, failed),
        observed_failure(unknown_loop, unknown_call),
        failed,
        (),
    )
    if unknown.decision.decision is not ReactDecision.QUERY_STATUS:
        raise RuntimeError("unknown mutating outcome did not query registered state")

    looped = loop(8401)
    loop_call = failed_call(
        8410,
        "phase6:loop-detected",
        TrustedToolCallStatus.FAILED,
        PolicyReason.EXECUTION_FAILED,
    )
    loop_failure = observed_failure(looped, loop_call)
    loop_plan = plan(looped, failed)
    fingerprint = ReactBudgetSupervisor.fingerprint(
        observation=loop_failure.observation, plan=loop_plan
    )
    looped = replace(looped, observation_fingerprints=(fingerprint,))
    detected = step_scenario(
        "phase6:loop-detected", looped, loop_plan, loop_failure, failed, (candidate,)
    )
    if detected.loop.status is not ReactLoopStatus.AWAITING_HUMAN:
        raise RuntimeError("loop detection did not stop for human review")

    exhausted = loop(8501, value=budget(loop_limit=1, loops_used=1))
    budget_call = failed_call(
        8510,
        "phase6:budget-exhausted",
        TrustedToolCallStatus.FAILED,
        PolicyReason.EXECUTION_FAILED,
    )
    stopped = step_scenario(
        "phase6:budget-exhausted",
        exhausted,
        plan(exhausted, failed),
        observed_failure(exhausted, budget_call),
        failed,
        (candidate,),
    )
    if stopped.loop.status is not ReactLoopStatus.AWAITING_HUMAN:
        raise RuntimeError("budget exhaustion did not stop for human review")

    rejected_loop = loop(8601)
    rejected_call = failed_call(
        8610,
        "phase6:approval-rejected",
        TrustedToolCallStatus.REJECTED,
        PolicyReason.APPROVAL_REJECTED,
    )
    rejected = step_scenario(
        "phase6:approval-rejected",
        rejected_loop,
        plan(rejected_loop, failed),
        observed_failure(rejected_loop, rejected_call),
        failed,
        (candidate,),
    )
    if rejected.decision.decision is not ReactDecision.MANUAL_REVIEW:
        raise RuntimeError("approval rejection did not stop for human review")

    api = ReactApiService(factory)
    taken = api.control(
        tenant_id=TENANT,
        actor_id=ACTOR,
        loop_id=LOOP,
        action="takeover",
        reason="operator takeover",
        request_id="phase6-takeover",
        now=NOW + timedelta(seconds=1),
    )
    resumed = api.control(
        tenant_id=TENANT,
        actor_id=ACTOR,
        loop_id=LOOP,
        action="resume",
        reason="operator takeover complete",
        request_id="phase6-resume",
        now=NOW + timedelta(seconds=2),
    )
    if taken.status != "awaiting_human" or resumed.status != "awaiting_execution":
        raise RuntimeError(
            "human takeover did not restore the trusted execution boundary"
        )
    trace = api.trajectory(tenant_id=TENANT, run_id=RUN).model_dump_json()
    for forbidden in (
        "tenant_id",
        "actor_subject_id",
        "reason_summary",
        "request_id",
        "adapter_result",
        "chain_of_thought",
        "raw_prompt",
    ):
        if forbidden in trace:
            raise RuntimeError(
                f"public ReAct trajectory leaked forbidden field: {forbidden}"
            )
    engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    run(parser.parse_args().database)
    print("Phase 6 offline bounded ReAct smoke passed.")
