from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, select

from shieldchain.agents.persistence import AgentRunRow, CaseContextRow
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.response_planning.compiler import (
    ResponsePlanCompileContext,
    ResponsePlanCompiler,
    ResponsePlanScopeError,
)
from shieldchain.response_planning.domain import ResponsePlanStatus
from shieldchain.response_planning.persistence import (
    ResponsePlanActionRow,
    ResponsePlanEventRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000099")
CASE = UUID("00000000-0000-4000-8000-000000000101")
RUN = UUID("00000000-0000-4000-8000-000000000102")
SIMULATION = UUID("00000000-0000-4000-8000-000000000103")
EVIDENCE = UUID("00000000-0000-4000-8000-000000000104")


@pytest.fixture
def compiler_context(tmp_path: Path):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'response-plans.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        session.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="response-plan",
                generation=1,
                environment="simulation",
                connection_status="active",
                firewall_status="not_blocked",
                fail_block_consumed=False,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            IncidentRow(
                id=str(CASE),
                tenant_id=str(TENANT),
                external_id="INC-PLAN",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALT-PLAN",
                alert_status="open",
                endpoint="endpoint-7",
                username="analyst",
                source_ip="203.0.113.8",
                remote_ip="203.0.113.9",
                remote_port=443,
                process_name="agent",
                parent_process_name="system",
                command_summary="public summary",
                threat_label="confirmed",
                created_at=NOW,
            )
        )
        session.flush()
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(UUID(int=2)),
                run_kind="incident_investigation",
                status="running",
                goal="Compile a response plan.",
                catalog_revision="trusted-tools-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
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
            CaseContextRow(
                id=str(CASE),
                run_id=str(RUN),
                tenant_id=str(TENANT),
                revision=0,
                phase="response_planning",
                user_goal="Contain the confirmed source.",
                hypotheses_json=[],
                risks_json=[],
                plan_json=[],
                step_status_json={},
                disposition_status="open",
                budget_json={},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            EvidenceRecordRow(
                id=str(EVIDENCE),
                run_id=str(RUN),
                evidence_type="network",
                source="siem",
                observed_at=NOW,
                summary="Confirmed malicious source.",
                raw_reference="siem:event:1",
                integrity_sha256="c" * 64,
                confidence=1.0,
                confirmed=True,
                payload_json={"target_ip": "203.0.113.8"},
                created_at=NOW,
            )
        )
    yield ResponsePlanCompiler(factory), factory
    engine.dispose()


def _context(*, tenant_id: UUID = TENANT) -> ResponsePlanCompileContext:
    return ResponsePlanCompileContext(
        tenant_id=tenant_id,
        run_id=RUN,
        case_id=CASE,
        model_id="test-model",
        prompt_policy_version="response-plan-v1",
        now=NOW,
    )


def _candidate(*, tool: str = "block_ip") -> str:
    return json.dumps(
        {
            "action": "propose_response_plan",
            "public_summary": "建议处置已确认恶意来源。",
            "assumptions": [{"statement": "来源已确认", "evidence_ids": [str(EVIDENCE)]}],
            "actions": [
                {
                    "client_action_id": "step-1",
                    "tool": tool,
                    "target_reference_id": str(EVIDENCE),
                    "arguments": {"rule_ttl_seconds": 600},
                    "expected_state": {"firewall_status": "blocked"},
                    "depends_on": [],
                    "public_reason": "减少后续恶意连接。",
                    "verification": {
                        "tool": "query_firewall_state",
                        "expected_state": {"firewall_status": "blocked"},
                    },
                    "rollback_note": "由人工删除对应防火墙规则。",
                }
            ],
            "stop_conditions": ["证据冲突", "审批拒绝"],
            "operator_notes": ["计划建议不代表已经执行"],
        },
        ensure_ascii=False,
    )


def test_compiler_rebinds_evidence_target_tool_version_risk_and_approval(
    compiler_context,
) -> None:
    compiler, factory = compiler_context
    result = compiler.compile_json(_candidate(), _context())

    assert result.status is ResponsePlanStatus.PROPOSED
    assert result.revision == 0
    assert len(result.action_ids) == 1
    with factory() as session:
        plan = session.get(ResponsePlanRow, str(result.plan_id))
        revision = session.get(ResponsePlanRevisionRow, str(result.revision_id))
        action = session.get(ResponsePlanActionRow, str(result.action_ids[0]))
        event = session.scalar(select(ResponsePlanEventRow))
        assert plan is not None and plan.current_revision == 0
        assert revision is not None and revision.reason_code is None
        assert action is not None
        assert action.tool_name == "block_ip"
        assert action.tool_version == "1"
        assert action.target_identifier == "203.0.113.8"
        assert action.arguments_json == {"rule_ttl_seconds": 600, "target_ip": "203.0.113.8"}
        assert action.assessed_risk == "high"
        assert action.approval_required is True
        assert action.verification_tool == "query_firewall_state"
        assert event is not None and event.event_type == "plan_compiled"


def test_invalid_candidate_is_safely_recorded_without_raw_output_or_actions(
    compiler_context,
) -> None:
    compiler, factory = compiler_context
    raw = _candidate().replace('"arguments": {', '"risk":"low","arguments": {')
    result = compiler.compile_json(raw, _context())

    assert result.status is ResponsePlanStatus.NEEDS_REVIEW
    assert result.reason_code == "candidate_invalid"
    with factory() as session:
        revision = session.get(ResponsePlanRevisionRow, str(result.revision_id))
        assert revision is not None
        assert "risk" not in repr(revision.assumptions_json)
        assert session.scalar(select(func.count()).select_from(ResponsePlanActionRow)) == 0


def test_unknown_tool_and_unconfirmed_or_cross_tenant_evidence_fail_closed(
    compiler_context,
) -> None:
    compiler, factory = compiler_context
    unknown = compiler.compile_json(_candidate(tool="run_shell"), _context())
    assert unknown.reason_code == "tool_not_registered"

    with factory.begin() as session:
        session.get(EvidenceRecordRow, str(EVIDENCE)).confirmed = False
    invalid_evidence = compiler.compile_json(_candidate(), _context())
    assert invalid_evidence.reason_code == "evidence_invalid"

    with pytest.raises(ResponsePlanScopeError):
        compiler.compile_json(_candidate(), _context(tenant_id=OTHER))


def test_recompile_appends_revision_without_overwriting_history(compiler_context) -> None:
    compiler, factory = compiler_context
    first = compiler.compile_json(_candidate(), _context())
    second = compiler.compile_json(_candidate(), _context())

    assert second.plan_id == first.plan_id
    assert second.revision == 1
    with factory() as session:
        revisions = list(
            session.scalars(
                select(ResponsePlanRevisionRow).order_by(ResponsePlanRevisionRow.revision)
            )
        )
        assert [item.revision for item in revisions] == [0, 1]
        assert revisions[1].parent_revision == 0


def test_empty_action_candidate_compiles_as_advisory(compiler_context) -> None:
    compiler, _factory = compiler_context
    payload = json.loads(_candidate())
    payload["actions"] = []
    result = compiler.compile_json(json.dumps(payload, ensure_ascii=False), _context())
    assert result.status is ResponsePlanStatus.COMPLETED_ADVISORY
    assert result.action_ids == ()


def test_dependency_ids_are_rebound_and_any_invalid_action_rejects_atomically(
    compiler_context,
) -> None:
    compiler, factory = compiler_context
    payload = json.loads(_candidate())
    query = {
        "client_action_id": "step-1",
        "tool": "query_firewall_state",
        "target_reference_id": str(EVIDENCE),
        "arguments": {},
        "expected_state": {"firewall_status": "not_blocked"},
        "depends_on": [],
        "public_reason": "先读取可信当前状态。",
        "verification": None,
        "rollback_note": "只读动作无需回滚。",
    }
    change = payload["actions"][0]
    change["client_action_id"] = "step-2"
    change["depends_on"] = ["step-1"]
    payload["actions"] = [query, change]
    result = compiler.compile_json(json.dumps(payload, ensure_ascii=False), _context())

    with factory() as session:
        actions = list(
            session.scalars(
                select(ResponsePlanActionRow)
                .where(ResponsePlanActionRow.plan_revision_id == str(result.revision_id))
                .order_by(ResponsePlanActionRow.sequence)
            )
        )
        assert actions[1].depends_on_json == [actions[0].id]

    payload["actions"].append({**change, "client_action_id": "step-3", "tool": "run_shell"})
    rejected = compiler.compile_json(json.dumps(payload, ensure_ascii=False), _context())
    assert rejected.reason_code == "tool_not_registered"
    with factory() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(ResponsePlanActionRow)
                .where(ResponsePlanActionRow.plan_revision_id == str(rejected.revision_id))
            )
            == 0
        )


def test_stale_confirmed_evidence_is_rejected(compiler_context) -> None:
    compiler, factory = compiler_context
    with factory.begin() as session:
        session.get(EvidenceRecordRow, str(EVIDENCE)).observed_at = NOW.replace(year=2025)
    result = compiler.compile_json(_candidate(), _context())
    assert result.reason_code == "evidence_stale"
