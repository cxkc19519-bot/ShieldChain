from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import func, select

from shieldchain.agents.persistence import AgentRunRow, CaseContextRow
from shieldchain.core.config import Settings
from shieldchain.db.base import Base
from shieldchain.db.session import create_engine_from_url, create_session_factory
from shieldchain.incidents.persistence import (
    EvidenceRecordRow,
    IncidentRow,
    InvestigationRunRow,
    SimulationInstanceRow,
)
from shieldchain.operations.response_plan_agent import OperationsResponsePlanAgent
from shieldchain.response_planning.compiler import ResponsePlanCompiler
from shieldchain.response_planning.persistence import (
    ResponsePlanActionRow,
    ResponsePlanRevisionRow,
    ResponsePlanRow,
)
from shieldchain.tools.persistence import TrustedToolCallRow
from shieldchain.wazuh.persistence import WazuhCaseRunRow

NOW = datetime(2026, 8, 23, 14, tzinfo=UTC)
TENANT = UUID("00000000-0000-4000-8000-000000000001")
RUN = UUID("00000000-0000-4000-8000-000000000201")
CASE_RUN = UUID("00000000-0000-4000-8000-000000000206")
WAZUH_CASE = UUID("00000000-0000-4000-8000-000000000207")
WAZUH_ALERT = UUID("00000000-0000-4000-8000-000000000208")
FOREIGN_RUN = UUID("00000000-0000-4000-8000-000000000202")
FOREIGN_CASE = UUID("00000000-0000-4000-8000-000000000203")
FOREIGN_EVIDENCE = UUID("00000000-0000-4000-8000-000000000204")
SIMULATION = UUID("00000000-0000-4000-8000-000000000205")


@pytest.fixture
def planner_context(tmp_path: Path):
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'operations-plan.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        session.add(
            AgentRunRow(
                id=str(RUN),
                tenant_id=str(TENANT),
                principal_id=str(UUID(int=2)),
                run_kind="operations_report",
                status="running",
                goal="Generate a bounded operations report.",
                catalog_revision="test-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            AgentRunRow(
                id=str(CASE_RUN),
                tenant_id=str(TENANT),
                principal_id=str(UUID(int=2)),
                run_kind="operations_report",
                status="running",
                goal="Generate a bounded Wazuh case report.",
                catalog_revision="test-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            CaseContextRow(
                id=str(WAZUH_CASE),
                run_id=str(CASE_RUN),
                tenant_id=str(TENANT),
                revision=0,
                phase="response_planning",
                user_goal="Investigate the Wazuh review case.",
                hypotheses_json=[],
                risks_json=[],
                plan_json=[],
                step_status_json={},
                disposition_status="pending",
                budget_json={},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.add(
            WazuhCaseRunRow(
                run_id=str(CASE_RUN),
                case_id=str(WAZUH_CASE),
                tenant_id=str(TENANT),
                alert_id=str(WAZUH_ALERT),
                created_at=NOW,
            )
        )
        session.add(
            SimulationInstanceRow(
                id=str(SIMULATION),
                scenario_key="foreign-plan-evidence",
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
                id=str(FOREIGN_CASE),
                tenant_id=str(TENANT),
                external_id="INC-FOREIGN",
                simulation_instance_id=str(SIMULATION),
                alert_id="ALT-FOREIGN",
                alert_status="open",
                endpoint="endpoint-foreign",
                username="foreign-user",
                source_ip="203.0.113.77",
                remote_ip="203.0.113.78",
                remote_port=443,
                process_name="foreign-agent",
                parent_process_name="system",
                command_summary="public summary",
                threat_label="confirmed",
                created_at=NOW,
            )
        )
        session.add(
            AgentRunRow(
                id=str(FOREIGN_RUN),
                tenant_id=str(TENANT),
                principal_id=str(UUID(int=2)),
                run_kind="incident_investigation",
                status="running",
                goal="Foreign investigation.",
                catalog_revision="test-v1",
                revision=0,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.flush()
        session.add(
            InvestigationRunRow(
                id=str(FOREIGN_RUN),
                tenant_id=str(TENANT),
                incident_id=str(FOREIGN_CASE),
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
                id=str(FOREIGN_EVIDENCE),
                run_id=str(FOREIGN_RUN),
                evidence_type="network",
                source="siem",
                observed_at=NOW,
                summary="Evidence belonging to another run.",
                raw_reference="siem:foreign:1",
                integrity_sha256="d" * 64,
                confidence=1.0,
                confirmed=True,
                payload_json={"target_ip": "203.0.113.77"},
                created_at=NOW,
            )
        )
    compiler = ResponsePlanCompiler(factory)
    planner = OperationsResponsePlanAgent(
        Settings(_env_file=None, deepseek_api_key="test-key"),
        compiler,
        factory,
        tenant_id=TENANT,
    )
    yield planner, factory
    engine.dispose()


def _candidate(summary: str = "建议人工复核当前报告线索。") -> dict[str, object]:
    return {
        "action": "propose_response_plan",
        "public_summary": summary,
        "assumptions": [],
        "actions": [],
        "stop_conditions": ["缺少案件级确认事实"],
        "operator_notes": ["本计划未执行任何动作"],
    }


def _generate(
    planner: OperationsResponsePlanAgent,
    *,
    run_id: UUID = RUN,
    case_id: UUID | None = None,
):
    return asyncio.run(
        planner.generate(
            run_id=run_id,
            public_handoffs=[{"role": "threat_investigation", "summary": "存在待复核线索。"}],
            observation_summaries="告警工具：发现一条待复核告警。",
            now=NOW,
            case_id=case_id,
        )
    )


def test_valid_model_candidate_creates_advisory_plan_without_execution(planner_context) -> None:
    planner, factory = planner_context
    captured: dict[str, str] = {}

    async def chat(system: str, user: str):
        captured["system"] = system
        captured["user"] = user
        return SimpleNamespace(
            content=json.dumps(_candidate(), ensure_ascii=False), model="test-model"
        )

    planner._chat = chat  # type: ignore[method-assign]
    result = _generate(planner)

    assert result.used_fallback is False
    assert result.reference.generation_status == "model_compiled"
    assert result.reference.status == "completed_advisory"
    assert result.reference.action_count == 0
    assert result.reference.execution_status == "not_executed"
    assert result.reference.public_summary == "建议人工复核当前报告线索。"
    prompt = json.loads(captured["user"])
    assert prompt["allowed_actions"] == []
    assert prompt["case_bound"] is False
    assert "response_plan_schema" in prompt
    assert "tenant_id" not in captured["user"]
    assert "principal_id" not in captured["user"]
    assert "不得输出思维链" not in captured["user"]
    assert "只输出一个" in captured["system"]
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ResponsePlanRow)) == 1
        assert session.scalar(select(func.count()).select_from(ResponsePlanActionRow)) == 0
        assert session.scalar(select(func.count()).select_from(TrustedToolCallRow)) == 0


def test_case_without_actionable_target_creates_advisory_without_fallback(
    planner_context,
) -> None:
    planner, factory = planner_context

    async def chat(_system: str, _user: str):
        return SimpleNamespace(
            content=json.dumps(
                _candidate("案件缺少可安全处置的目标，建议人工补充证据。"),
                ensure_ascii=False,
            ),
            model="test-model",
        )

    planner._chat = chat  # type: ignore[method-assign]
    result = _generate(planner, run_id=CASE_RUN, case_id=WAZUH_CASE)

    assert result.used_fallback is False
    assert result.reference.generation_status == "model_compiled"
    assert result.reference.status == "completed_advisory"
    assert result.reference.action_count == 0
    assert result.reference.execution_status == "not_executed"
    with factory() as session:
        plan = session.get(ResponsePlanRow, str(result.reference.plan_id))
        assert plan is not None
        assert plan.run_id == str(CASE_RUN)
        assert plan.case_id == str(WAZUH_CASE)


@pytest.mark.parametrize(
    ("raw_candidate", "reason_code"),
    [
        ("not-json SECRET_MARKER", "candidate_invalid"),
        (
            json.dumps(
                {
                    **_candidate(),
                    "actions": [
                        {
                            "client_action_id": "step-1",
                            "tool": "run_shell",
                            "target_reference_id": str(FOREIGN_EVIDENCE),
                            "arguments": {},
                            "expected_state": {"done": True},
                            "depends_on": [],
                            "public_reason": "invalid tool",
                            "verification": None,
                            "rollback_note": "人工复核。",
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            "tool_not_registered",
        ),
        (
            json.dumps(
                {
                    **_candidate(),
                    "assumptions": [
                        {
                            "statement": "错误引用其他运行证据",
                            "evidence_ids": [str(FOREIGN_EVIDENCE)],
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            "evidence_invalid",
        ),
    ],
)
def test_invalid_model_candidate_is_recorded_then_replaced_by_safe_advisory(
    planner_context, raw_candidate: str, reason_code: str
) -> None:
    planner, factory = planner_context

    async def chat(_system: str, _user: str):
        return SimpleNamespace(content=raw_candidate, model="test-model")

    planner._chat = chat  # type: ignore[method-assign]
    result = _generate(planner)

    assert result.used_fallback is True
    assert result.reference.generation_status == "deterministic_fallback"
    assert result.reference.fallback_reason_code == reason_code
    assert result.reference.revision == 1
    assert result.reference.status == "completed_advisory"
    with factory() as session:
        revisions = list(
            session.scalars(
                select(ResponsePlanRevisionRow).order_by(ResponsePlanRevisionRow.revision)
            )
        )
        assert [item.reason_code for item in revisions] == [reason_code, None]
        assert "SECRET_MARKER" not in repr(revisions)
        assert session.scalar(select(func.count()).select_from(ResponsePlanActionRow)) == 0
        assert session.scalar(select(func.count()).select_from(TrustedToolCallRow)) == 0


def test_model_unavailable_uses_one_deterministic_advisory_revision(planner_context) -> None:
    _planner, factory = planner_context
    planner = OperationsResponsePlanAgent(
        Settings(_env_file=None),
        ResponsePlanCompiler(factory),
        factory,
        tenant_id=TENANT,
    )

    result = _generate(planner)

    assert result.used_fallback is True
    assert result.reference.fallback_reason_code == "model_unavailable"
    assert result.reference.revision == 0
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(ResponsePlanRevisionRow)) == 1


def test_wazuh_endpoint_allowlist_is_server_owned(planner_context) -> None:
    planner, _factory = planner_context
    assert planner._actionable_endpoint("002") is True
    assert planner._actionable_endpoint("001") is False
    assert planner._actionable_endpoint(None) is False
