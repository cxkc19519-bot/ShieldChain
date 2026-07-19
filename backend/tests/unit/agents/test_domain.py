import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType
from uuid import uuid4

import pytest

from shieldchain.agents.domain import (
    AgentOutput,
    AgentRole,
    AlertTriagePrivateContext,
    BudgetSnapshot,
    CasePhase,
    ConfirmedFact,
    EvidenceReference,
    HandoffPacket,
    Hypothesis,
    KnowledgeReference,
    ReferenceKind,
    ResponsePlanningPrivateContext,
    Risk,
    SharedCaseContext,
    TerminationReason,
)

NOW = datetime(2026, 7, 20, 1, 2, 3, tzinfo=UTC)


def evidence_reference():
    return EvidenceReference(
        id=uuid4(),
        case_id=uuid4(),
        source_id="edr:event:42",
        observed_at=NOW,
        integrity_sha256="a" * 64,
    )


def budget() -> BudgetSnapshot:
    return BudgetSnapshot(
        step_limit=20,
        steps_used=2,
        loop_limit=4,
        loops_used=1,
        time_limit_seconds=600,
        time_used_seconds=12,
        token_limit=20_000,
        tokens_used=500,
        cost_limit_usd=5.0,
        cost_used_usd=0.2,
        tool_call_limit=10,
        tool_calls_used=0,
    )


def test_roles_exclude_security_supervisor() -> None:
    assert {role.value for role in AgentRole} == {
        "superagent",
        "alert_triage",
        "threat_investigation",
        "knowledge_retrieval",
        "response_planning",
        "verification",
        "reporting",
    }
    assert "security_supervisor" not in AgentRole._value2member_map_


def test_reference_kinds_are_fixed_by_concrete_type() -> None:
    case_id = uuid4()
    evidence = EvidenceReference(uuid4(), case_id, "siem:1", NOW, "b" * 64)
    knowledge = KnowledgeReference(uuid4(), case_id, "kb:doc:v2:chunk:7", NOW, "c" * 64)
    assert evidence.kind is ReferenceKind.EVIDENCE
    assert knowledge.kind is ReferenceKind.KNOWLEDGE


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "not-uuid"), ("case_id", "not-uuid")],
)
def test_reference_requires_real_uuids(field: str, value: str) -> None:
    values = {
        "id": uuid4(),
        "case_id": uuid4(),
        "source_id": "source",
        "observed_at": NOW,
        "integrity_sha256": "a" * 64,
    }
    values[field] = value
    with pytest.raises(TypeError, match="UUID"):
        EvidenceReference(**values)


@pytest.mark.parametrize(
    "timestamp",
    [datetime(2026, 7, 20), datetime(2026, 7, 20, tzinfo=timezone(timedelta(hours=8)))],
)
def test_reference_requires_aware_utc(timestamp: datetime) -> None:
    with pytest.raises(ValueError, match="aware UTC"):
        EvidenceReference(uuid4(), uuid4(), "source", timestamp, "a" * 64)


def test_confirmed_fact_must_be_confirmed_and_cited() -> None:
    values = dict(
        id=uuid4(),
        statement="Endpoint contacted a known command-and-control address.",
        confirmed=True,
        references=(evidence_reference(),),
        confidence=0.95,
        confirmed_at=NOW,
    )
    with pytest.raises(ValueError, match="confirmed"):
        ConfirmedFact(**(values | {"confirmed": False}))
    with pytest.raises(ValueError, match="reference"):
        ConfirmedFact(**(values | {"references": ()}))


@pytest.mark.parametrize("confidence", [-0.01, 1.01, True, float("nan"), float("inf")])
def test_confidence_is_bounded(confidence: float) -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        Hypothesis(uuid4(), "Possible credential theft", confidence, ())


def test_budget_rejects_negative_overused_and_excessive_limits() -> None:
    values = budget().to_dict()
    with pytest.raises(ValueError, match="non-negative"):
        BudgetSnapshot(**(values | {"steps_used": -1}))
    with pytest.raises(ValueError, match="cannot exceed"):
        BudgetSnapshot(**(values | {"steps_used": 21}))
    with pytest.raises(ValueError, match="hard maximum"):
        BudgetSnapshot(**(values | {"token_limit": 2_000_001}))
    with pytest.raises(TypeError, match="integers"):
        BudgetSnapshot(**(values | {"step_limit": 20.5}))
    with pytest.raises(TypeError, match="integers"):
        BudgetSnapshot(**(values | {"tokens_used": True}))
    with pytest.raises(ValueError, match="non-negative"):
        BudgetSnapshot(**(values | {"cost_used_usd": float("nan")}))


def test_shared_context_defensively_freezes_sequences_and_mappings() -> None:
    case_id = uuid4()
    facts = []
    plan = ["triage"]
    statuses = {"triage": "running"}
    context = SharedCaseContext(
        case_id=case_id,
        phase=CasePhase.TRIAGE,
        user_goal="Determine whether the alert is malicious.",
        confirmed_facts=facts,
        hypotheses=(),
        risks=(),
        plan=plan,
        step_status=statuses,
        disposition_status="open",
        budget=budget(),
        revision=0,
        updated_at=NOW,
    )
    facts.append("invalid")
    plan.append("mutated")
    statuses["triage"] = "succeeded"
    assert context.confirmed_facts == ()
    assert context.plan == ("triage",)
    assert context.step_status == {"triage": "running"}
    assert isinstance(context.step_status, MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        context.phase = CasePhase.INVESTIGATION


def test_private_context_owner_must_match_concrete_type() -> None:
    common = dict(
        case_id=uuid4(),
        owner=AgentRole.ALERT_TRIAGE,
        working_items={"candidate": ["alert-1"]},
        references=(),
        updated_at=NOW,
    )
    context = AlertTriagePrivateContext(**common)
    assert context.working_items["candidate"] == ("alert-1",)
    with pytest.raises(ValueError, match="owner"):
        ResponsePlanningPrivateContext(**common)


def test_handoff_requires_different_roles_and_complete_content() -> None:
    values = dict(
        id=uuid4(),
        case_id=uuid4(),
        sender=AgentRole.ALERT_TRIAGE,
        receiver=AgentRole.THREAT_INVESTIGATION,
        conclusion="Correlated alerts require investigation.",
        references=(evidence_reference(),),
        confidence=0.8,
        open_questions=("Was the process user initiated?",),
        recommended_actions=("Build the endpoint timeline.",),
        created_at=NOW,
    )
    with pytest.raises(ValueError, match="different"):
        HandoffPacket(**(values | {"receiver": AgentRole.ALERT_TRIAGE}))
    with pytest.raises(ValueError, match="conclusion"):
        HandoffPacket(**(values | {"conclusion": " "}))


def test_high_confidence_handoff_requires_reference() -> None:
    with pytest.raises(ValueError, match="reference"):
        HandoffPacket(
            uuid4(),
            uuid4(),
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
            "Likely malicious",
            (),
            0.9,
            (),
            ("Investigate",),
            NOW,
        )


def test_handoff_is_same_case_and_json_safe() -> None:
    reference = evidence_reference()
    handoff = HandoffPacket(
        uuid4(),
        reference.case_id,
        AgentRole.ALERT_TRIAGE,
        AgentRole.THREAT_INVESTIGATION,
        "Correlated alerts require investigation.",
        (reference,),
        0.9,
        ("Was the process user initiated?",),
        ("Build the endpoint timeline.",),
        NOW,
    )

    assert json.loads(json.dumps(handoff.to_dict()))["references"][0]["kind"] == "evidence"
    assert handoff.open_questions == ("Was the process user initiated?",)
    assert handoff.recommended_actions == ("Build the endpoint timeline.",)
    with pytest.raises(ValueError, match="same case"):
        HandoffPacket(
            uuid4(),
            uuid4(),
            AgentRole.ALERT_TRIAGE,
            AgentRole.THREAT_INVESTIGATION,
            "Investigate.",
            (reference,),
            0.5,
            (),
            ("Build timeline.",),
            NOW,
        )


def test_agent_output_is_explicit_json_safe_and_has_no_forbidden_fields() -> None:
    reference = evidence_reference()
    output = AgentOutput(
        role=AgentRole.THREAT_INVESTIGATION,
        case_id=reference.case_id,
        summary="Investigation produced one bounded hypothesis.",
        references=(reference,),
        hypotheses=(Hypothesis(uuid4(), "Possible beaconing", 0.6, (reference,)),),
        risks=(Risk(uuid4(), "Potential command and control", "high", (reference,)),),
        recommended_actions=("Request human review.",),
        created_at=NOW,
        termination_reason=TerminationReason.COMPLETED,
    )
    encoded = json.dumps(output.to_dict(), allow_nan=False)
    assert '"role": "threat_investigation"' in encoded
    assert NOW.isoformat() in encoded
    lowered = encoded.lower()
    for forbidden in (
        "tenant",
        "principal",
        "secret",
        "raw_prompt",
        "chain_of_thought",
    ):
        assert forbidden not in lowered


def test_text_and_collection_bounds_are_enforced() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        Risk(uuid4(), " ", "high", ())
    with pytest.raises(ValueError, match="maximum length"):
        Hypothesis(uuid4(), "x" * 4097, 0.5, ())
    with pytest.raises(ValueError, match="too many"):
        AgentOutput(
            AgentRole.REPORTING,
            uuid4(),
            "summary",
            (),
            (),
            (),
            tuple("action" for _ in range(1001)),
            NOW,
        )
