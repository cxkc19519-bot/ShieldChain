import json
from uuid import uuid4

import pytest

from shieldchain.response_planning.candidate import parse_response_plan_candidate


def _candidate() -> dict[str, object]:
    evidence = str(uuid4())
    return {
        "action": "propose_response_plan",
        "public_summary": "建议先验证目标，再由人工审批处置。",
        "assumptions": [{"statement": "证据已确认", "evidence_ids": [evidence]}],
        "actions": [
            {
                "client_action_id": "step-1",
                "tool": "block_ip",
                "target_reference_id": evidence,
                "arguments": {"rule_ttl_seconds": 600},
                "expected_state": {"firewall_status": "blocked"},
                "depends_on": [],
                "public_reason": "阻止已确认恶意来源。",
                "verification": {
                    "tool": "query_firewall_state",
                    "expected_state": {"firewall_status": "blocked"},
                },
                "rollback_note": "由人工删除对应规则。",
            }
        ],
        "stop_conditions": ["证据冲突", "审批拒绝"],
        "operator_notes": ["变更必须单独审批"],
    }


def test_candidate_accepts_only_strict_bounded_shape() -> None:
    parsed = parse_response_plan_candidate(json.dumps(_candidate(), ensure_ascii=False))
    assert parsed.actions[0].tool == "block_ip"
    assert parsed.actions[0].arguments == {"rule_ttl_seconds": 600}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: {**value, "tenant_id": str(uuid4())},
        lambda value: {
            **value,
            "actions": [{**value["actions"][0], "risk": "low"}],
        },
        lambda value: {
            **value,
            "actions": [{**value["actions"][0], "arguments": {"url": "https://evil"}}],
        },
        lambda value: {
            **value,
            "actions": [{**value["actions"][0], "arguments": {"command": "rm"}}],
        },
        lambda value: {
            **value,
            "actions": [{**value["actions"][0], "depends_on": ["future"]}],
        },
    ],
)
def test_candidate_rejects_identity_policy_target_and_code_injection(mutate) -> None:
    with pytest.raises(ValueError):
        parse_response_plan_candidate(json.dumps(mutate(_candidate()), ensure_ascii=False))


def test_candidate_rejects_markdown_trailing_text_and_duplicate_keys() -> None:
    raw = json.dumps(_candidate(), ensure_ascii=False)
    for invalid in (f"```json\n{raw}\n```", raw + " trailing", '{"action":"x","action":"y"}'):
        with pytest.raises(ValueError):
            parse_response_plan_candidate(invalid)
