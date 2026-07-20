import json

import pytest

from saga.domain import (
    AgentId,
    ContactPolicy,
    ContactPolicyDenied,
    ContactPolicyNoMatch,
    InvalidContactInput,
    InvalidContactPolicy,
    PolicyRule,
    UserId,
)


def _agent(owner: str, name: str) -> AgentId:
    return AgentId(owner=UserId(owner), name=name)


def _policy(rules: list[dict[str, object]]) -> bytes:
    return json.dumps({"version": 1, "rules": rules}, separators=(",", ":")).encode()


def test_policy_selects_the_most_specific_matching_rule_without_rule_order_effect() -> None:
    policy = ContactPolicy.parse(
        _policy(
            [
                {"kind": "global", "budget": 1},
                {"kind": "type", "name": "worker", "budget": 2},
                {"kind": "user", "user_id": "initiator", "budget": 3},
                {"kind": "exact", "agent_id": "initiator:worker", "budget": 4},
            ]
        )
    )

    match = policy.match(_agent("initiator", "worker"))

    assert match.rule == PolicyRule(kind="exact", selector="initiator:worker", budget=4)
    assert match.budget == 4


@pytest.mark.parametrize(
    "rules",
    [
        [{"kind": "global", "budget": 1}, {"kind": "global", "budget": 2}],
        [
            {"kind": "user", "user_id": "same", "budget": 1},
            {"kind": "user", "user_id": "same", "budget": 2},
        ],
        [
            {"kind": "type", "name": "same", "budget": 1},
            {"kind": "type", "name": "same", "budget": 2},
        ],
        [
            {"kind": "exact", "agent_id": "same:agent", "budget": 1},
            {"kind": "exact", "agent_id": "same:agent", "budget": 2},
        ],
    ],
)
def test_equal_specificity_overlap_is_rejected(rules: list[dict[str, object]]) -> None:
    with pytest.raises(InvalidContactPolicy):
        ContactPolicy.parse(_policy(rules))


@pytest.mark.parametrize(
    "document",
    [
        b"[]",
        b'{"version":1,"rules":[]}',
        b'{"version":1,"rules":[{"kind":"global","budget":0}]}',
        b'{"version":1,"rules":[{"kind":"global","budget":true}]}',
        b'{"version":1,"rules":[{"kind":"global","budget":1,"extra":2}]}',
        b'{"version":2,"rules":[{"kind":"global","budget":1}]}',
        b'{"version":1,"rules":[{"kind":"exact","budget":1}]}',
    ],
)
def test_policy_is_a_strict_closed_json_document(document: bytes) -> None:
    with pytest.raises(InvalidContactPolicy):
        ContactPolicy.parse(document)


def test_no_match_and_explicit_deny_remain_distinct() -> None:
    no_match = ContactPolicy.parse(_policy([{"kind": "type", "name": "other", "budget": 1}]))
    deny = ContactPolicy.parse(_policy([{"kind": "global", "budget": -1}]))

    with pytest.raises(ContactPolicyNoMatch):
        no_match.match(_agent("initiator", "worker"))
    with pytest.raises(ContactPolicyDenied):
        deny.match(_agent("initiator", "worker"))


def test_policy_value_objects_fail_closed_for_wrong_runtime_types() -> None:
    with pytest.raises(InvalidContactPolicy):
        PolicyRule(kind="global", selector=None, budget=True)
    policy = ContactPolicy.parse(_policy([{"kind": "global", "budget": 1}]))
    with pytest.raises(InvalidContactInput):
        policy.match("initiator:worker")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kind", "selector"),
    [
        ("exact", "owner:"),
        ("user", ""),
        ("type", "has:colon"),
    ],
)
def test_malformed_selectors_normalize_registration_errors_to_policy_errors(
    kind: str, selector: str
) -> None:
    with pytest.raises(InvalidContactPolicy):
        PolicyRule(kind=kind, selector=selector, budget=1)


@pytest.mark.parametrize(
    "document",
    [
        b'{"version": 1,"rules":[{"kind":"global","budget":1}]}',
        b'{"rules":[{"kind":"global","budget":1}],"version":1}',
        b'{"version":1,"rules":[{"budget":1,"kind":"global"}]}',
        b'{"version":1,"rules":[{"kind":"user","user_id":"\\u0069nitiator","budget":1}]}',
    ],
)
def test_policy_requires_one_canonical_utf8_json_spelling(document: bytes) -> None:
    with pytest.raises(InvalidContactPolicy):
        ContactPolicy.parse(document)
