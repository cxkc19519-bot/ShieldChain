"""Closed, deterministic contact-policy representation for Phase 3."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .agents import AgentId
from .errors import (
    ContactPolicyDenied,
    ContactPolicyNoMatch,
    InvalidContactInput,
    InvalidContactPolicy,
    RegistrationError,
)
from .users import UserId

_MAX_RULES = 1_024
_MAX_BUDGET = 1_000_000
_SPECIFICITY = {"global": 0, "type": 1, "user": 2, "exact": 3}


class _Pairs(list[tuple[str, object]]):
    """Keep duplicate JSON keys visible while validating a closed document."""


def _pairs_hook(items: list[tuple[str, object]]) -> _Pairs:
    return _Pairs(items)


def _plain_non_negative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise InvalidContactInput()
    return value


def _require_budget(value: object) -> int:
    if type(value) is not int or value == 0 or value < -1 or value > _MAX_BUDGET:
        raise InvalidContactPolicy()
    return value


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One closed policy selector and its pair budget."""

    kind: str
    selector: str | None
    budget: int

    def __post_init__(self) -> None:
        if self.kind not in _SPECIFICITY:
            raise InvalidContactPolicy()
        _require_budget(self.budget)
        if self.kind == "global":
            if self.selector is not None:
                raise InvalidContactPolicy()
            return
        if type(self.selector) is not str:
            raise InvalidContactPolicy()
        try:
            if self.kind == "exact":
                owner, name = self.selector.split(":", maxsplit=1)
                if AgentId(owner=UserId(owner), name=name).value != self.selector:
                    raise InvalidContactPolicy()
            elif self.kind == "user":
                if UserId(self.selector).value != self.selector:
                    raise InvalidContactPolicy()
            elif self.kind == "type":
                # Reuse AgentId's exact identifier rules without making up a new one.
                if AgentId(owner=UserId("policy"), name=self.selector).name != self.selector:
                    raise InvalidContactPolicy()
        # Selector validation deliberately reuses the Phase 2 identifier
        # objects.  Their failures belong to the registration error family,
        # but policy input must never expose that implementation detail.
        except (RegistrationError, ValueError):
            raise InvalidContactPolicy() from None

    @property
    def specificity(self) -> int:
        return _SPECIFICITY[self.kind]

    def matches(self, agent_id: AgentId) -> bool:
        if type(agent_id) is not AgentId:
            raise InvalidContactInput()
        return (
            self.kind == "global"
            or (self.kind == "exact" and self.selector == agent_id.value)
            or (self.kind == "user" and self.selector == agent_id.owner.value)
            or (self.kind == "type" and self.selector == agent_id.name)
        )


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    rule: PolicyRule
    budget: int

    def __post_init__(self) -> None:
        if type(self.rule) is not PolicyRule or type(self.budget) is not int:
            raise InvalidContactInput()
        if self.budget != self.rule.budget:
            raise InvalidContactInput()


@dataclass(frozen=True, slots=True)
class ContactPolicy:
    """A parsed strict policy document.  Legacy bytes are never normalized here."""

    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if type(self.rules) is not tuple or not 1 <= len(self.rules) <= _MAX_RULES:
            raise InvalidContactPolicy()
        if any(type(rule) is not PolicyRule for rule in self.rules):
            raise InvalidContactPolicy()
        keys = tuple((rule.kind, rule.selector) for rule in self.rules)
        if len(keys) != len(set(keys)):
            raise InvalidContactPolicy()

    @classmethod
    def parse(cls, document: object) -> ContactPolicy:
        if type(document) is not bytes:
            raise InvalidContactPolicy()
        try:
            root = json.loads(
                document.decode("utf-8", errors="strict"), object_pairs_hook=_pairs_hook
            )
            if not isinstance(root, _Pairs):
                raise InvalidContactPolicy()
            root_names = tuple(name for name, _ in root)
            if len(root_names) != 2 or set(root_names) != {"version", "rules"}:
                raise InvalidContactPolicy()
            values = dict(root)
            if type(values["version"]) is not int or values["version"] != 1:
                raise InvalidContactPolicy()
            raw_rules = values["rules"]
            if type(raw_rules) is not list or not 1 <= len(raw_rules) <= _MAX_RULES:
                raise InvalidContactPolicy()
            rules = tuple(cls._parse_rule(raw_rule) for raw_rule in raw_rules)
            policy = cls(rules=rules)
            if document != policy._canonical_document():
                raise InvalidContactPolicy()
            return policy
        except (
            UnicodeDecodeError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            InvalidContactPolicy,
        ):
            raise InvalidContactPolicy() from None

    def _canonical_document(self) -> bytes:
        """Return the one accepted UTF-8 JSON spelling for this policy."""
        rules: list[dict[str, object]] = []
        for rule in self.rules:
            encoded: dict[str, object] = {"kind": rule.kind}
            if rule.kind == "exact":
                encoded["agent_id"] = rule.selector
            elif rule.kind == "user":
                encoded["user_id"] = rule.selector
            elif rule.kind == "type":
                encoded["name"] = rule.selector
            encoded["budget"] = rule.budget
            rules.append(encoded)
        return json.dumps(
            {"version": 1, "rules": rules},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _parse_rule(raw_rule: object) -> PolicyRule:
        if not isinstance(raw_rule, _Pairs):
            raise InvalidContactPolicy()
        names = tuple(name for name, _ in raw_rule)
        values = dict(raw_rule)
        kind = values.get("kind")
        if len(names) != len(set(names)) or type(kind) is not str:
            raise InvalidContactPolicy()
        expected_names = {
            "exact": {"kind", "agent_id", "budget"},
            "user": {"kind", "user_id", "budget"},
            "type": {"kind", "name", "budget"},
            "global": {"kind", "budget"},
        }.get(kind)
        if expected_names is None or set(names) != expected_names:
            raise InvalidContactPolicy()
        selector_key = {"exact": "agent_id", "user": "user_id", "type": "name"}.get(kind)
        selector = None if selector_key is None else values[selector_key]
        if selector is not None and type(selector) is not str:
            raise InvalidContactPolicy()
        return PolicyRule(
            kind=kind,
            selector=selector,
            budget=_require_budget(values["budget"]),
        )

    def match(self, agent_id: AgentId) -> PolicyMatch:
        if type(agent_id) is not AgentId:
            raise InvalidContactInput()
        candidates = tuple(rule for rule in self.rules if rule.matches(agent_id))
        if not candidates:
            raise ContactPolicyNoMatch()
        selected = max(candidates, key=lambda rule: rule.specificity)
        if selected.budget == -1:
            raise ContactPolicyDenied()
        return PolicyMatch(rule=selected, budget=selected.budget)


__all__ = ("ContactPolicy", "PolicyMatch", "PolicyRule")
