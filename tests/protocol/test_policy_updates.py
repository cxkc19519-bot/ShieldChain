"""Phase 3 authenticated structural policy-management evidence."""

from __future__ import annotations

import pytest

from saga.crypto.canonical import OtkAttestation, encode_otk_attestation
from saga.crypto.signatures import sign
from saga.domain.agents import RegisteredPublicOtk
from saga.domain.contact import (
    AppendPublicOtksCommand,
    DeactivateAgentCommand,
    UpdateContactPolicyCommand,
)
from saga.domain.errors import AgentInactive, AgentOwnerAuthenticationFailed
from saga.ports.contact_state import ContactCommitOutcome
from saga.protocols.contact_management import ContactManagementService
from tests.helpers.certificates import NOW_MS
from tests.helpers.registration import FixedClock
from tests.protocol.test_contact_resolution import _key, _registered_agent


def _service(policy: bytes = b'{"version":1,"rules":[{"kind":"global","budget":2}]}'):
    agents, users, fixtures, agent_id, _ = _registered_agent(policy=policy)
    return (
        ContactManagementService(
            contact_state_store=agents,
            user_registry=users,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
        ),
        agents,
        agent_id,
    )


def test_policy_replacement_deactivation_and_owner_password_checks() -> None:
    service, agents, agent_id = _service()
    policy = b'{"version":1,"rules":[{"kind":"global","budget":-1}]}'
    service.replace_policy(
        UpdateContactPolicyCommand(agent_id.owner, "owner-password", agent_id, policy)
    )
    assert (
        agents.read_snapshot(
            receiving_agent_id=agent_id, initiating_agent_id=agent_id
        ).contact_policy_document
        == policy
    )
    with pytest.raises(AgentOwnerAuthenticationFailed):
        service.deactivate(DeactivateAgentCommand(agent_id.owner, "wrong", agent_id))
    service.deactivate(DeactivateAgentCommand(agent_id.owner, "owner-password", agent_id))
    with pytest.raises(AgentInactive):
        service.replace_policy(
            UpdateContactPolicyCommand(agent_id.owner, "owner-password", agent_id, policy)
        )


def test_signed_refill_appends_without_resetting_revisions_or_counter() -> None:
    service, agents, agent_id = _service()
    public_key = b"z" * 32
    public_otk = RegisteredPublicOtk(
        public_key,
        sign(_key(2), encode_otk_attestation(OtkAttestation(agent_id.value, public_key))),
    )
    before = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)

    service.append_public_otks(
        AppendPublicOtksCommand(agent_id.owner, "owner-password", agent_id, (public_otk,))
    )

    after = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert after.otk_pool_revision == before.otk_pool_revision + 1
    assert after.available_public_otks[-1].otk_id.ordinal == 2


class _CountingUsers:
    def __init__(self, inner) -> None:  # type: ignore[no-untyped-def]
        self._inner = inner
        self.get_calls = 0

    def get(self, user_id):  # type: ignore[no-untyped-def]
        self.get_calls += 1
        return self._inner.get(user_id)

    def create_if_absent(self, registration):  # type: ignore[no-untyped-def]
        return self._inner.create_if_absent(registration)


class _FirstPolicyConflict:
    def __init__(self, inner) -> None:  # type: ignore[no-untyped-def]
        self._inner = inner
        self.replace_calls = 0

    def read_snapshot(self, *, receiving_agent_id, initiating_agent_id):  # type: ignore[no-untyped-def]
        return self._inner.read_snapshot(
            receiving_agent_id=receiving_agent_id, initiating_agent_id=initiating_agent_id
        )

    def try_commit(self, command):  # type: ignore[no-untyped-def]
        return self._inner.try_commit(command)

    def replace_policy(self, command):  # type: ignore[no-untyped-def]
        self.replace_calls += 1
        if self.replace_calls == 1:
            return ContactCommitOutcome.CONFLICT
        return self._inner.replace_policy(command)

    def append_otks(self, command):  # type: ignore[no-untyped-def]
        return self._inner.append_otks(command)

    def deactivate(self, command):  # type: ignore[no-untyped-def]
        return self._inner.deactivate(command)


def test_policy_conflict_retries_with_a_fresh_owner_authentication() -> None:
    agents, users, fixtures, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}'
    )
    counted_users = _CountingUsers(users)
    conflicts = _FirstPolicyConflict(agents)
    service = ContactManagementService(
        contact_state_store=conflicts,
        user_registry=counted_users,
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
    )
    replacement = b'{"version":1,"rules":[{"kind":"global","budget":-1}]}'

    service.replace_policy(
        UpdateContactPolicyCommand(agent_id.owner, "owner-password", agent_id, replacement)
    )

    assert conflicts.replace_calls == 2
    assert counted_users.get_calls == 2
    assert (
        agents.read_snapshot(
            receiving_agent_id=agent_id, initiating_agent_id=agent_id
        ).contact_policy_document
        == replacement
    )
