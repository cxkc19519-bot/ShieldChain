"""Structural in-memory ContactStateStore CAS evidence."""

from __future__ import annotations

from saga.domain.contact import ContactCommit
from saga.ports.contact_state import ContactCommitOutcome
from tests.protocol.test_contact_resolution import _registered_agent


def test_memory_contact_state_cas_consumes_exactly_one_public_otk() -> None:
    agents, _, _, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":1}]}'
    )
    snapshot = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    command = ContactCommit(
        agent_id,
        agent_id,
        snapshot.available_public_otks[0].otk_id,
        0,
        snapshot.agent_revision,
        snapshot.receiving_active,
        snapshot.policy_version,
        snapshot.pair_counter,
        snapshot.otk_pool_revision,
    )

    assert agents.try_commit(command) is ContactCommitOutcome.COMMITTED
    assert agents.try_commit(command) is ContactCommitOutcome.CONFLICT
    current = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert [entry.otk_id.ordinal for entry in current.available_public_otks] == [1]
    assert current.otk_pool_revision == snapshot.otk_pool_revision + 1


def test_stale_allocation_conflicts_on_pool_revision_without_partial_mutation() -> None:
    agents, _, _, agent_id, _ = _registered_agent(
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}'
    )
    snapshot = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    first = ContactCommit(
        agent_id,
        agent_id,
        snapshot.available_public_otks[0].otk_id,
        1,
        snapshot.agent_revision,
        snapshot.receiving_active,
        snapshot.policy_version,
        snapshot.pair_counter,
        snapshot.otk_pool_revision,
    )
    stale = ContactCommit(
        agent_id,
        agent_id,
        snapshot.available_public_otks[1].otk_id,
        1,
        snapshot.agent_revision,
        snapshot.receiving_active,
        snapshot.policy_version,
        snapshot.pair_counter,
        snapshot.otk_pool_revision,
    )

    assert agents.try_commit(first) is ContactCommitOutcome.COMMITTED
    before = agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id)
    assert agents.try_commit(stale) is ContactCommitOutcome.CONFLICT
    assert agents.read_snapshot(receiving_agent_id=agent_id, initiating_agent_id=agent_id) == before
