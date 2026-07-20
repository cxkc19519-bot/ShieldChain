"""Memory/SQLite transcript parity, including preserved legacy policy bytes."""

from __future__ import annotations

from pathlib import Path

import pytest

from saga.domain.contact import ResolveContactCommand
from saga.domain.errors import InvalidContactPolicy, PairBudgetExhausted
from saga.protocols.contact_resolution import ContactResolutionService
from tests.integration.test_contact_atomicity import make_backend


def _resolve_transcript(backend) -> tuple[object, ...]:  # type: ignore[no-untyped-def]
    command = ResolveContactCommand(backend.agent_id, backend.agent_id)
    service = ContactResolutionService(
        contact_state_store=backend.agents, user_registry=backend.users
    )
    transcript: list[object] = []
    for _ in range(3):
        try:
            transcript.append(service.resolve(command).public_otk.otk_id.ordinal)
        except Exception as error:
            transcript.append(type(error))
    return tuple(transcript)


def test_memory_and_sqlite_have_the_same_valid_contact_transcript(tmp_path: Path) -> None:
    policy = b'{"version":1,"rules":[{"kind":"global","budget":2}]}'
    memory = make_backend(backend="memory", policy=policy, public_otk_count=2)
    sqlite = make_backend(
        backend="sqlite",
        database=tmp_path / "parity.sqlite3",
        policy=policy,
        public_otk_count=2,
    )

    assert _resolve_transcript(memory) == _resolve_transcript(sqlite) == (0, 1, PairBudgetExhausted)
    for backend in (memory, sqlite):
        snapshot = backend.agents.read_snapshot(
            receiving_agent_id=backend.agent_id, initiating_agent_id=backend.agent_id
        )
        assert snapshot.pair_counter is not None and snapshot.pair_counter.remaining == 0
        assert snapshot.available_public_otks == ()


def test_legacy_phase_two_policy_fails_closed_with_zero_mutation_on_both_backends(
    tmp_path: Path,
) -> None:
    legacy = b'{"legacy":true}'
    memory = make_backend(backend="memory", policy=legacy, public_otk_count=2)
    sqlite = make_backend(
        backend="sqlite",
        database=tmp_path / "legacy.sqlite3",
        policy=legacy,
        public_otk_count=2,
    )
    for backend in (memory, sqlite):
        before = backend.agents.read_snapshot(
            receiving_agent_id=backend.agent_id, initiating_agent_id=backend.agent_id
        )
        with pytest.raises(InvalidContactPolicy, match="^invalid contact policy$"):
            ContactResolutionService(
                contact_state_store=backend.agents, user_registry=backend.users
            ).resolve(ResolveContactCommand(backend.agent_id, backend.agent_id))
        assert (
            backend.agents.read_snapshot(
                receiving_agent_id=backend.agent_id, initiating_agent_id=backend.agent_id
            )
            == before
        )
