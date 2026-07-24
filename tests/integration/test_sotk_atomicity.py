"""Concurrency integration tests for SQLiteSotkStore."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from saga.adapters.persistence.sqlite import SQLiteSotkStore
from saga.domain.agents import AgentId
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping
from saga.domain.users import UserId
from saga.ports.token_state import SotkClaimOutcome


@pytest.fixture
def store(tmp_path: object) -> SQLiteSotkStore:
    from pathlib import Path
    db_path = Path(str(tmp_path)) / "sotk.db"
    
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE agents(agent_id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO agents(agent_id) VALUES (?)", ("receiver@example.com:agent-a",))
        
    store = SQLiteSotkStore(str(db_path))
    return store


def test_concurrent_sotk_claim(store: SQLiteSotkStore) -> None:
    # We want to simulate N threads trying to claim the exact same SOTK concurrently.
    # Only 1 thread should succeed (return CLAIMED), all others should return ALREADY_CONSUMED.
    receiver_id = AgentId(owner=UserId("receiver@example.com"), name="agent-a")
    otk_id = PublicOtkId(receiving_agent_id=receiver_id, ordinal=42)
    sotk_secret = b"\xaa" * 32
    
    mapping = SotkMapping(otk_id=otk_id, secret_key=sotk_secret)
    store.store(mapping)

    num_threads = 20
    barrier = threading.Barrier(num_threads)
    
    def claim_sotk() -> SotkClaimOutcome:
        barrier.wait()
        outcome, key = store.claim_and_return(otk_id)
        if outcome == SotkClaimOutcome.CLAIMED:
            assert key == sotk_secret
        else:
            assert key is None
        return outcome
        
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(claim_sotk) for _ in range(num_threads)]
        results = [f.result() for f in as_completed(futures)]
        
    claimed = [r for r in results if r == SotkClaimOutcome.CLAIMED]
    consumed = [r for r in results if r == SotkClaimOutcome.ALREADY_CONSUMED]
    
    assert len(claimed) == 1
    assert len(consumed) == 19
    
    # Verify final state
    # A second claim attempt directly should return already consumed
    outcome, _ = store.claim_and_return(otk_id)
    assert outcome == SotkClaimOutcome.ALREADY_CONSUMED
