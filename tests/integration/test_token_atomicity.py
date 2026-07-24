"""Concurrency integration tests for the SQLiteTokenStateStore."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from saga.adapters.persistence.sqlite import SQLiteTokenStateStore
from saga.domain.agents import AgentId
from saga.domain.token_state import TokenRecord
from saga.domain.users import UserId
from saga.ports.token_state import TokenUseOutcome


@pytest.fixture
def store(tmp_path: object) -> SQLiteTokenStateStore:
    from pathlib import Path
    db_path = Path(str(tmp_path)) / "token_state.db"
    
    # Pre-create the agents table and the agent so FK constraints pass
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE agents(agent_id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO agents(agent_id) VALUES (?)", ("receiver@example.com:agent-a",))
        
    store = SQLiteTokenStateStore(str(db_path))
    return store


def test_concurrent_use_quota_limits(store: SQLiteTokenStateStore) -> None:
    # We want to simulate N threads trying to use a token with q_max=M, where N > M.
    # Only M threads should succeed (return USED), others should return QUOTA_EXHAUSTED.
    receiver_id = AgentId(owner=UserId("receiver@example.com"), name="agent-a")
    record = TokenRecord(
        token_nonce=b"\x01" * 32,
        receiving_agent_id=receiver_id,
        initiating_agent_access_control_public_key=b"\x02" * 32,
        sdhk=b"\x03" * 32,
        issued_at=1000,
        expires_at=2000,
        q_max=5,
        use_count=0,
        revision=0,
    )
    store.create(record)

    num_threads = 20
    barrier = threading.Barrier(num_threads)
    
    def use_token() -> TokenUseOutcome:
        barrier.wait()
        for _ in range(10):
            token = store.get(receiving_agent_id=receiver_id, token_nonce=record.token_nonce)
            if token is None:
                return TokenUseOutcome.NOT_FOUND
            if token.use_count >= token.q_max:
                return "exhausted"
            outcome = store.try_increment_use(
                receiving_agent_id=receiver_id,
                token_nonce=record.token_nonce,
                expected_revision=token.revision,
            )
            if outcome == TokenUseOutcome.INCREMENTED:
                return TokenUseOutcome.INCREMENTED
        return TokenUseOutcome.CONFLICT
        
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(use_token) for _ in range(num_threads)]
        results = [f.result() for f in as_completed(futures)]
        
    succeeded = [r for r in results if r == TokenUseOutcome.INCREMENTED]
    exhausted = [r for r in results if r == "exhausted"]
    
    assert len(succeeded) == 5
    assert len(exhausted) == 15
    
    # Verify final state
    token = store.get(receiving_agent_id=receiver_id, token_nonce=record.token_nonce)
    assert token is not None
    assert token.use_count == 5
    assert token.revision == 5
