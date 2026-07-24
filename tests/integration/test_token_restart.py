"""Restart and persistence integration tests for SQLite stores."""

from __future__ import annotations

import sqlite3

import pytest

from saga.adapters.persistence.sqlite import SQLiteSotkStore, SQLiteTokenStateStore
from saga.domain.agents import AgentId
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping, TokenRecord
from saga.domain.users import UserId
from saga.ports.token_state import SotkClaimOutcome, TokenUseOutcome


@pytest.fixture
def db_path(tmp_path: object) -> str:
    from pathlib import Path
    path = str(Path(str(tmp_path)) / "persist.db")
    
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE agents(agent_id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO agents(agent_id) VALUES (?)", ("receiver@example.com:agent-a",))
        
    return path


def test_sotk_persistence(db_path: str) -> None:
    receiver_id = AgentId(owner=UserId("receiver@example.com"), name="agent-a")
    otk_id = PublicOtkId(receiving_agent_id=receiver_id, ordinal=42)
    sotk_secret = b"\xaa" * 32
    
    mapping = SotkMapping(otk_id=otk_id, secret_key=sotk_secret)
    
    # Store with first instance
    store1 = SQLiteSotkStore(db_path)
    store1.store(mapping)
    
    # Recover with second instance
    store2 = SQLiteSotkStore(db_path)
    outcome, key = store2.claim_and_return(otk_id)
    
    assert outcome == SotkClaimOutcome.CLAIMED
    assert key == sotk_secret


def test_token_state_persistence(db_path: str) -> None:
    receiver_id = AgentId(owner=UserId("receiver@example.com"), name="agent-a")
    record = TokenRecord(
        token_nonce=b"\x01" * 32,
        receiving_agent_id=receiver_id,
        initiating_agent_access_control_public_key=b"\x02" * 32,
        sdhk=b"\x03" * 32,
        issued_at=1000,
        expires_at=2000,
        q_max=5,
        use_count=1,
        revision=1,
    )
    
    # Store with first instance
    store1 = SQLiteTokenStateStore(db_path)
    store1.create(record)
    
    # Recover with second instance
    store2 = SQLiteTokenStateStore(db_path)
    recovered = store2.get(receiving_agent_id=receiver_id, token_nonce=record.token_nonce)
    
    assert recovered is not None
    assert recovered.token_nonce == record.token_nonce
    assert recovered.use_count == 1
    assert recovered.q_max == 5
    
    # Try increment on recovered token
    outcome = store2.try_increment_use(
        receiving_agent_id=receiver_id,
        token_nonce=record.token_nonce,
        expected_revision=recovered.revision,
    )
    assert outcome == TokenUseOutcome.INCREMENTED
    
    # Try third instance
    store3 = SQLiteTokenStateStore(db_path)
    recovered3 = store3.get(receiving_agent_id=receiver_id, token_nonce=record.token_nonce)
    
    assert recovered3 is not None
    assert recovered3.use_count == 2
    assert recovered3.revision == 2
