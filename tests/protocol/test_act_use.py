"""Integration tests for the ACT use protocol service."""

from __future__ import annotations

import pytest

from saga.adapters.persistence.memory import InMemoryTokenStateStore
from saga.crypto import aead
from saga.domain.act import (
    ActEnvelope,
    ActPlaintext,
    UseActCommand,
)
from saga.domain.agents import AgentId
from saga.domain.errors import (
    ActBindingFailed,
    ActExpired,
    ActFutureIssued,
    ActQuotaExhausted,
)
from saga.domain.token_state import TokenRecord
from saga.domain.users import UserId
from saga.ports.clock import Clock
from saga.protocols.act_use import ActUseService


class MockClock(Clock):
    def __init__(self, time_ms: int = 1_000_000) -> None:
        self._time = time_ms

    def now_ms(self) -> int:
        return self._time

    def advance(self, ms: int) -> None:
        self._time += ms


@pytest.fixture
def clock() -> MockClock:
    return MockClock()


@pytest.fixture
def token_state_store() -> InMemoryTokenStateStore:
    return InMemoryTokenStateStore()


@pytest.fixture
def service(
    clock: MockClock, token_state_store: InMemoryTokenStateStore, receiver_id: AgentId
) -> ActUseService:
    return ActUseService(
        receiving_agent_id=receiver_id,
        clock=clock,
        token_state_store=token_state_store,
    )


@pytest.fixture
def initiator_pk() -> bytes:
    return b"\x02" * 32


@pytest.fixture
def receiver_id() -> AgentId:
    return AgentId(owner=UserId("receiver@example.com"), name="agent-2")


@pytest.fixture
def dummy_sdhk() -> bytes:
    return b"\xbb" * 32


@pytest.fixture
def dummy_plaintext(initiator_pk: bytes, clock: MockClock) -> ActPlaintext:
    return ActPlaintext(
        nonce=b"\x01" * 32,
        issued_at=clock.now_ms(),
        expires_at=clock.now_ms() + 60_000,
        q_max=5,
        initiating_agent_access_control_public_key=initiator_pk,
    )


@pytest.fixture
def dummy_envelope(dummy_plaintext: ActPlaintext, dummy_sdhk: bytes) -> ActEnvelope:
    from saga.crypto.canonical import ActPlaintext as CanonicalActPlaintext
    from saga.crypto.canonical import encode_act_plaintext
    
    canonical_pt = CanonicalActPlaintext(
        nonce=dummy_plaintext.nonce,
        issued_at=dummy_plaintext.issued_at,
        expires_at=dummy_plaintext.expires_at,
        q_max=dummy_plaintext.q_max,
        initiating_agent_access_control_public_key=dummy_plaintext.initiating_agent_access_control_public_key,
    )

    envelope_aead_nonce = b"\x03" * 12
    aead_envelope = aead.encrypt_act(
        key=dummy_sdhk,
        plaintext=encode_act_plaintext(canonical_pt),
        nonce=envelope_aead_nonce,
    )
    return ActEnvelope(
        version=1,
        aead_nonce=aead_envelope.nonce,
        ciphertext=aead_envelope.ciphertext,
    )


@pytest.fixture
def dummy_record(
    receiver_id: AgentId, dummy_plaintext: ActPlaintext, dummy_sdhk: bytes
) -> TokenRecord:
    return TokenRecord(
        token_nonce=dummy_plaintext.nonce,
        receiving_agent_id=receiver_id,
        initiating_agent_access_control_public_key=dummy_plaintext.initiating_agent_access_control_public_key,
        sdhk=dummy_sdhk,
        issued_at=dummy_plaintext.issued_at,
        expires_at=dummy_plaintext.expires_at,
        q_max=dummy_plaintext.q_max,
        use_count=0,
        revision=0,
    )


def test_use_act_success(
    service: ActUseService,
    token_state_store: InMemoryTokenStateStore,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_envelope: ActEnvelope,
    dummy_record: TokenRecord,
) -> None:
    token_state_store.create(dummy_record)
    command = UseActCommand(
        envelope=dummy_envelope,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    result = service.use(command=command)
    assert result.use_count == 1
    
    # Second use
    result = service.use(command=command)
    assert result.use_count == 2
    
    token = token_state_store.get(receiving_agent_id=receiver_id, token_nonce=dummy_record.token_nonce)
    assert token is not None
    assert token.use_count == 2


def test_use_act_token_not_found(
    service: ActUseService,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_envelope: ActEnvelope,
) -> None:
    command = UseActCommand(
        envelope=dummy_envelope,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    with pytest.raises(ActBindingFailed):
        service.use(command=command)


def test_use_act_binding_mismatch(
    service: ActUseService,
    token_state_store: InMemoryTokenStateStore,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_envelope: ActEnvelope,
    dummy_record: TokenRecord,
) -> None:
    token_state_store.create(dummy_record)
    
    # Try using it with a different PK
    wrong_pk = b"\xff" * 32
    command = UseActCommand(
        envelope=dummy_envelope,
        initiating_agent_access_control_public_key=wrong_pk,
    )
    with pytest.raises(ActBindingFailed):
        service.use(command=command)


def test_use_act_expired(
    service: ActUseService,
    token_state_store: InMemoryTokenStateStore,
    clock: MockClock,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_envelope: ActEnvelope,
    dummy_record: TokenRecord,
) -> None:
    token_state_store.create(dummy_record)
    command = UseActCommand(
        envelope=dummy_envelope,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    clock.advance(60_001)  # past expires_at
    with pytest.raises(ActExpired):
        service.use(command=command)


def test_use_act_future_issued(
    service: ActUseService,
    token_state_store: InMemoryTokenStateStore,
    clock: MockClock,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_sdhk: bytes,
) -> None:
    # Create token issued in the future
    issued_at = clock.now_ms() + 10_000
    pt = ActPlaintext(
        nonce=b"\x01" * 32,
        issued_at=issued_at,
        expires_at=issued_at + 60_000,
        q_max=5,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    from saga.crypto.canonical import ActPlaintext as CanonicalActPlaintext
    from saga.crypto.canonical import encode_act_plaintext
    
    canonical_pt = CanonicalActPlaintext(
        nonce=pt.nonce,
        issued_at=pt.issued_at,
        expires_at=pt.expires_at,
        q_max=pt.q_max,
        initiating_agent_access_control_public_key=pt.initiating_agent_access_control_public_key,
    )

    envelope_aead_nonce = b"\x03" * 12
    aead_envelope = aead.encrypt_act(
        key=dummy_sdhk,
        plaintext=encode_act_plaintext(canonical_pt),
        nonce=envelope_aead_nonce,
    )
    envelope = ActEnvelope(version=1, aead_nonce=aead_envelope.nonce, ciphertext=aead_envelope.ciphertext)
    
    record = TokenRecord(
        token_nonce=pt.nonce,
        receiving_agent_id=receiver_id,
        initiating_agent_access_control_public_key=initiator_pk,
        sdhk=dummy_sdhk,
        issued_at=pt.issued_at,
        expires_at=pt.expires_at,
        q_max=pt.q_max,
        use_count=0,
        revision=0,
    )
    token_state_store.create(record)
    
    command = UseActCommand(
        envelope=envelope,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    with pytest.raises(ActFutureIssued):
        service.use(command=command)


def test_use_act_quota_exhausted(
    service: ActUseService,
    token_state_store: InMemoryTokenStateStore,
    receiver_id: AgentId,
    initiator_pk: bytes,
    dummy_envelope: ActEnvelope,
    dummy_record: TokenRecord,
) -> None:
    token_state_store.create(dummy_record)
    command = UseActCommand(
        envelope=dummy_envelope,
        initiating_agent_access_control_public_key=initiator_pk,
    )
    for _ in range(dummy_record.q_max):
        service.use(command=command)
        
    with pytest.raises(ActQuotaExhausted):
        service.use(command=command)
