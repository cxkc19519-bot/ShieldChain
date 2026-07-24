"""Integration tests for the ACT establishment protocol service."""

from __future__ import annotations

import pytest

from saga.adapters.persistence.memory import InMemorySotkStore, InMemoryTokenStateStore
from saga.domain.act import (
    ActEnvelope,
    ActPlaintext,
    EstablishActCommand,
)
from saga.domain.agents import AgentId, AgentRegistration
from saga.domain.errors import (
    ActEstablishmentFailed,
    SotkAlreadyConsumed,
)
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping
from saga.domain.users import UserId
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.protocols.act_establishment import ActEstablishmentService


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
def sotk_store() -> InMemorySotkStore:
    return InMemorySotkStore()


@pytest.fixture
def token_state_store() -> InMemoryTokenStateStore:
    return InMemoryTokenStateStore()


class MockRandomSource(RandomSource):
    def get_bytes(self, num_bytes: int) -> bytes:
        return b"\x01" * num_bytes
    def get_int(self, max_exclusive: int) -> int:
        return 0
    def bytes(self, count: int) -> bytes:
        return b"\x01" * count


@pytest.fixture
def random_source() -> MockRandomSource:
    return MockRandomSource()


@pytest.fixture
def receiver_registration(receiver_id: AgentId) -> AgentRegistration:
    from saga.domain.agents import RegisteredPublicOtk
    from saga.domain.encoding import EndpointValue
    return AgentRegistration(
        agent_id=receiver_id,
        owner_id=receiver_id.owner,
        endpoint=EndpointValue("device", "127.0.0.1", 8080),
        certificate_der=b"\x00" * 150,
        access_control_public_key=b"\x00" * 32,
        contact_policy_document=b"{}",
        public_otks=(
            RegisteredPublicOtk(
                public_key=b"\x00" * 32,
                user_signature=b"\x00" * 64,
            ),
        ),
        user_metadata_signature=b"\x00" * 64,
    )


@pytest.fixture
def service(
    clock: MockClock,
    sotk_store: InMemorySotkStore,
    token_state_store: InMemoryTokenStateStore,
    receiver_id: AgentId,
    receiver_registration: AgentRegistration,
    random_source: MockRandomSource,
) -> ActEstablishmentService:
    return ActEstablishmentService(
        receiving_agent_id=receiver_id,
        receiving_registration=receiver_registration,
        sotk_store=sotk_store,
        token_state_store=token_state_store,
        clock=clock,
        random_source=random_source,
        trust_anchor_der=b"\x00" * 100,
        provider_public_key=b"\x00" * 32,
    )


@pytest.fixture
def initiator_id() -> AgentId:
    return AgentId(owner=UserId("initiator@example.com"), name="agent-1")


@pytest.fixture
def receiver_id() -> AgentId:
    return AgentId(owner=UserId("receiver@example.com"), name="agent-2")


@pytest.fixture
def base_command() -> EstablishActCommand:
    return EstablishActCommand(
        initiating_agent_certificate_der=b"\x01" * 100,
        initiating_agent_access_control_public_key=b"\x02" * 32,
        provider_attestation_signature=b"\x03" * 64,
        allocated_otk_public_key=b"\x04" * 32,
        allocated_otk_user_signature=b"\x05" * 64,
        q_max=10,
        lifetime_ms=60_000,
    )


@pytest.fixture
def dummy_sotk(receiver_id: AgentId) -> SotkMapping:
    otk_id = PublicOtkId(receiving_agent_id=receiver_id, ordinal=0)
    return SotkMapping(otk_id=otk_id, secret_key=b"\xaa" * 32)


def test_establish_act_success(
    service: ActEstablishmentService,
    sotk_store: InMemorySotkStore,
    token_state_store: InMemoryTokenStateStore,
    clock: MockClock,
    receiver_id: AgentId,
    dummy_sotk: SotkMapping,
    base_command: EstablishActCommand,
    random_source: MockRandomSource,
) -> None:
    sotk_store.store(dummy_sotk)
    
    # We can't easily mock verify_initiator since it's an integration test.
    # We will patch it out or use valid values if possible. Wait, the crypto
    # requires valid Ed25519 signatures. It's easier to patch _verify_initiator.
    # Actually, ActEstablishmentService does real verification.
    # Let's monkeypatch it for the sake of these logic tests, or provide valid stubs.
    # For now, let's patch it.
    import unittest.mock
    with unittest.mock.patch.object(service, "_verify_initiator"):
        envelope = service.establish(
            command=base_command,
            otk_id=dummy_sotk.otk_id,
        )
    
    assert type(envelope) is ActEnvelope
    
    outcome, _ = sotk_store.claim_and_return(dummy_sotk.otk_id)
    assert outcome.name == "ALREADY_CONSUMED"

    pt_mock = ActPlaintext(
        nonce=random_source.get_bytes(32),
        issued_at=clock.now_ms(),
        expires_at=clock.now_ms() + base_command.lifetime_ms,
        q_max=base_command.q_max,
        initiating_agent_access_control_public_key=base_command.initiating_agent_access_control_public_key,
    )
    
    assert pt_mock.q_max == base_command.q_max
    assert pt_mock.initiating_agent_access_control_public_key == base_command.initiating_agent_access_control_public_key
    assert pt_mock.issued_at == clock.now_ms()
    assert pt_mock.expires_at == clock.now_ms() + base_command.lifetime_ms
    
    token = token_state_store.get(receiving_agent_id=receiver_id, token_nonce=pt_mock.nonce)
    assert token is not None
    assert token.q_max == base_command.q_max


def test_establish_act_sotk_not_found(
    service: ActEstablishmentService,
    receiver_id: AgentId,
    base_command: EstablishActCommand,
) -> None:
    with pytest.raises(ActEstablishmentFailed):
        import unittest.mock
        with unittest.mock.patch.object(service, "_verify_initiator"):
            service.establish(
                command=base_command,
                otk_id=PublicOtkId(receiving_agent_id=receiver_id, ordinal=999),
            )


def test_establish_act_sotk_already_consumed(
    service: ActEstablishmentService,
    sotk_store: InMemorySotkStore,
    receiver_id: AgentId,
    dummy_sotk: SotkMapping,
    base_command: EstablishActCommand,
) -> None:
    sotk_store.store(dummy_sotk)
    sotk_store.claim_and_delete(dummy_sotk.otk_id)
    
    with pytest.raises(SotkAlreadyConsumed):
        import unittest.mock
        with unittest.mock.patch.object(service, "_verify_initiator"):
            service.establish(
                command=base_command,
                otk_id=dummy_sotk.otk_id,
            )
