"""Integration tests for the full ACT lifecycle."""

from __future__ import annotations

import pytest

from saga.adapters.persistence.memory import InMemorySotkStore, InMemoryTokenStateStore
from saga.domain.act import (
    EstablishActCommand,
    UseActCommand,
)
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    ActExpired,
    ActQuotaExhausted,
    SotkAlreadyConsumed,
)
from saga.domain.otk import PublicOtkId
from saga.domain.token_state import SotkMapping
from saga.domain.users import UserId
from saga.ports.clock import Clock
from saga.ports.random import RandomSource
from saga.protocols.act_establishment import ActEstablishmentService
from saga.protocols.act_use import ActUseService


class MockClock(Clock):
    def __init__(self, time_ms: int = 1_000_000) -> None:
        self._time = time_ms

    def now_ms(self) -> int:
        return self._time

    def advance(self, ms: int) -> None:
        self._time += ms


class MockRandomSource(RandomSource):
    def get_bytes(self, num_bytes: int) -> bytes:
        return b"\xaa" * num_bytes
        
    def get_int(self, max_exclusive: int) -> int:
        return 0
        
    def bytes(self, count: int) -> bytes:
        return b"\xaa" * count


@pytest.fixture
def clock() -> MockClock:
    return MockClock()


@pytest.fixture
def random_source() -> MockRandomSource:
    return MockRandomSource()


@pytest.fixture
def sotk_store() -> InMemorySotkStore:
    return InMemorySotkStore()


@pytest.fixture
def token_state_store() -> InMemoryTokenStateStore:
    return InMemoryTokenStateStore()


@pytest.fixture
def receiver_id() -> AgentId:
    return AgentId(owner=UserId("receiver@example.com"), name="agent-a")


@pytest.fixture
def receiver_registration(receiver_id: AgentId) -> AgentRegistration:
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
def establishment_service(
    clock: MockClock,
    sotk_store: InMemorySotkStore,
    token_state_store: InMemoryTokenStateStore,
    random_source: MockRandomSource,
    receiver_id: AgentId,
    receiver_registration: AgentRegistration,
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
def use_service(
    clock: MockClock,
    token_state_store: InMemoryTokenStateStore,
    receiver_id: AgentId,
) -> ActUseService:
    return ActUseService(
        receiving_agent_id=receiver_id,
        token_state_store=token_state_store,
        clock=clock,
    )


def test_full_lifecycle_success(
    establishment_service: ActEstablishmentService,
    use_service: ActUseService,
    sotk_store: InMemorySotkStore,
    clock: MockClock,
    receiver_id: AgentId,
) -> None:
    # 1. Provide an SOTK
    sotk = SotkMapping(
        otk_id=PublicOtkId(receiving_agent_id=receiver_id, ordinal=10),
        secret_key=b"\xbb" * 32,
    )
    sotk_store.store(sotk)
    
    # 2. Establish ACT
    command = EstablishActCommand(
        initiating_agent_certificate_der=b"\x01" * 150,
        initiating_agent_access_control_public_key=b"\x02" * 32,
        provider_attestation_signature=b"\x03" * 64,
        allocated_otk_public_key=b"\x04" * 32,
        allocated_otk_user_signature=b"\x05" * 64,
        q_max=3,
        lifetime_ms=60_000,
    )
    
    import unittest.mock
    with unittest.mock.patch.object(establishment_service, "_verify_initiator"):
        envelope = establishment_service.establish(command=command, otk_id=sotk.otk_id)
        
    # SOTK should be consumed
    with pytest.raises(SotkAlreadyConsumed):
        with unittest.mock.patch.object(establishment_service, "_verify_initiator"):
            establishment_service.establish(command=command, otk_id=sotk.otk_id)
            
    # 3. Use ACT successfully
    use_command = UseActCommand(
        envelope=envelope,
        initiating_agent_access_control_public_key=command.initiating_agent_access_control_public_key,
    )
    
    result = use_service.use(command=use_command)
    assert result.use_count == 1
    
    result = use_service.use(command=use_command)
    assert result.use_count == 2
    
    result = use_service.use(command=use_command)
    assert result.use_count == 3
    
    # 4. Quota Exhausted
    with pytest.raises(ActQuotaExhausted):
        use_service.use(command=use_command)
        
    # 5. Expiration handling (even if quota exhausted, time advances)
    clock.advance(60_001)
    with pytest.raises(ActExpired):
        use_service.use(command=use_command)
