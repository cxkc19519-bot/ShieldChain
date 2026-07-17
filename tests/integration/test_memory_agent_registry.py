"""Atomicity evidence for the in-memory Agent Registry."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from saga.adapters.persistence.memory import InMemoryAgentRegistry
from saga.domain.agents import AgentId, AgentRegistration, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.users import UserId
from saga.ports.transactions import AgentCreateOutcome


class _FailingEndpointIndex(dict[tuple[str, str, int], AgentId]):
    def __init__(self) -> None:
        super().__init__()
        self._failed = False

    def __setitem__(self, key: tuple[str, str, int], value: AgentId) -> None:
        if not self._failed:
            self._failed = True
            raise MemoryError("injected endpoint-index write failure")
        super().__setitem__(key, value)


def _registration(name: str, endpoint: EndpointValue) -> AgentRegistration:
    owner = UserId("alice")
    return AgentRegistration(
        AgentId(owner, name),
        owner,
        endpoint,
        b"cert",
        b"a" * 32,
        b"opaque",
        (RegisteredPublicOtk(b"o" * 32, b"s" * 64),),
        b"m" * 64,
    )


def test_agent_id_conflict_wins_over_endpoint_conflict() -> None:
    registry = InMemoryAgentRegistry()
    registration = _registration("worker", EndpointValue("device", "192.0.2.1", 8443))
    assert registry.create_if_unique(registration) is AgentCreateOutcome.CREATED
    assert registry.create_if_unique(registration) is AgentCreateOutcome.AGENT_ID_CONFLICT


def test_concurrent_same_endpoint_has_exactly_one_winner() -> None:
    registry = InMemoryAgentRegistry()
    endpoint = EndpointValue("device", "192.0.2.1", 8443)
    registrations = [_registration(f"worker-{index}", endpoint) for index in range(20)]
    with ThreadPoolExecutor(max_workers=20) as executor:
        outcomes = list(executor.map(registry.create_if_unique, registrations))
    assert outcomes.count(AgentCreateOutcome.CREATED) == 1
    assert outcomes.count(AgentCreateOutcome.ENDPOINT_CONFLICT) == 19


def test_concurrent_same_agent_id_has_exactly_one_winner() -> None:
    registry = InMemoryAgentRegistry()
    registrations = [
        _registration("worker", EndpointValue(f"device-{index}", f"192.0.2.{index + 1}", 8443))
        for index in range(20)
    ]
    with ThreadPoolExecutor(max_workers=20) as executor:
        outcomes = list(executor.map(registry.create_if_unique, registrations))
    assert outcomes.count(AgentCreateOutcome.CREATED) == 1
    assert outcomes.count(AgentCreateOutcome.AGENT_ID_CONFLICT) == 19


def test_insert_failure_is_rolled_back_before_memory_error_propagates() -> None:
    registry = InMemoryAgentRegistry()
    registration = _registration("worker", EndpointValue("device", "192.0.2.1", 8443))
    registry._agent_ids_by_endpoint = _FailingEndpointIndex()

    try:
        registry.create_if_unique(registration)
    except MemoryError:
        pass
    else:
        raise AssertionError("injected MemoryError did not propagate")

    assert registry.get(registration.agent_id) is None
    assert (
        registry.create_if_unique(_registration("other", registration.endpoint))
        is AgentCreateOutcome.CREATED
    )
