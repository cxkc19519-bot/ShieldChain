"""Phase 3 concurrent allocation and management linearization evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import saga.protocols.contact_management as contact_management
from saga.adapters.crypto import Ed25519ProviderSigner
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.adapters.persistence.sqlite import SQLiteAgentRegistry, SQLiteUserRegistry
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import ed25519_public_key_bytes, sign
from saga.domain.agents import AgentId, RegisterAgentCommand, RegisteredPublicOtk
from saga.domain.contact import (
    AppendPublicOtksCommand,
    DeactivateAgentCommand,
    ResolveContactCommand,
    UpdateContactPolicyCommand,
)
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    AgentInactive,
    ConcurrentContactConflict,
    PairBudgetExhausted,
    PublicOtkPoolExhausted,
)
from saga.domain.users import RegisterUserCommand, UserId
from saga.ports.contact_state import ContactCommitOutcome
from saga.protocols.agent_registration import AgentRegistrationService
from saga.protocols.contact_management import ContactManagementService
from saga.protocols.contact_resolution import ContactResolutionService
from saga.protocols.user_registration import UserRegistrationService
from tests.helpers.certificates import NOW_MS, CertificateFixtureSet, build_certificate_fixtures
from tests.helpers.contact_state import run_barrier_workers
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


@dataclass(frozen=True, slots=True)
class ContactBackend:
    agents: object
    users: object
    fixtures: CertificateFixtureSet
    agent_id: AgentId
    provider_public_key: bytes


def make_backend(
    *,
    backend: str,
    policy: bytes,
    public_otk_count: int,
    database: Path | None = None,
) -> ContactBackend:
    """Build the same authenticated registration transcript for both adapters."""
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    if backend == "memory":
        users: object = InMemoryUserRegistry()
        agents: object = InMemoryAgentRegistry()
    elif backend == "sqlite" and database is not None:
        users = SQLiteUserRegistry(database)
        agents = SQLiteAgentRegistry(database)
    else:
        raise ValueError("backend fixture invalid")
    UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({owner})),
        user_registry=users,
        clock=FixedClock(NOW_MS),
        random_source=DeterministicRandomSource((b"s" * 16,)),
        trust_anchor_der=fixtures.anchor_der,
    ).register(RegisterUserCommand(owner, "owner-password", fixtures.user.der))
    agent_id = AgentId(owner, "worker")
    endpoint = EndpointValue("worker-1", "192.0.2.10", 8443)
    provider_public_key = ed25519_public_key_bytes(_key(3).public_key())
    metadata = sign(
        _key(2),
        encode_agent_user_attestation(
            AgentUserAttestation(
                agent_id.value,
                endpoint,
                _key(4).public_key().public_bytes_raw(),
                b"a" * 32,
                provider_public_key,
            )
        ),
    )
    public_otks = tuple(
        RegisteredPublicOtk(
            bytes([ordinal + 1]) * 32,
            sign(
                _key(2),
                encode_otk_attestation(OtkAttestation(agent_id.value, bytes([ordinal + 1]) * 32)),
            ),
        )
        for ordinal in range(public_otk_count)
    )
    AgentRegistrationService(
        user_registry=users,
        agent_registry=agents,
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=Ed25519ProviderSigner(_key(3)),
    ).register(
        RegisterAgentCommand(
            owner,
            "owner-password",
            agent_id,
            endpoint,
            fixtures.agent.der,
            b"a" * 32,
            policy,
            public_otks,
            metadata,
        )
    )
    return ContactBackend(agents, users, fixtures, agent_id, provider_public_key)


def _resolution(backend: ContactBackend) -> ContactResolutionService:
    return ContactResolutionService(
        contact_state_store=backend.agents,  # type: ignore[arg-type]
        user_registry=backend.users,  # type: ignore[arg-type]
    )


def _management(backend: ContactBackend) -> ContactManagementService:
    return ContactManagementService(
        contact_state_store=backend.agents,  # type: ignore[arg-type]
        user_registry=backend.users,  # type: ignore[arg-type]
        clock=FixedClock(NOW_MS),
        trust_anchor_der=backend.fixtures.anchor_der,
    )


def _snapshot(backend: ContactBackend):  # type: ignore[no-untyped-def]
    return backend.agents.read_snapshot(  # type: ignore[union-attr]
        receiving_agent_id=backend.agent_id, initiating_agent_id=backend.agent_id
    )


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
@pytest.mark.parametrize("participants", (2, 8, 32))
@pytest.mark.parametrize(
    ("public_otk_count", "budget", "loser", "available_after", "remaining_after"),
    (
        (1, 2, PublicOtkPoolExhausted, 0, 1),
        (2, 1, PairBudgetExhausted, 1, 0),
        (1, 1, PairBudgetExhausted, 0, 0),
    ),
)
def test_last_resource_races_have_one_winner_and_no_partial_loser_mutation(
    tmp_path: Path,
    backend: str,
    participants: int,
    public_otk_count: int,
    budget: int,
    loser: type[Exception],
    available_after: int,
    remaining_after: int,
) -> None:
    state = make_backend(
        backend=backend,
        database=tmp_path / f"{backend}-{participants}-{budget}.sqlite3",
        policy=(
            b'{"version":1,"rules":[{"kind":"global","budget":' + str(budget).encode() + b"}]}"
        ),
        public_otk_count=public_otk_count,
    )
    command = ResolveContactCommand(state.agent_id, state.agent_id)

    def contender() -> object:
        try:
            return _resolution(state).resolve(command)
        except Exception as error:  # test transcript intentionally records closed outcomes
            return error

    results = run_barrier_workers(participants, contender)
    winners = tuple(result for result in results if not isinstance(result, Exception))
    failures = tuple(result for result in results if isinstance(result, Exception))

    assert len(winners) == 1
    assert all(isinstance(result, (loser, ConcurrentContactConflict)) for result in failures)
    after = _snapshot(state)
    assert len(after.available_public_otks) == available_after
    assert after.pair_counter is not None and after.pair_counter.remaining == remaining_after
    assert after.otk_pool_revision == 1


class _FirstManagementConflict:
    """Force one CAS loss so each management path proves its fresh retry."""

    def __init__(self, inner: object, method: str) -> None:
        self._inner = inner
        self._method = method
        self.calls = 0

    def read_snapshot(self, **kwargs):  # type: ignore[no-untyped-def]
        return self._inner.read_snapshot(**kwargs)

    def try_commit(self, command):  # type: ignore[no-untyped-def]
        return self._inner.try_commit(command)

    def replace_policy(self, command):  # type: ignore[no-untyped-def]
        return self._call("replace_policy", command)

    def append_otks(self, command):  # type: ignore[no-untyped-def]
        return self._call("append_otks", command)

    def deactivate(self, command):  # type: ignore[no-untyped-def]
        return self._call("deactivate", command)

    def _call(self, method, command):  # type: ignore[no-untyped-def]
        if method == self._method:
            self.calls += 1
            if self.calls == 1:
                return ContactCommitOutcome.CONFLICT
        return getattr(self._inner, method)(command)


class _CountingUsers:
    """Observe the owner lookup that must be repeated after every CAS loss."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.get_calls = 0

    def get(self, user_id):  # type: ignore[no-untyped-def]
        self.get_calls += 1
        return self._inner.get(user_id)

    def create_if_absent(self, registration):  # type: ignore[no-untyped-def]
        return self._inner.create_if_absent(registration)


@pytest.mark.parametrize("method", ("replace_policy", "append_otks", "deactivate"))
def test_each_management_operation_reauthenticates_and_retries_one_cas_conflict(
    method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = make_backend(
        backend="memory",
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    retrying = _FirstManagementConflict(backend.agents, method)
    counted_users = _CountingUsers(backend.users)
    password_calls = 0
    signature_calls = 0
    original_password_verify = contact_management.verify_password
    original_signature_verify = contact_management.verify

    def counted_password(password, record):  # type: ignore[no-untyped-def]
        nonlocal password_calls
        password_calls += 1
        return original_password_verify(password, record)

    def counted_signature(public_key, message, signature):  # type: ignore[no-untyped-def]
        nonlocal signature_calls
        signature_calls += 1
        return original_signature_verify(public_key, message, signature)

    monkeypatch.setattr(contact_management, "verify_password", counted_password)
    monkeypatch.setattr(contact_management, "verify", counted_signature)
    service = ContactManagementService(
        contact_state_store=retrying,
        user_registry=counted_users,  # type: ignore[arg-type]
        clock=FixedClock(NOW_MS),
        trust_anchor_der=backend.fixtures.anchor_der,
    )
    if method == "replace_policy":
        service.replace_policy(
            UpdateContactPolicyCommand(
                backend.agent_id.owner,
                "owner-password",
                backend.agent_id,
                b'{"version":1,"rules":[{"kind":"global","budget":-1}]}',
            )
        )
    elif method == "append_otks":
        key = b"z" * 32
        public_otk = RegisteredPublicOtk(
            key,
            sign(_key(2), encode_otk_attestation(OtkAttestation(backend.agent_id.value, key))),
        )
        service.append_public_otks(
            AppendPublicOtksCommand(
                backend.agent_id.owner, "owner-password", backend.agent_id, (public_otk,)
            )
        )
    else:
        service.deactivate(
            DeactivateAgentCommand(backend.agent_id.owner, "owner-password", backend.agent_id)
        )
    assert retrying.calls == 2
    assert counted_users.get_calls == 2
    assert password_calls == 2
    assert signature_calls == (2 if method == "append_otks" else 0)


@pytest.mark.parametrize("backend", ("memory", "sqlite"))
def test_policy_update_and_deactivation_race_leaves_one_coherent_latest_state(
    tmp_path: Path, backend: str
) -> None:
    state = make_backend(
        backend=backend,
        database=tmp_path / f"{backend}-management-race.sqlite3",
        policy=b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        public_otk_count=2,
    )
    service = _management(state)
    replacement = b'{"version":1,"rules":[{"kind":"global","budget":-1}]}'

    def replace() -> object:
        try:
            service.replace_policy(
                UpdateContactPolicyCommand(
                    state.agent_id.owner, "owner-password", state.agent_id, replacement
                )
            )
            return None
        except Exception as error:
            return error

    def deactivate() -> object:
        try:
            service.deactivate(
                DeactivateAgentCommand(state.agent_id.owner, "owner-password", state.agent_id)
            )
            return None
        except Exception as error:
            return error

    # The barrier is deliberately at the call boundary; each service then performs CAS retries.
    from threading import Barrier, Thread

    barrier = Barrier(2)
    results: list[object | None] = [None, None]

    def call(index: int, operation):  # type: ignore[no-untyped-def]
        barrier.wait(timeout=10)
        results[index] = operation()

    threads = (Thread(target=call, args=(0, replace)), Thread(target=call, args=(1, deactivate)))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert not any(thread.is_alive() for thread in threads)
    assert results.count(None) >= 1
    assert all(result is None or isinstance(result, AgentInactive) for result in results)
    after = _snapshot(state)
    assert after.receiving_active is False
    assert after.contact_policy_document in {
        b'{"version":1,"rules":[{"kind":"global","budget":2}]}',
        replacement,
    }
