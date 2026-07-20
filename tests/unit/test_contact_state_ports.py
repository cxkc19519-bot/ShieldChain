import inspect
from dataclasses import fields
from enum import StrEnum
from typing import get_type_hints

from saga.domain import (
    AgentId,
    AgentRegistration,
    ContactCommit,
    ContactSnapshot,
    EndpointValue,
    PairCounter,
    PublicOtkId,
    RegisteredPublicOtk,
    UserId,
)
from saga.ports import (
    ContactCommitOutcome,
    ContactStateStore,
    DeactivateCommit,
    OtkAppendCommit,
    PolicyReplaceCommit,
)
from tests.helpers.contact_state import (
    BarrierConflictContactStateStore,
    ConflictContactStateStore,
    PolicyBlindContactStateStore,
)


def _agent(owner: str, name: str) -> AgentId:
    return AgentId(owner=UserId(owner), name=name)


def _registration(agent_id: AgentId) -> AgentRegistration:
    return AgentRegistration(
        agent_id=agent_id,
        owner_id=agent_id.owner,
        endpoint=EndpointValue("device", "192.0.2.1", 8443),
        certificate_der=b"certificate",
        access_control_public_key=b"a" * 32,
        contact_policy_document=b"legacy policy bytes",
        public_otks=(RegisteredPublicOtk(public_key=b"k" * 32, user_signature=b"s" * 64),),
        user_metadata_signature=b"m" * 64,
    )


def _snapshot() -> ContactSnapshot:
    receiver = _agent("receiver", "service")
    initiator = _agent("initiator", "worker")
    return ContactSnapshot(
        receiving_registration=_registration(receiver),
        initiating_registration=_registration(initiator),
        receiving_active=True,
        agent_revision=4,
        contact_policy_document=b"legacy policy bytes",
        policy_version=2,
        pair_counter=PairCounter(
            receiving_agent_id=receiver,
            initiating_agent_id=initiator,
            remaining=3,
            revision=7,
        ),
        available_public_otks=(),
        otk_pool_revision=5,
    )


def _contact_commit(snapshot: ContactSnapshot) -> ContactCommit:
    assert snapshot.receiving_registration is not None
    assert snapshot.initiating_registration is not None
    return ContactCommit(
        receiving_agent_id=snapshot.receiving_registration.agent_id,
        initiating_agent_id=snapshot.initiating_registration.agent_id,
        selected_public_otk_id=PublicOtkId(
            receiving_agent_id=snapshot.receiving_registration.agent_id,
            ordinal=0,
        ),
        remaining=2,
        expected_agent_revision=snapshot.agent_revision,
        expected_active=snapshot.receiving_active,
        expected_policy_version=snapshot.policy_version,
        expected_counter=snapshot.pair_counter,
        expected_otk_pool_revision=snapshot.otk_pool_revision,
    )


def _policy_replace(snapshot: ContactSnapshot) -> PolicyReplaceCommit:
    assert snapshot.receiving_registration is not None
    return PolicyReplaceCommit(
        receiving_agent_id=snapshot.receiving_registration.agent_id,
        contact_policy_document=b"legacy policy bytes",
        expected_agent_revision=snapshot.agent_revision,
        expected_active=snapshot.receiving_active,
        expected_policy_version=snapshot.policy_version,
    )


def _otk_append(snapshot: ContactSnapshot) -> OtkAppendCommit:
    assert snapshot.receiving_registration is not None
    return OtkAppendCommit(
        receiving_agent_id=snapshot.receiving_registration.agent_id,
        public_otks=(RegisteredPublicOtk(public_key=b"n" * 32, user_signature=b"z" * 64),),
        expected_agent_revision=snapshot.agent_revision,
        expected_active=snapshot.receiving_active,
        expected_otk_pool_revision=snapshot.otk_pool_revision,
    )


def _deactivate(snapshot: ContactSnapshot) -> DeactivateCommit:
    assert snapshot.receiving_registration is not None
    return DeactivateCommit(
        receiving_agent_id=snapshot.receiving_registration.agent_id,
        expected_agent_revision=snapshot.agent_revision,
        expected_active=snapshot.receiving_active,
    )


class StructuralContactStatePort:
    def __init__(self, snapshot: ContactSnapshot) -> None:
        self.snapshot = snapshot

    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot:
        del receiving_agent_id, initiating_agent_id
        return self.snapshot

    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome:
        del command
        return ContactCommitOutcome.CONFLICT

    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome:
        del command
        return ContactCommitOutcome.CONFLICT

    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome:
        del command
        return ContactCommitOutcome.CONFLICT

    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome:
        del command
        return ContactCommitOutcome.CONFLICT


def test_contact_state_port_has_the_exact_runtime_protocol_surface() -> None:
    assert isinstance(StructuralContactStatePort(_snapshot()), ContactStateStore)
    methods = {
        "read_snapshot": ["self", "receiving_agent_id", "initiating_agent_id"],
        "try_commit": ["self", "command"],
        "replace_policy": ["self", "command"],
        "append_otks": ["self", "command"],
        "deactivate": ["self", "command"],
    }
    public_names = {
        name
        for name, value in vars(ContactStateStore).items()
        if not name.startswith("_") and callable(value)
    }
    assert public_names == set(methods)
    for name, parameters in methods.items():
        signature = inspect.signature(getattr(ContactStateStore, name))
        assert list(signature.parameters) == parameters
    assert list(inspect.signature(ContactStateStore.read_snapshot).parameters.values())[1].kind is (
        inspect.Parameter.KEYWORD_ONLY
    )


def test_port_annotations_commands_and_outcomes_are_exact_and_closed() -> None:
    assert get_type_hints(ContactStateStore.read_snapshot) == {
        "receiving_agent_id": AgentId,
        "initiating_agent_id": AgentId,
        "return": ContactSnapshot,
    }
    assert get_type_hints(ContactStateStore.try_commit) == {
        "command": ContactCommit,
        "return": ContactCommitOutcome,
    }
    assert get_type_hints(ContactStateStore.replace_policy) == {
        "command": PolicyReplaceCommit,
        "return": ContactCommitOutcome,
    }
    assert get_type_hints(ContactStateStore.append_otks) == {
        "command": OtkAppendCommit,
        "return": ContactCommitOutcome,
    }
    assert get_type_hints(ContactStateStore.deactivate) == {
        "command": DeactivateCommit,
        "return": ContactCommitOutcome,
    }
    assert issubclass(ContactCommitOutcome, StrEnum)
    assert [(item.name, item.value) for item in ContactCommitOutcome] == [
        ("COMMITTED", "committed"),
        ("CONFLICT", "conflict"),
    ]
    assert tuple(field.name for field in fields(PolicyReplaceCommit)) == (
        "receiving_agent_id",
        "contact_policy_document",
        "expected_agent_revision",
        "expected_active",
        "expected_policy_version",
    )
    assert tuple(field.name for field in fields(OtkAppendCommit)) == (
        "receiving_agent_id",
        "public_otks",
        "expected_agent_revision",
        "expected_active",
        "expected_otk_pool_revision",
    )
    assert tuple(field.name for field in fields(DeactivateCommit)) == (
        "receiving_agent_id",
        "expected_agent_revision",
        "expected_active",
    )


def test_conflicting_structural_commits_report_conflict_and_preserve_every_value() -> None:
    snapshot = _snapshot()
    store = ConflictContactStateStore(snapshot)
    commands = (
        _contact_commit(snapshot),
        _policy_replace(snapshot),
        _otk_append(snapshot),
        _deactivate(snapshot),
    )
    outcomes = (
        store.try_commit(commands[0]),
        store.replace_policy(commands[1]),
        store.append_otks(commands[2]),
        store.deactivate(commands[3]),
    )
    assert outcomes == (ContactCommitOutcome.CONFLICT,) * 4
    assert store.snapshot == snapshot
    assert store.commands == commands


def test_deterministic_barrier_releases_conflicting_writers_without_sleep() -> None:
    snapshot = _snapshot()
    store = BarrierConflictContactStateStore(snapshot, participants=2)
    outcomes = store.run_two(lambda: store.try_commit(_contact_commit(snapshot)))
    assert outcomes == (ContactCommitOutcome.CONFLICT, ContactCommitOutcome.CONFLICT)
    assert store.snapshot == snapshot
    assert store.commands == (_contact_commit(snapshot), _contact_commit(snapshot))


def test_persistence_fixture_is_policy_blind_and_accepts_opaque_legacy_bytes() -> None:
    snapshot = _snapshot()
    store = PolicyBlindContactStateStore(snapshot)
    command = _policy_replace(snapshot)
    assert store.replace_policy(command) is ContactCommitOutcome.COMMITTED
    assert store.last_policy_document == b"legacy policy bytes"
    assert store.policy_match_attempts == 0
