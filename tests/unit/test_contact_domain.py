import pytest

from saga.domain import (
    AgentId,
    AppendPublicOtksCommand,
    AvailablePublicOtk,
    ContactBundle,
    ContactCommit,
    ContactSnapshot,
    DeactivateAgentCommand,
    InvalidContactInput,
    PairCounter,
    PublicOtkId,
    RegisteredPublicOtk,
    ResolveContactCommand,
    UpdateContactPolicyCommand,
    UserId,
)
from saga.domain.agents import AgentRegistration
from saga.domain.encoding import EndpointValue


def _agent(owner: str, name: str) -> AgentId:
    return AgentId(owner=UserId(owner), name=name)


def _otk() -> AvailablePublicOtk:
    agent = _agent("receiver", "service")
    return AvailablePublicOtk(
        otk_id=PublicOtkId(receiving_agent_id=agent, ordinal=0),
        public_key=b"k" * 32,
        user_signature=b"s" * 64,
    )


def _registration(agent: AgentId) -> AgentRegistration:
    return AgentRegistration(
        agent_id=agent,
        owner_id=agent.owner,
        endpoint=EndpointValue("device", "192.0.2.1", 8443),
        certificate_der=b"certificate",
        access_control_public_key=b"k" * 32,
        contact_policy_document=b"legacy",
        public_otks=(RegisteredPublicOtk(public_key=b"o" * 32, user_signature=b"s" * 64),),
        user_metadata_signature=b"m" * 64,
    )


def test_public_otk_ids_and_counters_require_non_negative_plain_integers() -> None:
    agent = _agent("receiver", "service")
    for bad in (-1, True, 1.0):
        with pytest.raises(InvalidContactInput):
            PublicOtkId(receiving_agent_id=agent, ordinal=bad)
        with pytest.raises(InvalidContactInput):
            PairCounter(
                receiving_agent_id=agent,
                initiating_agent_id=_agent("initiator", "worker"),
                remaining=bad,
                revision=0,
            )


def test_contact_commands_are_secret_safe_in_repr() -> None:
    receiver = _agent("receiver", "service")
    initiator = _agent("initiator", "worker")
    commands = (
        ResolveContactCommand(receiving_agent_id=receiver, initiating_agent_id=initiator),
        UpdateContactPolicyCommand(
            owner_id=UserId("receiver"),
            password="secret-password",
            agent_id=receiver,
            contact_policy_document=b'{"version":1,"rules":[{"kind":"global","budget":1}]}',
        ),
        AppendPublicOtksCommand(
            owner_id=UserId("receiver"),
            password="secret-password",
            agent_id=receiver,
            public_otks=(RegisteredPublicOtk(public_key=b"k" * 32, user_signature=b"s" * 64),),
        ),
        DeactivateAgentCommand(
            owner_id=UserId("receiver"), password="secret-password", agent_id=receiver
        ),
    )
    for command in commands:
        assert "secret-password" not in repr(command)
        assert "redacted=True" in repr(command)


def test_snapshot_requires_ordered_available_otks_for_its_receiving_agent() -> None:
    valid = ContactSnapshot(
        receiving_registration=None,
        initiating_registration=None,
        receiving_active=True,
        agent_revision=0,
        contact_policy_document=b"legacy",
        policy_version=0,
        pair_counter=None,
        available_public_otks=(_otk(),),
        otk_pool_revision=0,
    )
    assert valid.available_public_otks[0].otk_id.ordinal == 0
    with pytest.raises(InvalidContactInput):
        ContactSnapshot(
            receiving_registration=None,
            initiating_registration=None,
            receiving_active=True,
            agent_revision=0,
            contact_policy_document=b"legacy",
            policy_version=0,
            pair_counter=None,
            available_public_otks=(_otk(), _otk()),
            otk_pool_revision=0,
        )


def test_bundle_redacts_certificate_and_signatures() -> None:
    receiver = _agent("receiver", "service")
    bundle = ContactBundle(
        receiving_user_certificate_der=b"certificate",
        receiving_agent_id=receiver,
        receiving_endpoint=None,
        receiving_agent_certificate_der=b"agent-certificate",
        receiving_access_control_public_key=b"k" * 32,
        public_otk=_otk(),
    )
    assert "certificate" not in repr(bundle)


def test_commit_counter_must_describe_the_same_agent_pair() -> None:
    receiver = _agent("receiver", "service")
    initiator = _agent("initiator", "worker")
    selected = PublicOtkId(receiving_agent_id=receiver, ordinal=0)
    for counter in (
        PairCounter(
            receiving_agent_id=_agent("other", "service"),
            initiating_agent_id=initiator,
            remaining=1,
            revision=0,
        ),
        PairCounter(
            receiving_agent_id=receiver,
            initiating_agent_id=_agent("other", "worker"),
            remaining=1,
            revision=0,
        ),
    ):
        with pytest.raises(InvalidContactInput):
            ContactCommit(
                receiving_agent_id=receiver,
                initiating_agent_id=initiator,
                selected_public_otk_id=selected,
                remaining=0,
                expected_agent_revision=0,
                expected_active=True,
                expected_policy_version=0,
                expected_counter=counter,
                expected_otk_pool_revision=0,
            )


def test_snapshot_counter_must_describe_its_registered_agent_pair() -> None:
    receiver = _agent("receiver", "service")
    initiator = _agent("initiator", "worker")
    for counter in (
        PairCounter(
            receiving_agent_id=initiator,
            initiating_agent_id=receiver,
            remaining=1,
            revision=0,
        ),
        PairCounter(
            receiving_agent_id=_agent("other", "service"),
            initiating_agent_id=initiator,
            remaining=1,
            revision=0,
        ),
    ):
        with pytest.raises(InvalidContactInput):
            ContactSnapshot(
                receiving_registration=_registration(receiver),
                initiating_registration=_registration(initiator),
                receiving_active=True,
                agent_revision=0,
                contact_policy_document=b"legacy",
                policy_version=0,
                pair_counter=counter,
                available_public_otks=(_otk(),),
                otk_pool_revision=0,
            )
