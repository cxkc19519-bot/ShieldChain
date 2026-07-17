"""Paper IV-C Agent-registration protocol evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.adapters.crypto import Ed25519ProviderSigner
from saga.adapters.persistence.memory import InMemoryAgentRegistry, InMemoryUserRegistry
from saga.crypto.canonical import (
    AgentUserAttestation,
    OtkAttestation,
    ProviderAttestation,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from saga.crypto.signatures import ed25519_public_key_bytes, sign, verify
from saga.domain.agents import AgentId, AgentRegistration, RegisterAgentCommand, RegisteredPublicOtk
from saga.domain.encoding import EndpointValue
from saga.domain.errors import (
    AgentEndpointExists,
    AgentIdentifierExists,
    AgentOwnerAuthenticationFailed,
    AgentRegistrationVerificationFailed,
    InvalidRegistrationInput,
)
from saga.domain.users import RegisterUserCommand, UserId, UserRegistration
from saga.protocols.agent_registration import AgentRegistrationService
from saga.protocols.user_registration import UserRegistrationService
from tests.helpers.certificates import NOW_MS, build_certificate_fixtures
from tests.helpers.registration import (
    DeterministicRandomSource,
    FixedClock,
    TrustedIdentityVerifier,
)


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _registered_owner() -> tuple[InMemoryUserRegistry, object]:
    fixtures = build_certificate_fixtures()
    owner = UserId("alice")
    users = InMemoryUserRegistry()
    UserRegistrationService(
        identity_verifier=TrustedIdentityVerifier(frozenset({owner})),
        user_registry=users,
        clock=FixedClock(NOW_MS),
        random_source=DeterministicRandomSource((b"s" * 16,)),
        trust_anchor_der=fixtures.anchor_der,
    ).register(RegisterUserCommand(owner, "owner-password", fixtures.user.der))
    return users, fixtures


def _command(
    fixtures: object,
    *,
    endpoint: EndpointValue | None = None,
    public_otks: tuple[RegisteredPublicOtk, ...] | None = None,
    password: str = "owner-password",  # noqa: S107 - synthetic protocol input
) -> RegisterAgentCommand:
    agent_id = AgentId(UserId("alice"), "worker")
    endpoint = endpoint or EndpointValue("worker-1", "192.0.2.10", 8443)
    provider_public = ed25519_public_key_bytes(_key(3).public_key())
    access_control = bytes(range(32))
    metadata = encode_agent_user_attestation(
        AgentUserAttestation(
            agent_id.value,
            endpoint,
            _key(4).public_key().public_bytes_raw(),
            access_control,
            provider_public,
        )
    )
    otks = public_otks or (
        RegisteredPublicOtk(
            b"o" * 32,
            sign(_key(2), encode_otk_attestation(OtkAttestation(agent_id.value, b"o" * 32))),
        ),
    )
    return RegisterAgentCommand(
        owner_id=UserId("alice"),
        password=password,
        agent_id=agent_id,
        endpoint=endpoint,
        certificate_der=fixtures.agent.der,
        access_control_public_key=access_control,
        contact_policy_document=b'{"opaque":"registered-only"}',
        public_otks=otks,
        user_metadata_signature=sign(_key(2), metadata),
    )


def _service(
    users: InMemoryUserRegistry, fixtures: object, agents: InMemoryAgentRegistry | None = None
) -> AgentRegistrationService:
    return AgentRegistrationService(
        user_registry=users,
        agent_registry=agents or InMemoryAgentRegistry(),
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=Ed25519ProviderSigner(_key(3)),
    )


class _ProviderSignerFailure:
    def __init__(
        self,
        *,
        public_result: object = ed25519_public_key_bytes(_key(3).public_key()),
        sign_result: object = b"s" * 64,
    ) -> None:
        self._public_result = public_result
        self._sign_result = sign_result
        self.sign_calls = 0

    def public_key_bytes(self) -> bytes:
        if isinstance(self._public_result, BaseException):
            raise self._public_result
        return self._public_result  # type: ignore[return-value]

    def sign(self, _: bytes) -> bytes:
        self.sign_calls += 1
        if isinstance(self._sign_result, BaseException):
            raise self._sign_result
        return self._sign_result  # type: ignore[return-value]


class _CapturingProviderSigner(Ed25519ProviderSigner):
    def __init__(self, key: Ed25519PrivateKey) -> None:
        super().__init__(key)
        self.messages: list[bytes] = []

    def sign(self, message: bytes) -> bytes:
        self.messages.append(message)
        return super().sign(message)


def test_iv_c_success_stores_public_record_and_returns_main_text_attestation() -> None:
    users, fixtures = _registered_owner()
    agents = InMemoryAgentRegistry()
    command = _command(fixtures)
    result = _service(users, fixtures, agents).register(command)

    assert result.agent_id == command.agent_id
    stored = agents.get(command.agent_id)
    assert stored == AgentRegistration(
        command.agent_id,
        command.owner_id,
        command.endpoint,
        command.certificate_der,
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    assert "provider_attestation_signature" not in stored.__dataclass_fields__
    verify(
        _key(3).public_key(),
        encode_provider_attestation(
            ProviderAttestation(
                command.agent_id.value,
                command.certificate_der,
                command.endpoint,
                command.access_control_public_key,
                command.user_metadata_signature,
            )
        ),
        result.provider_attestation_signature,
    )


def test_wrong_password_fails_before_agent_validation() -> None:
    users, fixtures = _registered_owner()
    agents = InMemoryAgentRegistry()
    command = _command(fixtures, password="wrong-password")
    command = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        command.endpoint,
        b"not-a-certificate",
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    with pytest.raises(AgentOwnerAuthenticationFailed):
        _service(users, fixtures, agents).register(command)
    assert agents.get(command.agent_id) is None


def test_missing_owner_fails_before_agent_validation_and_storage() -> None:
    fixtures = build_certificate_fixtures()
    agents = InMemoryAgentRegistry()
    command = _command(fixtures)
    command = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        command.endpoint,
        b"not-a-certificate",
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    with pytest.raises(AgentOwnerAuthenticationFailed):
        _service(InMemoryUserRegistry(), fixtures, agents).register(command)
    assert agents.get(command.agent_id) is None


def test_empty_password_is_rejected_as_invalid_command_input() -> None:
    _, fixtures = _registered_owner()
    with pytest.raises(InvalidRegistrationInput):
        _command(fixtures, password="")


def test_owner_and_agent_id_relationship_is_rechecked_before_owner_loading() -> None:
    _, fixtures = _registered_owner()
    command = _command(fixtures)
    object.__setattr__(command, "agent_id", AgentId(UserId("bob"), "worker"))
    with pytest.raises(InvalidRegistrationInput):
        _service(InMemoryUserRegistry(), fixtures).register(command)


def test_invalid_user_signature_or_otk_rejects_entire_registration() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    agents = InMemoryAgentRegistry()
    invalid_metadata = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        command.endpoint,
        command.certificate_der,
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        b"x" * 64,
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures, agents).register(invalid_metadata)
    assert agents.get(command.agent_id) is None
    invalid_otk = RegisteredPublicOtk(command.public_otks[0].public_key, b"x" * 64)
    invalid_otk_command = _command(fixtures, public_otks=(invalid_otk,))
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures, agents).register(invalid_otk_command)
    assert agents.get(command.agent_id) is None


@pytest.mark.parametrize("member", ["endpoint", "agent_key", "access_control", "provider_key"])
def test_each_reachable_user_metadata_tuple_member_mutation_fails(
    member: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    if member == "endpoint":
        command = RegisterAgentCommand(
            command.owner_id,
            command.password,
            command.agent_id,
            EndpointValue("other-device", "192.0.2.99", 8443),
            command.certificate_der,
            command.access_control_public_key,
            command.contact_policy_document,
            command.public_otks,
            command.user_metadata_signature,
        )
    elif member == "access_control":
        command = RegisterAgentCommand(
            command.owner_id,
            command.password,
            command.agent_id,
            command.endpoint,
            command.certificate_der,
            b"z" * 32,
            command.contact_policy_document,
            command.public_otks,
            command.user_metadata_signature,
        )
    elif member == "provider_key":
        with pytest.raises(AgentRegistrationVerificationFailed):
            AgentRegistrationService(
                user_registry=users,
                agent_registry=InMemoryAgentRegistry(),
                clock=FixedClock(NOW_MS),
                trust_anchor_der=fixtures.anchor_der,
                provider_signer=Ed25519ProviderSigner(_key(9)),
            ).register(command)
        return
    else:
        from saga.crypto import certificates

        original = certificates.validated_leaf_public_key_bytes
        calls = 0

        def changed_agent_key(**kwargs: object) -> bytes:
            nonlocal calls
            calls += 1
            result = original(**kwargs)  # type: ignore[arg-type]
            return b"z" * 32 if calls == 2 else result

        monkeypatch.setattr(certificates, "validated_leaf_public_key_bytes", changed_agent_key)
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures).register(command)


def test_otk_value_mutation_and_duplicate_batch_fail_before_storage() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    changed = RegisteredPublicOtk(b"q" * 32, command.public_otks[0].user_signature)
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures).register(_command(fixtures, public_otks=(changed,)))
    with pytest.raises(InvalidRegistrationInput):
        _command(fixtures, public_otks=(command.public_otks[0], command.public_otks[0]))


@pytest.mark.parametrize("case", ["leaf_bad_key_usage", "leaf_wrong_eku"])
def test_agent_certificate_profile_fail_closed(case: str) -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    invalid = RegisterAgentCommand(
        command.owner_id,
        command.password,
        command.agent_id,
        command.endpoint,
        fixtures.negative[case].leaf_der,
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures).register(invalid)


def test_agent_certificate_identity_fail_closed() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    wrong_identity = RegisterAgentCommand(
        command.owner_id,
        command.password,
        AgentId(UserId("alice"), "other-worker"),
        command.endpoint,
        command.certificate_der,
        command.access_control_public_key,
        command.contact_policy_document,
        command.public_otks,
        command.user_metadata_signature,
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures).register(wrong_identity)


def test_certificate_time_failure_is_normalized() -> None:
    users, fixtures = _registered_owner()
    with pytest.raises(AgentRegistrationVerificationFailed):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=InMemoryAgentRegistry(),
            clock=FixedClock(fixtures.negative["expired_leaf"].now_ms),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=Ed25519ProviderSigner(_key(3)),
        ).register(_command(fixtures))


def test_owner_certificate_wrong_profile_fails_closed() -> None:
    users, fixtures = _registered_owner()
    owner = users.get(UserId("alice"))
    assert owner is not None
    users._registrations[owner.user_id] = UserRegistration(
        owner.user_id, owner.password_record, fixtures.agent.der
    )
    with pytest.raises(AgentRegistrationVerificationFailed):
        _service(users, fixtures).register(_command(fixtures))


def test_all_public_otk_vector_records_verify() -> None:
    users, fixtures = _registered_owner()
    records = json.loads(
        (Path(__file__).parents[1] / "vectors" / "registration-records.json").read_text(
            encoding="utf-8"
        )
    )["otk_records"]
    assert records and all(record["agent_id"] == "alice:worker" for record in records)
    otks = tuple(
        RegisteredPublicOtk(
            bytes.fromhex(record["public_key_hex"]), bytes.fromhex(record["user_signature_hex"])
        )
        for record in records
    )
    result = _service(users, fixtures).register(_command(fixtures, public_otks=otks))
    assert result.agent_id.value == "alice:worker"


def test_provider_signer_is_redacted_and_rejects_figure_eight_substitution() -> None:
    users, fixtures = _registered_owner()
    signer = Ed25519ProviderSigner(_key(3))
    assert "private" not in repr(signer).lower()
    command = _command(fixtures)
    result = AgentRegistrationService(
        user_registry=users,
        agent_registry=InMemoryAgentRegistry(),
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=signer,
    ).register(command)
    figure_eight = encode_agent_user_attestation(
        AgentUserAttestation(
            command.agent_id.value,
            command.endpoint,
            _key(4).public_key().public_bytes_raw(),
            command.access_control_public_key,
            signer.public_key_bytes(),
        )
    )
    with pytest.raises(ValueError):
        verify(_key(3).public_key(), figure_eight, result.provider_attestation_signature)


def test_provider_signs_exact_main_text_tuple_and_attestation_is_not_stored() -> None:
    users, fixtures = _registered_owner()
    signer = _CapturingProviderSigner(_key(3))
    command = _command(fixtures)
    result = AgentRegistrationService(
        user_registry=users,
        agent_registry=InMemoryAgentRegistry(),
        clock=FixedClock(NOW_MS),
        trust_anchor_der=fixtures.anchor_der,
        provider_signer=signer,
    ).register(command)
    assert signer.messages == [
        encode_provider_attestation(
            ProviderAttestation(
                command.agent_id.value,
                command.certificate_der,
                command.endpoint,
                command.access_control_public_key,
                command.user_metadata_signature,
            )
        )
    ]
    assert result.provider_attestation_signature.hex() not in repr(result)


@pytest.mark.parametrize("bad_public", ["not-bytes", b"short", RuntimeError("public key failed")])
def test_invalid_provider_public_key_is_one_verification_failure(bad_public: object) -> None:
    users, fixtures = _registered_owner()
    with pytest.raises(AgentRegistrationVerificationFailed):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=InMemoryAgentRegistry(),
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=_ProviderSignerFailure(public_result=bad_public),
        ).register(_command(fixtures))


@pytest.mark.parametrize("bad_signature", ["not-bytes", b"short", RuntimeError("sign failed")])
def test_invalid_or_failing_provider_signing_leaves_no_record(bad_signature: object) -> None:
    users, fixtures = _registered_owner()
    agents = InMemoryAgentRegistry()
    command = _command(fixtures)
    signer = _ProviderSignerFailure(sign_result=bad_signature)
    with pytest.raises(AgentRegistrationVerificationFailed):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=agents,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=signer,
        ).register(command)
    assert signer.sign_calls == 1
    assert agents.get(command.agent_id) is None


def test_64_byte_garbage_provider_signature_is_rejected_after_signing() -> None:
    users, fixtures = _registered_owner()
    agents = InMemoryAgentRegistry()
    signer = _ProviderSignerFailure(sign_result=b"x" * 64)
    command = _command(fixtures)
    with pytest.raises(AgentRegistrationVerificationFailed):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=agents,
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=signer,
        ).register(command)
    assert signer.sign_calls == 1
    assert agents.get(command.agent_id) is None


def test_provider_signature_mutation_is_rejected_against_the_same_provider_key() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    result = _service(users, fixtures).register(command)
    mutated = result.provider_attestation_signature[:-1] + bytes(
        [result.provider_attestation_signature[-1] ^ 1]
    )
    with pytest.raises(ValueError):
        verify(
            _key(3).public_key(),
            encode_provider_attestation(
                ProviderAttestation(
                    command.agent_id.value,
                    command.certificate_der,
                    command.endpoint,
                    command.access_control_public_key,
                    command.user_metadata_signature,
                )
            ),
            mutated,
        )


@pytest.mark.parametrize("exception", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_provider_sign_control_flow_and_resource_exceptions_propagate(
    exception: BaseException,
) -> None:
    users, fixtures = _registered_owner()
    signer = _ProviderSignerFailure(sign_result=exception)
    with pytest.raises(type(exception)):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=InMemoryAgentRegistry(),
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=signer,
        ).register(_command(fixtures))
    assert signer.sign_calls == 1


def test_public_results_errors_and_representations_do_not_leak_registration_secrets() -> None:
    users, fixtures = _registered_owner()
    command = _command(fixtures)
    result = _service(users, fixtures).register(command)
    stored = users.get(UserId("alice"))
    assert stored is not None
    failed = _command(fixtures, password="password-which-must-not-leak")
    with pytest.raises(AgentOwnerAuthenticationFailed) as captured:
        _service(users, fixtures).register(failed)
    rendered = " ".join(
        (repr(command), repr(result), repr(stored), repr(captured.value), str(captured.value))
    )
    for forbidden in (
        "owner-password",
        "password-which-must-not-leak",
        stored.password_record.salt.hex(),
        stored.password_record.verifier.hex(),
        "SOTK",
        "PRIVATE KEY",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize("exception", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_provider_control_flow_and_resource_exceptions_propagate(exception: BaseException) -> None:
    users, fixtures = _registered_owner()
    with pytest.raises(type(exception)):
        AgentRegistrationService(
            user_registry=users,
            agent_registry=InMemoryAgentRegistry(),
            clock=FixedClock(NOW_MS),
            trust_anchor_der=fixtures.anchor_der,
            provider_signer=_ProviderSignerFailure(public_result=exception),
        ).register(_command(fixtures))


def test_agent_identifier_and_endpoint_conflicts_are_distinct_stable_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    users, fixtures = _registered_owner()
    agents = InMemoryAgentRegistry()
    service = _service(users, fixtures, agents)
    command = _command(fixtures)
    service.register(command)
    with pytest.raises(AgentIdentifierExists):
        service.register(command)
    second_id = AgentId(UserId("alice"), "worker-two")
    second_access_control = b"r" * 32
    second_metadata = encode_agent_user_attestation(
        AgentUserAttestation(
            second_id.value,
            command.endpoint,
            _key(4).public_key().public_bytes_raw(),
            second_access_control,
            ed25519_public_key_bytes(_key(3).public_key()),
        )
    )
    endpoint_conflict = RegisterAgentCommand(
        UserId("alice"),
        "owner-password",
        second_id,
        command.endpoint,
        command.certificate_der,
        second_access_control,
        b"opaque",
        (
            RegisteredPublicOtk(
                b"r" * 32,
                sign(_key(2), encode_otk_attestation(OtkAttestation(second_id.value, b"r" * 32))),
            ),
        ),
        sign(_key(2), second_metadata),
    )
    from saga.crypto import certificates

    original = certificates.validated_leaf_public_key_bytes

    def accept_second_agent(**kwargs: object) -> bytes:
        if kwargs["expected_kind"] is certificates.IdentityKind.AGENT:
            return _key(4).public_key().public_bytes_raw()
        return original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(certificates, "validated_leaf_public_key_bytes", accept_second_agent)
    with pytest.raises(AgentEndpointExists):
        service.register(endpoint_conflict)
