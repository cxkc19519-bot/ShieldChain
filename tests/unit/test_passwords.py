import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

import saga.crypto
from saga.crypto.passwords import (
    PasswordRecord,
    PasswordRecordError,
    hash_password,
    verify_password,
)

VALID_RECORD = PasswordRecord(1, 2**15, 8, 1, 32, b"0" * 16, b"1" * 32)


def _raising(error: BaseException) -> Callable[[int], bytes]:
    def raise_error(_: int) -> bytes:
        raise error

    return raise_error


class FakeScrypt:
    behavior: object = b"0" * 32

    def __init__(self, **_: object) -> None:
        if isinstance(self.behavior, BaseException):
            raise self.behavior

    def derive(self, _: bytes) -> bytes:
        if isinstance(self.behavior, BaseException):
            raise self.behavior
        return cast(bytes, self.behavior)


def test_scrypt_record_has_exact_baseline_parameters() -> None:
    record = hash_password("correct horse", salt=bytes(range(16)))
    assert record == PasswordRecord(
        version=1,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        salt=bytes(range(16)),
        verifier=bytes.fromhex("5c662628ac4eb1068a287e2aa2a202ae248e98db04d61d3327e7342db6ec7097"),
    )
    assert verify_password("correct horse", record)
    assert not verify_password("wrong", record)


def test_hash_password_uses_fresh_sixteen_byte_random_salt() -> None:
    salts = iter((b"a" * 16, b"b" * 16))
    requested: list[int] = []

    def random_bytes(length: int) -> bytes:
        requested.append(length)
        return next(salts)

    first = hash_password("public-test-password", random_bytes=random_bytes)
    second = hash_password("public-test-password", random_bytes=random_bytes)
    assert requested == [16, 16]
    assert first.salt == b"a" * 16
    assert second.salt == b"b" * 16
    assert first != second


def test_explicit_salt_bypasses_rng_completely() -> None:
    def forbidden_rng(_: int) -> bytes:
        raise AssertionError("rng must not be called")

    record = hash_password("public-test-password", salt=b"0" * 16, random_bytes=forbidden_rng)
    assert record.salt == b"0" * 16


def test_password_record_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        VALID_RECORD.version = 2  # type: ignore[misc]


def test_password_record_repr_redacts_salt_and_verifier() -> None:
    record = hash_password("never-log-me", salt=bytes(range(16)))
    representation = repr(record)
    assert representation == "PasswordRecord(version=1, redacted=True)"
    assert "never-log-me" not in representation
    assert record.salt.hex() not in representation
    assert record.verifier.hex() not in representation


def test_password_api_is_not_reexported_from_saga_crypto() -> None:
    for name in ("PasswordRecord", "PasswordRecordError", "hash_password", "verify_password"):
        assert not hasattr(saga.crypto, name)


def test_password_submodule_defines_exact_public_api() -> None:
    import saga.crypto.passwords as passwords

    assert passwords.__all__ == (
        "PasswordRecord",
        "PasswordRecordError",
        "hash_password",
        "verify_password",
    )


@pytest.mark.parametrize("password", ["", object(), b"password", "\ud800"])
def test_password_input_failures_are_normalized(password: object) -> None:
    with pytest.raises(PasswordRecordError) as caught:
        hash_password(password, salt=b"0" * 16)  # type: ignore[arg-type]
    assert repr(password) not in repr(caught.value)


@pytest.mark.parametrize("salt", [object(), "salt", b"", b"0" * 15, b"0" * 17])
def test_salt_failures_are_normalized(salt: object) -> None:
    with pytest.raises(PasswordRecordError) as caught:
        hash_password("public-test-password", salt=salt)  # type: ignore[arg-type]
    assert repr(salt) not in repr(caught.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"version": True},
        {"version": 2},
        {"n": True},
        {"n": 1},
        {"r": True},
        {"r": 1},
        {"p": True},
        {"p": 2},
        {"dklen": True},
        {"dklen": 31},
        {"salt": "x"},
        {"salt": b"0" * 15},
        {"verifier": "x"},
        {"verifier": b"1" * 31},
    ],
)
def test_malformed_records_fail_before_scrypt(changes: dict[str, object]) -> None:
    with pytest.raises(PasswordRecordError):
        verify_password("public-test-password", replace(VALID_RECORD, **changes))


@pytest.mark.parametrize("record", [object(), None, {"version": 1}])
def test_non_record_inputs_fail_closed(record: object) -> None:
    with pytest.raises(PasswordRecordError):
        verify_password("public-test-password", record)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "rng",
    [
        object(),
        lambda _: "x",
        lambda _: b"0" * 15,
        lambda _: b"0" * 17,
        _raising(TypeError("do-not-log-password")),
        _raising(ValueError("do-not-log-password")),
    ],
)
def test_password_rng_failures_are_normalized(rng: object) -> None:
    with pytest.raises(PasswordRecordError) as caught:
        hash_password("public-test-password", random_bytes=rng)  # type: ignore[arg-type]
    assert "do-not-log-password" not in repr(caught.value)


@pytest.mark.parametrize(
    "behavior",
    [
        TypeError(),
        ValueError(),
        OverflowError(),
        UnsupportedAlgorithm("unsupported"),
        object(),
        b"0" * 31,
    ],
)
def test_hash_scrypt_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, behavior: object
) -> None:
    FakeScrypt.behavior = behavior
    monkeypatch.setattr("saga.crypto.passwords.Scrypt", FakeScrypt)
    with pytest.raises(PasswordRecordError):
        hash_password("public-test-password", salt=b"0" * 16)


@pytest.mark.parametrize(
    "behavior",
    [
        TypeError(),
        ValueError(),
        OverflowError(),
        UnsupportedAlgorithm("unsupported"),
        object(),
        b"0" * 31,
    ],
)
def test_verify_scrypt_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, behavior: object
) -> None:
    FakeScrypt.behavior = behavior
    monkeypatch.setattr("saga.crypto.passwords.Scrypt", FakeScrypt)
    with pytest.raises(PasswordRecordError):
        verify_password("public-test-password", VALID_RECORD)


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_hash_control_flow_and_resource_exceptions_propagate(error: BaseException) -> None:
    with pytest.raises(type(error)):
        hash_password("public-test-password", random_bytes=_raising(error))


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_scrypt_control_flow_and_resource_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    FakeScrypt.behavior = error
    monkeypatch.setattr("saga.crypto.passwords.Scrypt", FakeScrypt)
    with pytest.raises(type(error)):
        hash_password("public-test-password", salt=b"0" * 16)
    with pytest.raises(type(error)):
        verify_password("public-test-password", VALID_RECORD)


def test_verify_uses_constant_time_library_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []

    def compare_digest(candidate: bytes, expected: bytes) -> bool:
        calls.append((candidate, expected))
        return True

    FakeScrypt.behavior = b"2" * 32
    monkeypatch.setattr("saga.crypto.passwords.Scrypt", FakeScrypt)
    monkeypatch.setattr("saga.crypto.passwords.hmac.compare_digest", compare_digest)
    assert verify_password("public-test-password", VALID_RECORD)
    assert calls == [(b"2" * 32, VALID_RECORD.verifier)]


def test_all_scrypt_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/scrypt-records.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    assert document["format_version"] == 1
    passwords = {"correct-horse": "correct horse"}
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {
            "name",
            "version",
            "n",
            "r",
            "p",
            "dklen",
            "salt_hex",
            "verifier_hex",
        }
        name = row["name"]
        assert name in passwords and name not in seen
        seen.add(name)
        expected = PasswordRecord(
            row["version"],
            row["n"],
            row["r"],
            row["p"],
            row["dklen"],
            bytes.fromhex(row["salt_hex"]),
            bytes.fromhex(row["verifier_hex"]),
        )
        assert hash_password(passwords[name], salt=expected.salt) == expected
        assert verify_password(passwords[name], expected)
    assert seen == set(passwords)
