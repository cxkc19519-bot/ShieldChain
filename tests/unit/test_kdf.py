import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from saga.crypto.kdf import SAGA_HKDF_INFO, KeyDerivationError, derive_sdhk


def test_saga_hkdf_vector_is_fixed() -> None:
    assert SAGA_HKDF_INFO == b"SAGA-ACT-DERIVE/v1"
    assert derive_sdhk(bytes(range(32))).hex() == (
        "43119e861811e97c6a0c43fa93e1b5fbfd672e52875e44d9e672f65ae7e6c3c2"
    )


def test_wrong_info_cannot_match_saga_key() -> None:
    wrong = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SAGA-ACT-DERIVE/v2",
    ).derive(bytes(range(32)))
    assert wrong != derive_sdhk(bytes(range(32)))


class BytesSubclass(bytes):
    pass


class FakeHKDF:
    constructor_behavior: object = None
    derive_behavior: object = b"0" * 32

    def __init__(self, **_: object) -> None:
        if isinstance(self.constructor_behavior, BaseException):
            raise self.constructor_behavior

    def derive(self, _: bytes) -> object:
        if isinstance(self.derive_behavior, BaseException):
            raise self.derive_behavior
        return self.derive_behavior


@pytest.mark.parametrize(
    "shared_secret",
    [
        object(),
        bytearray(range(32)),
        BytesSubclass(range(32)),
        bytes(range(31)),
        bytes(range(33)),
    ],
)
def test_derive_sdhk_requires_exact_plain_bytes32(shared_secret: object) -> None:
    with pytest.raises(KeyDerivationError):
        derive_sdhk(shared_secret)


@pytest.mark.parametrize(
    "stage,error",
    [
        ("constructor", TypeError("backend detail")),
        ("constructor", ValueError("backend detail")),
        ("constructor", UnsupportedAlgorithm("backend detail")),
        ("derive", TypeError("backend detail")),
        ("derive", ValueError("backend detail")),
        ("derive", UnsupportedAlgorithm("backend detail")),
    ],
)
def test_hkdf_ordinary_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, stage: str, error: BaseException
) -> None:
    FakeHKDF.constructor_behavior = error if stage == "constructor" else None
    FakeHKDF.derive_behavior = error if stage == "derive" else b"0" * 32
    monkeypatch.setattr("saga.crypto.kdf.HKDF", FakeHKDF)
    with pytest.raises(KeyDerivationError) as caught:
        derive_sdhk(bytes(range(32)))
    assert str(caught.value) == "key derivation failed"
    assert "backend detail" not in repr(caught.value)


@pytest.mark.parametrize("result", [object(), BytesSubclass(b"0" * 32), b"0" * 31])
def test_hkdf_requires_exact_plain_bytes32_result(
    monkeypatch: pytest.MonkeyPatch, result: object
) -> None:
    FakeHKDF.constructor_behavior = None
    FakeHKDF.derive_behavior = result
    monkeypatch.setattr("saga.crypto.kdf.HKDF", FakeHKDF)
    with pytest.raises(KeyDerivationError, match="^key derivation failed$"):
        derive_sdhk(bytes(range(32)))


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
@pytest.mark.parametrize("stage", ["constructor", "derive"])
def test_hkdf_control_flow_and_resource_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, stage: str, error: BaseException
) -> None:
    FakeHKDF.constructor_behavior = error if stage == "constructor" else None
    FakeHKDF.derive_behavior = error if stage == "derive" else b"0" * 32
    monkeypatch.setattr("saga.crypto.kdf.HKDF", FakeHKDF)
    with pytest.raises(type(error)):
        derive_sdhk(bytes(range(32)))


def test_all_hkdf_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/hkdf-sha256.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    inputs = {"range-00-1f": bytes(range(32))}
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "salt", "info_ascii", "length", "derived_key_hex"}
        assert row["name"] in inputs and row["name"] not in seen
        seen.add(row["name"])
        assert row["salt"] is None
        assert row["info_ascii"] == "SAGA-ACT-DERIVE/v1"
        assert row["length"] == 32
        assert derive_sdhk(inputs[row["name"]]).hex() == row["derived_key_hex"]
    assert seen == set(inputs)
