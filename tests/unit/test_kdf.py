import json
from pathlib import Path

import pytest
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
