# SAGA Phase 1 Canonical Serialization and Cryptographic Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the deterministic serialization and mature-library cryptographic primitives required by the paper-defined SAGA tuples, without implementing any protocol state machine or service behavior.

**Architecture:** `saga.domain.encoding` owns schema-safe scalar and endpoint values without importing a cryptographic library. `saga.crypto` owns canonical tuple bytes and narrow wrappers around `cryptography`; later protocol phases consume only its typed public interfaces. Every primitive is introduced by a failing unit/vector test, exposes stable fail-closed exceptions, and has no persistence, HTTP, policy, quota, or ACT lifecycle responsibility.

**Tech Stack:** CPython `>=3.11,<3.15` (implementation host: 3.14.4), `cryptography==49.0.0`, `pytest==9.1.1`, `mypy==2.2.0`, `ruff==0.15.20`, standard-library `json`, `base64`, `dataclasses`, and `datetime`; setuptools build backend and an isolated `.venv` created with `venv`/`pip`.

## Global Constraints

- The paper protocol text remains normative; concrete algorithms and serialization are reproduction engineering supplements recorded in `docs/feature-source-matrix.md`.
- ACT plaintext remains exactly `nonce`, `issued_at`, `expires_at`, `q_max`, and `initiating_agent_access_control_public_key`; `version` belongs only to an outer envelope.
- Use Ed25519 for User/Provider signatures, X25519 for access-control and OTK keys, HKDF-SHA256 with `salt=None` and `info=b"SAGA-ACT-DERIVE/v1"`, and ChaCha20-Poly1305 with `aad=b"SAGA-ACT/v1"`.
- Use scrypt with `N=2**15`, `r=8`, `p=1`, `dkLen=32`, and a fresh 16-byte cryptographically secure salt.
- Security times are non-negative integer Unix milliseconds; booleans and floats are rejected even though Python treats `bool` as an `int` subtype.
- Binary values use strict, unpadded Base64URL; decoding rejects padding, whitespace, non-URL-safe alphabet characters, non-canonical encodings, and non-string inputs.
- Canonical JSON uses UTF-8, schema-fixed field order, compact separators, `ensure_ascii=False`, no unknown/duplicate fields, and no floating-point security values.
- Never implement a cryptographic primitive directly. All signing, key agreement, KDF, AEAD, scrypt, and X.509 operations must delegate to `cryptography` or the Python standard library where explicitly stated.
- Operational/non-public secrets, real passwords, derived runtime keys, real ACT plaintext, and private keys must never appear in exceptions, `repr`, logs, vectors, or fixtures. Published RFC inputs and obviously synthetic test-only private inputs/passwords may appear only in `tests/**/*.py`; JSON vectors contain public expected outputs and public protocol bytes only, never private inputs or password text.
- Phase 1 creates no `protocols`, `ports`, `adapters`, database, FastAPI route, TLS listener, Contact Policy, OTK allocator, Token state, quota counter, or network credential deployment.
- Dependency installation is an external network action: request approval before `pip install`; never weaken tests or change pinned versions merely to make installation easier.
- Each task uses red-green TDD, receives a fresh implementer and reviewer, ends with a focused commit, and must leave the worktree clean.

---

## File and Interface Map

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata, exact dependencies, pytest/mypy/ruff configuration. |
| `requirements.lock` | Sorted exact constraints for constrained same-platform environment reconstruction. |
| `src/saga/domain/encoding.py` | Strict Base64URL, Unix-millisecond validation, immutable endpoint value. |
| `src/saga/crypto/canonical.py` | Duplicate-aware canonical JSON and exact paper-tuple serializers/parsers. |
| `src/saga/crypto/signatures.py` | Ed25519 key generation, raw public-key export, signing, verification. |
| `src/saga/crypto/key_agreement.py` | X25519 key generation, raw public-key export, shared-secret derivation. |
| `src/saga/crypto/kdf.py` | Fixed SAGA HKDF-SHA256 derivation. |
| `src/saga/crypto/aead.py` | Versioned outer ACT envelope and fixed-AAD ChaCha20-Poly1305 wrapper. |
| `src/saga/crypto/passwords.py` | Versioned scrypt record creation and constant-time verification. |
| `src/saga/crypto/certificates.py` | X.509 DER loading, trust-anchor signature, validity, identity URI, and public-key binding checks. |
| `src/saga/crypto/__init__.py` | Stable Phase 1 public exports only. |
| `tests/helpers/certificates.py` | Build all positive and negative X.509 fixtures in memory from published synthetic test seeds. |
| `tests/unit/test_*.py` | Focused red-green unit and tamper tests. |
| `tests/vectors/*.json` | Public-only deterministic vectors; no private keys, passwords, salts tied to real users, or plaintext secrets. |
| `docs/phase-1-verification.md` | Ten-part Phase 1 evidence report created only after implementation and review. |

Stable exception hierarchy:

```python
class EncodingError(ValueError):
    """A public value is not in the single accepted encoding."""

class CanonicalEncodingError(EncodingError):
    """A JSON object does not match its closed canonical schema."""

class SignatureError(ValueError):
    """A signature input or verification is invalid."""

class KeyAgreementError(ValueError):
    """An X25519 input or exchange is invalid."""

class KeyDerivationError(ValueError):
    """A SAGA KDF input is invalid."""

class AeadError(ValueError):
    """An ACT envelope is invalid or unauthentic."""

class PasswordRecordError(ValueError):
    """A password record is malformed."""

class CertificateValidationError(ValueError):
    """A certificate fails the closed SAGA validation profile."""
```

No exception message may include rejected bytes or secret values. Later phases branch on exception type, not message text.

---

### Task 1: Bootstrap the Typed Python Package and Reproducible Toolchain

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.lock`
- Create: `src/saga/__init__.py`
- Create: `src/saga/domain/__init__.py`
- Create: `src/saga/crypto/__init__.py`
- Create: `tests/unit/test_package_boundary.py`

**Interfaces:**
- Consumes: none.
- Produces: importable `saga`, `saga.domain`, and `saga.crypto` packages; the test/lint/type-check commands used by every later task.

- [ ] **Step 1: Create the isolated environment and install the approved toolchain**

Dependency installation is the only external-network action in this task. Obtain explicit approval, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade "pip==26.0.1"
.\.venv\Scripts\python.exe -m pip install "setuptools==80.9.0" "cryptography==49.0.0" "pytest==9.1.1" "mypy==2.2.0" "ruff==0.15.20"
```

Expected: every command exits 0. No test has been written or run before the environment and tools exist.

- [ ] **Step 2: Write the failing package-boundary test**

```python
from importlib.util import find_spec
from pathlib import Path


def test_phase_one_package_exists_without_forbidden_layers() -> None:
    assert find_spec("saga") is not None
    assert find_spec("saga.domain") is not None
    assert find_spec("saga.crypto") is not None
    for forbidden in ("protocols", "ports", "adapters"):
        assert not Path("src", "saga", forbidden).exists()
```

- [ ] **Step 3: Run the test and observe the expected red state**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_package_boundary.py -q`

Expected: FAIL because the `saga` package does not exist.

- [ ] **Step 4: Add exact package and tool configuration**

Create `pyproject.toml` with this complete configuration:

```toml
[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "saga-reproduction"
version = "0.1.0"
description = "Independent reproduction of the base SAGA protocol"
requires-python = ">=3.11,<3.15"
dependencies = ["cryptography==49.0.0"]

[project.optional-dependencies]
dev = [
  "mypy==2.2.0",
  "pytest==9.1.1",
  "ruff==0.15.20",
]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
addopts = "--strict-config --strict-markers"
testpaths = ["tests"]

[tool.mypy]
python_version = "3.11"
strict = true
packages = ["saga"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E4", "E7", "E9", "F", "B", "I", "S", "UP"]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "S105", "S106"]
```

Each package `__init__.py` contains only a module docstring and `__all__: tuple[str, ...] = ()` until a later task deliberately exports an interface.

- [ ] **Step 5: Generate a consumable exact lock and prove rebuild semantics**

The first approved environment produces the lock. `pip freeze --all --exclude-editable` contains no editable workspace path; normalize names/order by case-insensitive sorting:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pip freeze --all --exclude-editable |
  Sort-Object -CaseSensitive:$false |
  Set-Content -Encoding utf8 requirements.lock
.\.venv\Scripts\python.exe -m pip install --constraint requirements.lock -e ".[dev]"
```

Expected: both commands exit 0. This is an exact constraints snapshot for constrained same-platform reconstruction, not a hash-verified or content-addressed lock. It has only `name==version`/marker lines, no local path, and each direct dependency once. Rebuild with the pinned pip plus `--constraint requirements.lock`; never regenerate first.

- [ ] **Step 6: Run the green package and tool gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_package_boundary.py -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: pytest exits 0 with zero failures; mypy and both Ruff commands exit 0. Do not predeclare a suite-wide test count that has not yet been observed.

- [ ] **Step 7: Commit the bootstrap**

```powershell
git add pyproject.toml requirements.lock src/saga tests/unit/test_package_boundary.py
git commit -m "build: bootstrap SAGA cryptographic core"
```

---

### Task 2: Strict Encoding Values and Canonical JSON Engine

**Files:**
- Create: `src/saga/domain/encoding.py`
- Create: `src/saga/crypto/canonical.py`
- Create: `tests/unit/test_encoding.py`
- Create: `tests/unit/test_canonical.py`

**Interfaces:**
- Consumes: Task 1 package/tool configuration.
- Produces: `EncodingError`, `EndpointValue`, `b64url_encode`, `b64url_decode`, `require_unix_ms`, `CanonicalEncodingError`, `FieldSpec`, `canonical_object_bytes`, and `parse_canonical_object`.

- [ ] **Step 1: Write failing strict-encoding tests**

```python
import pytest

from saga.domain.encoding import (
    EncodingError,
    EndpointValue,
    b64url_decode,
    b64url_encode,
    require_unix_ms,
)


def test_unpadded_base64url_round_trip() -> None:
    assert b64url_encode(b"\xfb\xff\x00") == "-_8A"
    assert b64url_decode("-_8A") == b"\xfb\xff\x00"
    assert b64url_encode(b"") == ""
    assert b64url_decode("") == b""


@pytest.mark.parametrize("value", ["-_8A=", "-_8A\n", "+/8A", "-_8*", "A"])
def test_base64url_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(EncodingError, match="invalid Base64URL"):
        b64url_decode(value)


@pytest.mark.parametrize("value", [-1, True, False, 1.0, "1", None])
def test_unix_milliseconds_are_nonnegative_plain_integers(value: object) -> None:
    with pytest.raises(EncodingError, match="invalid Unix milliseconds"):
        require_unix_ms(value, "issued_at")


def test_endpoint_is_immutable_and_validated() -> None:
    endpoint = EndpointValue(device="worker-1", ip="192.0.2.10", port=8443)
    assert endpoint.as_canonical_value() == {
        "device": "worker-1",
        "ip": "192.0.2.10",
        "port": 8443,
    }


@pytest.mark.parametrize("ip", ["example.com", "192.168.001.1", "2001:0db8::1"])
def test_endpoint_accepts_only_canonical_ip_literals(ip: str) -> None:
    with pytest.raises(EncodingError, match="invalid endpoint"):
        EndpointValue(device="worker-1", ip=ip, port=8443)
```

- [ ] **Step 2: Write failing duplicate/unknown/order canonical tests**

```python
import pytest

from saga.crypto.canonical import (
    CanonicalEncodingError,
    FieldSpec,
    canonical_object_bytes,
    parse_canonical_object,
)

SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("issued_at", "unix_ms"),
    FieldSpec("public_key", "bytes"),
)


def test_canonical_bytes_are_ordered_compact_utf8() -> None:
    encoded = canonical_object_bytes(
        {"public_key": b"\x00\xff", "issued_at": 7, "agent_id": "代理-A"},
        SCHEMA,
    )
    assert encoded == (
        b'{"agent_id":"\xe4\xbb\xa3\xe7\x90\x86-A","issued_at":7,'
        b'"public_key":"AP8"}'
    )
    assert canonical_object_bytes(parse_canonical_object(encoded, SCHEMA), SCHEMA) == encoded


@pytest.mark.parametrize(
    "payload",
    [
        b'{"agent_id":"a","agent_id":"b","issued_at":7,"public_key":"AA"}',
        b'{"agent_id":"a","issued_at":7,"public_key":"AA","extra":1}',
        b'{"issued_at":7,"agent_id":"a","public_key":"AA"}',
        b'{"agent_id":"a","issued_at":7.0,"public_key":"AA"}',
        b'{"agent_id":"a","issued_at":true,"public_key":"AA"}',
        b'[]',
        b'{"agent_id":"a","issued_at":7,"public_key":0}',
    ],
)
def test_parser_rejects_duplicates_unknowns_wrong_order_and_float(payload: bytes) -> None:
    with pytest.raises(CanonicalEncodingError):
        parse_canonical_object(payload, SCHEMA)


def test_encoder_accepts_unordered_mapping_but_emits_schema_order() -> None:
    values = {"public_key": b"\x00", "agent_id": "a", "issued_at": 7}
    assert tuple(values) != tuple(field.name for field in SCHEMA)
    assert canonical_object_bytes(values, SCHEMA) == (
        b'{"agent_id":"a","issued_at":7,"public_key":"AA"}'
    )
```

- [ ] **Step 3: Run the focused tests and confirm the red state**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_encoding.py tests/unit/test_canonical.py -q`

Expected: collection fails because the interfaces are not implemented.

- [ ] **Step 4: Implement the minimal strict value layer**

`encoding.py` must define a frozen `EndpointValue` dataclass and the exact signatures:

Use this complete, Ruff-sorted import block at the top of `encoding.py`:

```python
import base64
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
```

```python
class EncodingError(ValueError):
    """A public value is not in the single accepted encoding."""


@dataclass(frozen=True, slots=True)
class EndpointValue:
    device: str
    ip: str
    port: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.device, str)
            or not self.device
            or any(unicodedata.category(c) == "Cc" for c in self.device)
        ):
            raise EncodingError("invalid endpoint")
        if not isinstance(self.ip, str) or not self.ip:
            raise EncodingError("invalid endpoint")
        try:
            parsed_ip = ipaddress.ip_address(self.ip)
        except ValueError:
            raise EncodingError("invalid endpoint") from None
        if parsed_ip.compressed != self.ip:
            raise EncodingError("invalid endpoint")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise EncodingError("invalid endpoint")

    def as_canonical_value(self) -> dict[str, str | int]:
        return {"device": self.device, "ip": self.ip, "port": self.port}


def b64url_encode(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise EncodingError("invalid binary value")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise EncodingError("invalid Base64URL")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise EncodingError("invalid Base64URL") from None
    if b64url_encode(decoded) != value:
        raise EncodingError("invalid Base64URL")
    return decoded


def require_unix_ms(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EncodingError("invalid Unix milliseconds")
    return value
```

The test table includes every Unicode `Cc` representative `"\x00"`, `"\x7f"`, and `"\u0085"`; each is rejected in device and later in canonical text/identity values. IP validation also rejects `%` zone identifiers before `ipaddress.ip_address`. Empty bytes have the unique encoding `""`; decode always re-encodes before returning.

- [ ] **Step 5: Implement duplicate-aware canonical JSON**

Create `canonical.py` with this single final implementation; no later step overrides it:

```python
import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeGuard

from saga.domain.encoding import (
    EncodingError,
    EndpointValue,
    b64url_decode,
    b64url_encode,
    require_unix_ms,
)


class CanonicalEncodingError(EncodingError):
    """A JSON object does not match its closed canonical schema."""


CanonicalKind = Literal["text", "integer", "unix_ms", "bytes", "endpoint"]
CanonicalDecodedValue = str | int | bytes | EndpointValue


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    kind: CanonicalKind


class _ObjectPairs(list[tuple[str, object]]):
    """Duplicate-preserving marker for a JSON object, distinct from arrays."""


def _pairs_hook(items: list[tuple[str, object]]) -> _ObjectPairs:
    return _ObjectPairs(items)


def _valid_text(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(unicodedata.category(c) == "Cc" for c in value)
    )


def _encode_value(value: object, kind: CanonicalKind) -> object:
    if kind == "text":
        if not _valid_text(value):
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "integer":
        if type(value) is not int:
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "unix_ms":
        try:
            return require_unix_ms(value, "canonical time")
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "bytes":
        if type(value) is not bytes:
            raise CanonicalEncodingError("canonical value invalid")
        try:
            return b64url_encode(value)
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "endpoint":
        if not isinstance(value, EndpointValue):
            raise CanonicalEncodingError("canonical value invalid")
        return value.as_canonical_value()
    raise CanonicalEncodingError("canonical schema invalid")


def _decode_endpoint(value: object) -> EndpointValue:
    if not isinstance(value, _ObjectPairs):
        raise CanonicalEncodingError("canonical value invalid")
    names = tuple(name for name, _ in value)
    if names != ("device", "ip", "port") or len(set(names)) != 3:
        raise CanonicalEncodingError("canonical value invalid")
    device, ip, port = (item for _, item in value)
    if not _valid_text(device) or not isinstance(ip, str) or type(port) is not int:
        raise CanonicalEncodingError("canonical value invalid")
    try:
        return EndpointValue(device=device, ip=ip, port=port)
    except EncodingError:
        raise CanonicalEncodingError("canonical value invalid") from None


def _decode_value(value: object, kind: CanonicalKind) -> CanonicalDecodedValue:
    if kind == "text":
        if not _valid_text(value):
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "integer":
        if type(value) is not int:
            raise CanonicalEncodingError("canonical value invalid")
        return value
    if kind == "unix_ms":
        try:
            return require_unix_ms(value, "canonical time")
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "bytes":
        if not isinstance(value, str):
            raise CanonicalEncodingError("canonical value invalid")
        try:
            return b64url_decode(value)
        except EncodingError:
            raise CanonicalEncodingError("canonical value invalid") from None
    if kind == "endpoint":
        return _decode_endpoint(value)
    raise CanonicalEncodingError("canonical schema invalid")


def canonical_object_bytes(
    values: Mapping[str, object], schema: tuple[FieldSpec, ...]
) -> bytes:
    try:
        expected = tuple(field.name for field in schema)
        if (
            len(set(expected)) != len(expected)
            or len(values) != len(expected)
            or set(values.keys()) != set(expected)
        ):
            raise CanonicalEncodingError("canonical fields invalid")
        encoded = {field.name: _encode_value(values[field.name], field.kind) for field in schema}
        return json.dumps(
            encoded, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("canonical JSON invalid") from None


def parse_canonical_object(
    data: bytes, schema: tuple[FieldSpec, ...]
) -> dict[str, CanonicalDecodedValue]:
    try:
        if not isinstance(data, bytes):
            raise CanonicalEncodingError("canonical JSON invalid")
        pairs = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_hook)
        if not isinstance(pairs, _ObjectPairs):
            raise CanonicalEncodingError("canonical JSON invalid")
        names = tuple(name for name, _ in pairs)
        expected = tuple(field.name for field in schema)
        if names != expected or len(set(names)) != len(names):
            raise CanonicalEncodingError("canonical fields invalid")
        result = {
            field.name: _decode_value(raw, field.kind)
            for field, (_, raw) in zip(schema, pairs, strict=True)
        }
        if canonical_object_bytes(result, schema) != data:
            raise CanonicalEncodingError("canonical JSON invalid")
        return result
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("canonical JSON invalid") from None
```

```python
ENDPOINT_SCHEMA = (FieldSpec("endpoint", "endpoint"),)


@pytest.mark.parametrize(
    ("payload", "schema"),
    [
        (b"[]", SCHEMA), (b'"x"', SCHEMA), (b"1", SCHEMA), (b"null", SCHEMA),
        (b'{"agent_id":"a","agent_id":"b","issued_at":1,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1,"public_key":"AA","x":0}', SCHEMA),
        (b'{"issued_at":1,"agent_id":"a","public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":true,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1.0,"public_key":"AA"}', SCHEMA),
        (b'{"agent_id":"a","issued_at":1,"public_key":"AA="}', SCHEMA),
        (b'{"endpoint":{"device":"d","device":"e","ip":"192.0.2.1","port":1}}', ENDPOINT_SCHEMA),
        (b'{"endpoint":{"ip":"192.0.2.1","device":"d","port":1}}', ENDPOINT_SCHEMA),
        (b'{"endpoint":{"device":"d","ip":"192.0.2.1","port":1,"x":0}}', ENDPOINT_SCHEMA),
        (b'{"endpoint":{"device":"d","ip":"192.0.2.1","port":true}}', ENDPOINT_SCHEMA),
        (b"\xff", SCHEMA),
    ],
)
def test_all_canonical_negative_cases(payload: bytes, schema: tuple[FieldSpec, ...]) -> None:
    with pytest.raises(CanonicalEncodingError):
        parse_canonical_object(payload, schema)


@pytest.mark.parametrize("control", ["\x00", "\x7f", "\u0085"])
def test_all_unicode_cc_text_is_rejected(control: str) -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_object_bytes({"agent_id": f"a{control}", "issued_at": 1, "public_key": b""}, SCHEMA)
```

- [ ] **Step 6: Run focused and static gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_encoding.py tests/unit/test_canonical.py -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: focused tests exit 0 with zero failures; mypy and both Ruff commands exit 0.

- [ ] **Step 7: Commit strict canonical encoding**

```powershell
git add src/saga/domain/encoding.py src/saga/crypto/canonical.py tests/unit/test_encoding.py tests/unit/test_canonical.py
git commit -m "feat: add strict canonical encoding"
```

---

### Task 3: Exact Paper-Tuple Serializers and Public Vectors

**Files:**
- Modify: `src/saga/crypto/canonical.py`
- Create: `tests/unit/test_protocol_tuples.py`
- Create: `tests/vectors/canonical-tuples.json`

**Interfaces:**
- Consumes: `EndpointValue`, canonical encoding engine.
- Produces: four frozen tuple dataclasses, four schema constants, and eight typed encode/decode functions for the exact User Agent, OTK, Provider, and ACT tuples.

- [ ] **Step 1: Write failing exact-field tests**

```python
import json
from pathlib import Path

import pytest

from saga.crypto.canonical import (
    ACT_PLAINTEXT_SCHEMA,
    AGENT_USER_ATTESTATION_SCHEMA,
    OTK_ATTESTATION_SCHEMA,
    PROVIDER_ATTESTATION_SCHEMA,
    ActPlaintext,
    AgentUserAttestation,
    CanonicalEncodingError,
    OtkAttestation,
    ProviderAttestation,
    decode_act_plaintext,
    decode_agent_user_attestation,
    decode_otk_attestation,
    decode_provider_attestation,
    encode_act_plaintext,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from saga.domain.encoding import EndpointValue, b64url_decode


def test_paper_tuple_field_orders_are_exact() -> None:
    assert tuple(field.name for field in AGENT_USER_ATTESTATION_SCHEMA) == (
        "agent_id",
        "endpoint",
        "agent_tls_public_key",
        "agent_access_control_public_key",
        "provider_public_key",
    )
    assert tuple(field.name for field in OTK_ATTESTATION_SCHEMA) == (
        "agent_id",
        "one_time_public_key",
    )
    assert tuple(field.name for field in PROVIDER_ATTESTATION_SCHEMA) == (
        "agent_id",
        "agent_certificate",
        "endpoint",
        "agent_access_control_public_key",
        "user_signature",
    )
    assert tuple(field.name for field in ACT_PLAINTEXT_SCHEMA) == (
        "nonce",
        "issued_at",
        "expires_at",
        "q_max",
        "initiating_agent_access_control_public_key",
    )
```

- [ ] **Step 2: Write failing vector and mutation tests**

The exact four public records use synthetic IDs, RFC 5737 documentation addresses, deterministic public bytes, and no private keys. Their initial byte-exact assertion is:

```python
def test_public_act_vector_is_byte_exact() -> None:
    value = ActPlaintext(
        nonce=bytes(range(16)), issued_at=1, expires_at=2, q_max=3,
        initiating_agent_access_control_public_key=bytes(range(32)),
    )
    encoded = encode_act_plaintext(value)
    expected = bytes.fromhex(
        "7b226e6f6e6365223a2241414543417751464267634943516f4c4441304f4477222c"
        "226973737565645f6174223a312c22657870697265735f6174223a322c22715f6d61"
        "78223a332c22696e6974696174696e675f6167656e745f6163636573735f636f6e74"
        "726f6c5f7075626c69635f6b6579223a2241414543417751464267634943516f4c44"
        "41304f4478415245684d554652595847426b6147787764486838227d"
    )
    assert encoded == expected
    assert encode_act_plaintext(value) == expected


def test_act_has_no_outer_or_future_extension_fields() -> None:
    forbidden = {
        "version", "token_id", "issuer_agent_id", "subject_agent_id", "task_id",
        "protocol_context_hash", "tool", "action", "parameters", "resource",
    }
    assert forbidden.isdisjoint(field.name for field in ACT_PLAINTEXT_SCHEMA)
```

The exact vector file and loader are in Step 5. This mutation test runs every parser through delete/add/swap/wrong-type/duplicate wire cases:

```python
def test_every_tuple_rejects_all_structural_mutations() -> None:
    document = json.loads(Path("tests/vectors/canonical-tuples.json").read_text("utf-8"))
    decoders = {
        "agent_user": decode_agent_user_attestation,
        "otk": decode_otk_attestation,
        "provider": decode_provider_attestation,
        "act": decode_act_plaintext,
    }
    for row in document["vectors"]:
        raw = bytes.fromhex(row["canonical_utf8_hex"])
        root = json.loads(raw)
        assert isinstance(root, dict)
        pairs = list(root.items())
        deleted = pairs[1:]
        added = [*pairs, ("unexpected", 0)]
        swapped = [pairs[1], pairs[0], *pairs[2:]]
        wrong_type = [(pairs[0][0], True), *pairs[1:]]
        duplicate = [pairs[0], pairs[0], *pairs[1:]]
        for changed in (deleted, added, swapped, wrong_type, duplicate):
            payload = ("{" + ",".join(
                f"{json.dumps(name)}:{json.dumps(value, separators=(',', ':'))}"
                for name, value in changed
            ) + "}").encode()
            with pytest.raises(CanonicalEncodingError):
                decoders[row["tuple_kind"]](payload)
```

- [ ] **Step 3: Run the tuple tests and observe red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_protocol_tuples.py -q`

Expected: FAIL because schemas and tuple functions are absent.

- [ ] **Step 4: Add typed tuple functions without protocol state**

Append this complete implementation to `canonical.py`:

```python
AGENT_USER_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("endpoint", "endpoint"),
    FieldSpec("agent_tls_public_key", "bytes"),
    FieldSpec("agent_access_control_public_key", "bytes"),
    FieldSpec("provider_public_key", "bytes"),
)
OTK_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("one_time_public_key", "bytes"),
)
PROVIDER_ATTESTATION_SCHEMA = (
    FieldSpec("agent_id", "text"),
    FieldSpec("agent_certificate", "bytes"),
    FieldSpec("endpoint", "endpoint"),
    FieldSpec("agent_access_control_public_key", "bytes"),
    FieldSpec("user_signature", "bytes"),
)
ACT_PLAINTEXT_SCHEMA = (
    FieldSpec("nonce", "bytes"),
    FieldSpec("issued_at", "unix_ms"),
    FieldSpec("expires_at", "unix_ms"),
    FieldSpec("q_max", "integer"),
    FieldSpec("initiating_agent_access_control_public_key", "bytes"),
)


@dataclass(frozen=True, slots=True)
class AgentUserAttestation:
    agent_id: str
    endpoint: EndpointValue
    agent_tls_public_key: bytes
    agent_access_control_public_key: bytes
    provider_public_key: bytes


@dataclass(frozen=True, slots=True)
class OtkAttestation:
    agent_id: str
    one_time_public_key: bytes


@dataclass(frozen=True, slots=True)
class ProviderAttestation:
    agent_id: str
    agent_certificate: bytes
    endpoint: EndpointValue
    agent_access_control_public_key: bytes
    user_signature: bytes


@dataclass(frozen=True, slots=True)
class ActPlaintext:
    nonce: bytes
    issued_at: int
    expires_at: int
    q_max: int
    initiating_agent_access_control_public_key: bytes


def _tuple_text(value: object) -> str:
    if not _valid_text(value):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_bytes(value: object, length: int | None = None) -> bytes:
    if type(value) is not bytes or not value:
        raise CanonicalEncodingError("protocol tuple invalid")
    if length is not None and len(value) != length:
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_endpoint(value: object) -> EndpointValue:
    if not isinstance(value, EndpointValue):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def _tuple_int(value: object, *, unix_ms: bool = False) -> int:
    if type(value) is not int or (unix_ms and value < 0):
        raise CanonicalEncodingError("protocol tuple invalid")
    return value


def encode_agent_user_attestation(value: AgentUserAttestation) -> bytes:
    try:
        if not isinstance(value, AgentUserAttestation):
            raise CanonicalEncodingError("protocol tuple invalid")
        fields: dict[str, object] = {
            "agent_id": _tuple_text(value.agent_id),
            "endpoint": _tuple_endpoint(value.endpoint),
            "agent_tls_public_key": _tuple_bytes(value.agent_tls_public_key),
            "agent_access_control_public_key": _tuple_bytes(
                value.agent_access_control_public_key, 32
            ),
            "provider_public_key": _tuple_bytes(value.provider_public_key, 32),
        }
        return canonical_object_bytes(fields, AGENT_USER_ATTESTATION_SCHEMA)
    except CanonicalEncodingError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise CanonicalEncodingError("protocol tuple invalid") from None


def decode_agent_user_attestation(data: bytes) -> AgentUserAttestation:
    try:
        values = parse_canonical_object(data, AGENT_USER_ATTESTATION_SCHEMA)
        return AgentUserAttestation(
            agent_id=_tuple_text(values["agent_id"]),
            endpoint=_tuple_endpoint(values["endpoint"]),
            agent_tls_public_key=_tuple_bytes(values["agent_tls_public_key"]),
            agent_access_control_public_key=_tuple_bytes(
                values["agent_access_control_public_key"], 32
            ),
            provider_public_key=_tuple_bytes(values["provider_public_key"], 32),
        )
    except CanonicalEncodingError:
        raise
    except (KeyError, TypeError, ValueError):
        raise CanonicalEncodingError("protocol tuple invalid") from None


def encode_otk_attestation(value: OtkAttestation) -> bytes:
    if not isinstance(value, OtkAttestation):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "agent_id": _tuple_text(value.agent_id),
            "one_time_public_key": _tuple_bytes(value.one_time_public_key, 32),
        },
        OTK_ATTESTATION_SCHEMA,
    )


def decode_otk_attestation(data: bytes) -> OtkAttestation:
    values = parse_canonical_object(data, OTK_ATTESTATION_SCHEMA)
    return OtkAttestation(
        agent_id=_tuple_text(values["agent_id"]),
        one_time_public_key=_tuple_bytes(values["one_time_public_key"], 32),
    )


def encode_provider_attestation(value: ProviderAttestation) -> bytes:
    if not isinstance(value, ProviderAttestation):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "agent_id": _tuple_text(value.agent_id),
            "agent_certificate": _tuple_bytes(value.agent_certificate),
            "endpoint": _tuple_endpoint(value.endpoint),
            "agent_access_control_public_key": _tuple_bytes(
                value.agent_access_control_public_key, 32
            ),
            "user_signature": _tuple_bytes(value.user_signature, 64),
        },
        PROVIDER_ATTESTATION_SCHEMA,
    )


def decode_provider_attestation(data: bytes) -> ProviderAttestation:
    values = parse_canonical_object(data, PROVIDER_ATTESTATION_SCHEMA)
    return ProviderAttestation(
        agent_id=_tuple_text(values["agent_id"]),
        agent_certificate=_tuple_bytes(values["agent_certificate"]),
        endpoint=_tuple_endpoint(values["endpoint"]),
        agent_access_control_public_key=_tuple_bytes(
            values["agent_access_control_public_key"], 32
        ),
        user_signature=_tuple_bytes(values["user_signature"], 64),
    )


def encode_act_plaintext(value: ActPlaintext) -> bytes:
    if not isinstance(value, ActPlaintext):
        raise CanonicalEncodingError("protocol tuple invalid")
    return canonical_object_bytes(
        {
            "nonce": _tuple_bytes(value.nonce),
            "issued_at": _tuple_int(value.issued_at, unix_ms=True),
            "expires_at": _tuple_int(value.expires_at, unix_ms=True),
            "q_max": _tuple_int(value.q_max),
            "initiating_agent_access_control_public_key": _tuple_bytes(
                value.initiating_agent_access_control_public_key, 32
            ),
        },
        ACT_PLAINTEXT_SCHEMA,
    )


def decode_act_plaintext(data: bytes) -> ActPlaintext:
    values = parse_canonical_object(data, ACT_PLAINTEXT_SCHEMA)
    return ActPlaintext(
        nonce=_tuple_bytes(values["nonce"]),
        issued_at=_tuple_int(values["issued_at"], unix_ms=True),
        expires_at=_tuple_int(values["expires_at"], unix_ms=True),
        q_max=_tuple_int(values["q_max"]),
        initiating_agent_access_control_public_key=_tuple_bytes(
            values["initiating_agent_access_control_public_key"], 32
        ),
    )
```

Representation is layered: `PK_Prov`, PAC, and OTK are raw 32-byte keys and signatures are raw 64 bytes. At the Task 3 tuple-encoding layer, `agent_tls_public_key` and `agent_certificate` are opaque non-empty bytes only; this layer makes no DER-validity claim. Task 9 alone parses and validates SPKI DER/certificate DER at the certificate boundary. `q_max` remains structural only; Phase 4 owns lifecycle semantics.

- [ ] **Step 5: Write and load the checked-in public vector file**

The exact file is the compact JSON object below. Byte values use only the tagged Base64URL object and endpoints use only the three-key object shown:

```json
{"format_version":1,"vectors":[{"name":"agent_user","tuple_kind":"agent_user","canonical_utf8_hex":"7b226167656e745f6964223a22616c6963653a776f726b6572222c22656e64706f696e74223a7b22646576696365223a22776f726b65722d31222c226970223a223139322e302e322e3130222c22706f7274223a383434337d2c226167656e745f746c735f7075626c69635f6b6579223a224d414541222c226167656e745f6163636573735f636f6e74726f6c5f7075626c69635f6b6579223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c2270726f76696465725f7075626c69635f6b6579223a22494345694979516c4a69636f4b536f724c4330754c7a41784d6a4d304e5459334f446b364f7a7739506a38227d","decoded_public_values":{"agent_id":"alice:worker","endpoint":{"device":"worker-1","ip":"192.0.2.10","port":8443},"agent_tls_public_key":{"encoding":"base64url","value":"MAEA"},"agent_access_control_public_key":{"encoding":"base64url","value":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},"provider_public_key":{"encoding":"base64url","value":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"}}},{"name":"otk","tuple_kind":"otk","canonical_utf8_hex":"7b226167656e745f6964223a22616c6963653a776f726b6572222c226f6e655f74696d655f7075626c69635f6b6579223a225145464351305246526b64495355704c5445314f54314252556c4e5556565a5857466c6157317864586c38227d","decoded_public_values":{"agent_id":"alice:worker","one_time_public_key":{"encoding":"base64url","value":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8"}}},{"name":"provider","tuple_kind":"provider","canonical_utf8_hex":"7b226167656e745f6964223a22616c6963653a776f726b6572222c226167656e745f6365727469666963617465223a224d414541222c22656e64706f696e74223a7b22646576696365223a22776f726b65722d31222c226970223a223139322e302e322e3130222c22706f7274223a383434337d2c226167656e745f6163636573735f636f6e74726f6c5f7075626c69635f6b6579223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838222c22757365725f7369676e6174757265223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838674953496a4a43556d4a7967704b6973734c5334764d4445794d7a51314e6a63344f546f375044302d5077227d","decoded_public_values":{"agent_id":"alice:worker","agent_certificate":{"encoding":"base64url","value":"MAEA"},"endpoint":{"device":"worker-1","ip":"192.0.2.10","port":8443},"agent_access_control_public_key":{"encoding":"base64url","value":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},"user_signature":{"encoding":"base64url","value":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"}}},{"name":"act","tuple_kind":"act","canonical_utf8_hex":"7b226e6f6e6365223a2241414543417751464267634943516f4c4441304f4477222c226973737565645f6174223a312c22657870697265735f6174223a322c22715f6d6178223a332c22696e6974696174696e675f6167656e745f6163636573735f636f6e74726f6c5f7075626c69635f6b6579223a2241414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838227d","decoded_public_values":{"nonce":{"encoding":"base64url","value":"AAECAwQFBgcICQoLDA0ODw"},"issued_at":1,"expires_at":2,"q_max":3,"initiating_agent_access_control_public_key":{"encoding":"base64url","value":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}}}]}
```

```python
def _tagged_bytes(value: object) -> bytes:
    assert isinstance(value, dict)
    assert set(value) == {"encoding", "value"}
    assert value["encoding"] == "base64url"
    assert isinstance(value["value"], str)
    return b64url_decode(value["value"])


def test_all_canonical_tuple_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/canonical-tuples.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    assert document["format_version"] == 1
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "tuple_kind", "canonical_utf8_hex", "decoded_public_values"}
        kind = row["tuple_kind"]
        assert row["name"] == kind and kind not in seen
        seen.add(kind)
        raw = bytes.fromhex(row["canonical_utf8_hex"])
        values = row["decoded_public_values"]
        endpoint = values.get("endpoint")
        endpoint_value = None if endpoint is None else EndpointValue(**endpoint)
        expected = {
            "agent_user": lambda: AgentUserAttestation(
                values["agent_id"], endpoint_value, _tagged_bytes(values["agent_tls_public_key"]),
                _tagged_bytes(values["agent_access_control_public_key"]),
                _tagged_bytes(values["provider_public_key"]),
            ),
            "otk": lambda: OtkAttestation(values["agent_id"], _tagged_bytes(values["one_time_public_key"])),
            "provider": lambda: ProviderAttestation(
                values["agent_id"], _tagged_bytes(values["agent_certificate"]), endpoint_value,
                _tagged_bytes(values["agent_access_control_public_key"]),
                _tagged_bytes(values["user_signature"]),
            ),
            "act": lambda: ActPlaintext(
                _tagged_bytes(values["nonce"]), values["issued_at"], values["expires_at"],
                values["q_max"], _tagged_bytes(values["initiating_agent_access_control_public_key"]),
            ),
        }[kind]()
        decode, encode = {
            "agent_user": (decode_agent_user_attestation, encode_agent_user_attestation),
            "otk": (decode_otk_attestation, encode_otk_attestation),
            "provider": (decode_provider_attestation, encode_provider_attestation),
            "act": (decode_act_plaintext, encode_act_plaintext),
        }[kind]
        assert decode(raw) == expected
        assert encode(expected) == raw
    assert seen == {"agent_user", "otk", "provider", "act"}
```

Expected: repeated calls and a fresh Python process produce identical bytes.

- [ ] **Step 6: Run focused and full current gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_protocol_tuples.py -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: pytest exits 0 with zero failures; mypy and both Ruff commands exit 0.

- [ ] **Step 7: Commit tuple serializers and vectors**

```powershell
git add src/saga/crypto/canonical.py tests/unit/test_protocol_tuples.py tests/vectors/canonical-tuples.json
git commit -m "feat: encode exact SAGA protocol tuples"
```

---

### Task 4: Ed25519 Signature Wrapper and Signed-Tuple Tamper Vectors

**Files:**
- Create: `src/saga/crypto/signatures.py`
- Create: `tests/unit/test_signatures.py`
- Create: `tests/vectors/ed25519-signatures.json`

**Interfaces:**
- Consumes: exact canonical tuple bytes from Task 3.
- Produces: `SignatureError`, `generate_ed25519_private_key`, `ed25519_public_key`, `ed25519_public_key_bytes`, `ed25519_public_key_from_bytes`, `sign`, and `verify`.

- [ ] **Step 1: Write failing Ed25519 tests**

```python
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.crypto.canonical import (
    OtkAttestation,
    decode_otk_attestation,
    encode_otk_attestation,
)
from saga.crypto.signatures import (
    SignatureError,
    ed25519_public_key,
    ed25519_public_key_bytes,
    ed25519_public_key_from_bytes,
    generate_ed25519_private_key,
    sign,
    verify,
)


def test_rfc8032_vector_one() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ))
    signature = sign(private_key, b"")
    public = ed25519_public_key(private_key)
    public_raw = ed25519_public_key_bytes(public)
    assert public_raw.hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    assert signature.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_public_key_bytes(ed25519_public_key_from_bytes(public_raw)) == public_raw
    verify(public, b"", signature)


def test_any_signed_input_mutation_fails() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    message = b'{"agent_id":"alice:worker","one_time_public_key":"AA"}'
    signature = sign(private_key, message)
    bad_signature = signature[:-1] + bytes([signature[-1] ^ 1])
    for public_key, candidate_message, candidate_signature in (
        (private_key.public_key(), message + b" ", signature),
        (private_key.public_key(), message, bad_signature),
        (other_key.public_key(), message, signature),
    ):
        with pytest.raises(SignatureError, match="signature verification failed"):
            verify(public_key, candidate_message, candidate_signature)
```

```python
def test_same_type_tuple_mutation_parses_but_breaks_signature() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    original = encode_otk_attestation(OtkAttestation("alice:worker", bytes(range(32))))
    changed_value = OtkAttestation("alice:worker", bytes(range(1, 33)))
    changed = encode_otk_attestation(changed_value)
    assert decode_otk_attestation(changed) == changed_value
    with pytest.raises(SignatureError):
        verify(private.public_key(), changed, sign(private, original))
```

- [ ] **Step 2: Run and confirm missing-wrapper failure**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_signatures.py -q`

Expected: collection FAIL because `saga.crypto.signatures` does not exist.

- [ ] **Step 3: Implement the narrow mature-library wrapper**

Use this complete, Ruff-sorted import block at the top of `signatures.py`:

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
```

```python
class SignatureError(ValueError):
    """Signature input or verification is invalid."""


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    try:
        key = Ed25519PrivateKey.generate()
    except (TypeError, ValueError):
        raise SignatureError("signature key generation failed") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("signature key generation failed")
    return key


def ed25519_public_key(key: Ed25519PrivateKey) -> Ed25519PublicKey:
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("signature key invalid")
    try:
        public = key.public_key()
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None
    if not isinstance(public, Ed25519PublicKey):
        raise SignatureError("signature key invalid")
    return public


def ed25519_public_key_bytes(key: Ed25519PublicKey) -> bytes:
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError("signature key invalid")
    try:
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None
    if type(raw) is not bytes or len(raw) != 32:
        raise SignatureError("signature key invalid")
    return raw


def ed25519_public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    if type(data) is not bytes or len(data) != 32:
        raise SignatureError("signature key invalid")
    try:
        return Ed25519PublicKey.from_public_bytes(data)
    except (TypeError, ValueError):
        raise SignatureError("signature key invalid") from None


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey) or type(message) is not bytes:
        raise SignatureError("signature input invalid")
    try:
        signature = private_key.sign(message)
    except (TypeError, ValueError):
        raise SignatureError("signature input invalid") from None
    if type(signature) is not bytes or len(signature) != 64:
        raise SignatureError("signature input invalid")
    return signature


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> None:
    if (
        not isinstance(public_key, Ed25519PublicKey)
        or type(message) is not bytes
        or type(signature) is not bytes
        or len(signature) != 64
    ):
        raise SignatureError("signature verification failed")
    try:
        public_key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        raise SignatureError("signature verification failed") from None
```

```python
def test_signature_wrong_objects_and_lengths_fail() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    calls = [
        lambda: ed25519_public_key(object()),
        lambda: ed25519_public_key_bytes(object()),
        lambda: ed25519_public_key_from_bytes(object()),
        lambda: sign(object(), b"m"),
        lambda: sign(private, "m"),
        lambda: verify(object(), b"m", b"0" * 64),
        lambda: verify(public, "m", b"0" * 64),
        lambda: verify(public, b"m", object()),
    ]
    calls.extend(lambda n=n: ed25519_public_key_from_bytes(b"0" * n) for n in (0, 31, 33))
    calls.extend(lambda n=n: verify(public, b"m", b"0" * n) for n in (0, 63, 65))
    for call in calls:
        with pytest.raises(SignatureError):
            call()
```

```python
class FakeEdPublic:
    @classmethod
    def from_public_bytes(cls, _: bytes) -> "FakeEdPublic":
        raise ValueError
    def public_bytes(self, *_: object) -> bytes:
        raise TypeError
    def verify(self, *_: object) -> None:
        raise InvalidSignature


class FakeEdPrivate:
    @classmethod
    def generate(cls) -> "FakeEdPrivate":
        raise ValueError
    def public_key(self) -> FakeEdPublic:
        raise TypeError
    def sign(self, _: bytes) -> bytes:
        raise ValueError


def test_signature_library_errors_are_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("saga.crypto.signatures.Ed25519PrivateKey", FakeEdPrivate)
    monkeypatch.setattr("saga.crypto.signatures.Ed25519PublicKey", FakeEdPublic)
    calls = [
        generate_ed25519_private_key,
        lambda: ed25519_public_key(FakeEdPrivate()),
        lambda: ed25519_public_key_bytes(FakeEdPublic()),
        lambda: ed25519_public_key_from_bytes(b"0" * 32),
        lambda: sign(FakeEdPrivate(), b"m"),
        lambda: verify(FakeEdPublic(), b"m", b"0" * 64),
    ]
    for call in calls:
        with pytest.raises(SignatureError):
            call()
```

- [ ] **Step 4: Add fixed public signature vectors for all three signed tuples**

Create this exact file. `message_vector_name` joins to the same-named record in `canonical-tuples.json`, avoiding a second message-byte source:

```json
{"format_version":1,"vectors":[{"name":"agent_user","source":"IV-C user Agent attestation","public_key_hex":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message_vector_name":"agent_user","signature_hex":"4e530659e1e4afbaf95cd563c6d4ed868e0da6906f14598c1684c73c091915305575c2971dec030fedf9e87174c6b8705bececc41f6e2b26542a528fd2c19c0e"},{"name":"otk","source":"IV-C user OTK binding","public_key_hex":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message_vector_name":"otk","signature_hex":"3141c05625df7d3c14338659fc8cb96d4cc6aebab825403489c8d9e5a1c644dd26aaa14d4c5808b6ef3113ac70808744a573103f01f297e5b176b17ce65d550a"},{"name":"provider","source":"IV-C Step 7 main-text formula; Figure 8 conflict excluded","public_key_hex":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message_vector_name":"provider","signature_hex":"dad2b1459d47d4abd95d6ecffcf926f4729b34a5951c750d23c73fde470287620bc9644639340d7330a1cd9a56ae37a007fe7d0654be055af39383641f04900b"}]}
```

```python
def test_all_signature_vectors_are_consumed() -> None:
    signature_doc = json.loads(Path("tests/vectors/ed25519-signatures.json").read_text("utf-8"))
    canonical_doc = json.loads(Path("tests/vectors/canonical-tuples.json").read_text("utf-8"))
    messages = {row["name"]: bytes.fromhex(row["canonical_utf8_hex"]) for row in canonical_doc["vectors"]}
    assert set(signature_doc) == {"format_version", "vectors"}
    seen: set[str] = set()
    for row in signature_doc["vectors"]:
        assert set(row) == {"name", "source", "public_key_hex", "message_vector_name", "signature_hex"}
        assert row["name"] == row["message_vector_name"] and row["name"] not in seen
        seen.add(row["name"])
        public = ed25519_public_key_from_bytes(bytes.fromhex(row["public_key_hex"]))
        signature = bytes.fromhex(row["signature_hex"])
        message = messages[row["message_vector_name"]]
        verify(public, message, signature)
        with pytest.raises(SignatureError):
            verify(public, message[:-1] + bytes([message[-1] ^ 1]), signature)
        with pytest.raises(SignatureError):
            verify(public, message, signature[:-1] + bytes([signature[-1] ^ 1]))
    assert seen == {"agent_user", "otk", "provider"}
```

- [ ] **Step 5: Run focused and accumulated gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_signatures.py tests/unit/test_protocol_tuples.py -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: pytest exits 0 with zero failures, both static checks and format check exit 0, every vector is consumed, and every signed-byte mutation fails closed.

- [ ] **Step 6: Commit signatures and vectors**

```powershell
git add src/saga/crypto/signatures.py tests/unit/test_signatures.py tests/vectors/ed25519-signatures.json
git commit -m "feat: wrap Ed25519 signatures"
```

---

### Task 5: X25519 Key Agreement and Equality Vector

**Files:**
- Create: `src/saga/crypto/key_agreement.py`
- Create: `tests/unit/test_key_agreement.py`
- Create: `tests/vectors/x25519-agreement.json`

**Interfaces:**
- Consumes: strict bytes and mature-library dependency.
- Produces: `KeyAgreementError`, `generate_x25519_private_key`, `x25519_public_key`, `x25519_public_key_bytes`, `x25519_public_key_from_bytes`, and `derive_shared_secret`.

- [ ] **Step 1: Write failing RFC 7748 and SAGA equality tests**

```python
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from saga.crypto.key_agreement import (
    KeyAgreementError,
    derive_shared_secret,
    generate_x25519_private_key,
    x25519_public_key,
    x25519_public_key_bytes,
    x25519_public_key_from_bytes,
)


def test_rfc7748_alice_bob_shared_secret() -> None:
    alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ))
    bob = X25519PrivateKey.from_private_bytes(bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    ))
    expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert derive_shared_secret(alice, bob.public_key()).hex() == expected
    assert derive_shared_secret(bob, alice.public_key()).hex() == expected


def test_saga_dh_ledger_equality() -> None:
    # SAC_B pairs with PAC_B; SOTK_A pairs with OTK_A.
    sac_b = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    sotk_a = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    pac_b = sac_b.public_key()
    otk_a = sotk_a.public_key()
    assert derive_shared_secret(sac_b, otk_a) == derive_shared_secret(sotk_a, pac_b)
```

Create this exact vector file and loader mapping:

```json
{"format_version":1,"vectors":[{"name":"rfc7748-alice-bob","alice_public_hex":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a","bob_public_hex":"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f","shared_secret_hex":"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"}]}
```

```python
def test_all_x25519_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/x25519-agreement.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    private_inputs = {
        "rfc7748-alice-bob": (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        )
    }
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "alice_public_hex", "bob_public_hex", "shared_secret_hex"}
        name = row["name"]
        assert name in private_inputs and name not in seen
        seen.add(name)
        alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_inputs[name][0]))
        bob = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_inputs[name][1]))
        assert x25519_public_key_bytes(alice.public_key()).hex() == row["alice_public_hex"]
        assert x25519_public_key_bytes(bob.public_key()).hex() == row["bob_public_hex"]
        assert derive_shared_secret(alice, bob.public_key()).hex() == row["shared_secret_hex"]
        assert derive_shared_secret(bob, alice.public_key()).hex() == row["shared_secret_hex"]
    assert seen == set(private_inputs)
```

- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_key_agreement.py -q`

Expected: collection FAIL because the module is absent.

- [ ] **Step 3: Implement exact X25519 interfaces**

Use this complete, Ruff-sorted import block at the top of `key_agreement.py`:

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
```

```python
class KeyAgreementError(ValueError):
    """An X25519 input or exchange is invalid."""

def generate_x25519_private_key() -> X25519PrivateKey:
    try:
        key = X25519PrivateKey.generate()
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key generation failed") from None
    if not isinstance(key, X25519PrivateKey):
        raise KeyAgreementError("key agreement key generation failed")
    return key

def x25519_public_key(key: X25519PrivateKey) -> X25519PublicKey:
    if not isinstance(key, X25519PrivateKey):
        raise KeyAgreementError("key agreement key invalid")
    try:
        public = key.public_key()
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None
    if not isinstance(public, X25519PublicKey):
        raise KeyAgreementError("key agreement key invalid")
    return public

def x25519_public_key_bytes(key: X25519PublicKey) -> bytes:
    if not isinstance(key, X25519PublicKey):
        raise KeyAgreementError("key agreement key invalid")
    try:
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None
    if type(raw) is not bytes or len(raw) != 32:
        raise KeyAgreementError("key agreement key invalid")
    return raw

def x25519_public_key_from_bytes(data: bytes) -> X25519PublicKey:
    if type(data) is not bytes or len(data) != 32:
        raise KeyAgreementError("key agreement key invalid")
    try:
        return X25519PublicKey.from_public_bytes(data)
    except (TypeError, ValueError):
        raise KeyAgreementError("key agreement key invalid") from None

def derive_shared_secret(
    private_key: X25519PrivateKey, peer_public_key: X25519PublicKey
) -> bytes:
    if not isinstance(private_key, X25519PrivateKey) or not isinstance(
        peer_public_key, X25519PublicKey
    ):
        raise KeyAgreementError("key agreement failed")
    try:
        shared = private_key.exchange(peer_public_key)
    except (ValueError, TypeError):
        raise KeyAgreementError("key agreement failed") from None
    if type(shared) is not bytes or len(shared) != 32 or not any(shared):
        raise KeyAgreementError("key agreement failed")
    return shared
```

```python
def test_x25519_wrong_objects_and_lengths_fail() -> None:
    private = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    calls = [
        lambda: x25519_public_key(object()),
        lambda: x25519_public_key_bytes(object()),
        lambda: x25519_public_key_from_bytes(object()),
        lambda: derive_shared_secret(object(), public),
        lambda: derive_shared_secret(private, object()),
    ]
    calls.extend(lambda n=n: x25519_public_key_from_bytes(b"0" * n) for n in (0, 31, 33))
    for call in calls:
        with pytest.raises(KeyAgreementError):
            call()
```

```python
class FakeXPublic:
    @classmethod
    def from_public_bytes(cls, _: bytes) -> "FakeXPublic":
        raise ValueError
    def public_bytes(self, *_: object) -> bytes:
        raise TypeError


class FakeXPrivate:
    @classmethod
    def generate(cls) -> "FakeXPrivate":
        raise ValueError
    def public_key(self) -> FakeXPublic:
        raise TypeError
    def exchange(self, _: FakeXPublic) -> bytes:
        return b"\x00" * 32


def test_x25519_library_errors_are_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("saga.crypto.key_agreement.X25519PrivateKey", FakeXPrivate)
    monkeypatch.setattr("saga.crypto.key_agreement.X25519PublicKey", FakeXPublic)
    calls = [
        generate_x25519_private_key,
        lambda: x25519_public_key(FakeXPrivate()),
        lambda: x25519_public_key_bytes(FakeXPublic()),
        lambda: x25519_public_key_from_bytes(b"0" * 32),
        lambda: derive_shared_secret(FakeXPrivate(), FakeXPublic()),
    ]
    for call in calls:
        with pytest.raises(KeyAgreementError):
            call()
```

- [ ] **Step 4: Freeze public RFC/SAGA agreement vectors and run gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_key_agreement.py -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: equality holds in both directions, every vector is loaded, and pytest/mypy/Ruff check/Ruff format all exit 0.

- [ ] **Step 5: Commit X25519 agreement**

```powershell
git add src/saga/crypto/key_agreement.py tests/unit/test_key_agreement.py tests/vectors/x25519-agreement.json
git commit -m "feat: wrap X25519 key agreement"
```

---

### Task 6: Fixed-Domain HKDF-SHA256

**Files:**
- Create: `src/saga/crypto/kdf.py`
- Create: `tests/unit/test_kdf.py`
- Create: `tests/vectors/hkdf-sha256.json`

**Interfaces:**
- Consumes: 32-byte X25519 shared secret.
- Produces: `KeyDerivationError`, constants `SAGA_HKDF_INFO`, `SAGA_KEY_BYTES`, and `derive_sdhk`.

- [ ] **Step 1: Write failing fixed-vector and domain-separation tests**

```python
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from saga.crypto.kdf import KeyDerivationError, SAGA_HKDF_INFO, derive_sdhk


def test_saga_hkdf_vector_is_fixed() -> None:
    assert SAGA_HKDF_INFO == b"SAGA-ACT-DERIVE/v1"
    assert derive_sdhk(bytes(range(32))).hex() == (
        "43119e861811e97c6a0c43fa93e1b5fbfd672e52875e44d9e672f65ae7e6c3c2"
    )


def test_wrong_info_cannot_match_saga_key() -> None:
    wrong = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"SAGA-ACT-DERIVE/v2",
    ).derive(bytes(range(32)))
    assert wrong != derive_sdhk(bytes(range(32)))
```

Reject non-bytes input and lengths other than 32 without exposing input. Add this
copyable test to `tests/unit/test_kdf.py`; it covers an arbitrary object, a mutable
byte buffer, a `bytes` subclass, and both adjacent invalid lengths:

```python
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
```

- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_kdf.py -q`

Expected: collection FAIL because `kdf.py` is absent.

- [ ] **Step 3: Implement the fixed KDF only**

Use this complete, Ruff-sorted import block at the top of `kdf.py`; the direct
test-side `HKDF` call remains the independent oracle:

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
```

```python
SAGA_HKDF_INFO = b"SAGA-ACT-DERIVE/v1"
SAGA_KEY_BYTES = 32


class KeyDerivationError(ValueError):
    """A SAGA KDF input is invalid."""


def derive_sdhk(shared_secret: bytes) -> bytes:
    """Derive the 32-byte SAGA ACT key with fixed salt/info."""
    if type(shared_secret) is not bytes or len(shared_secret) != 32:
        raise KeyDerivationError("key derivation input invalid")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SAGA_KEY_BYTES,
        salt=None,
        info=SAGA_HKDF_INFO,
    ).derive(shared_secret)
```

Instantiate `HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SAGA_HKDF_INFO)` inside the function. Expose no generic `info`, `salt`, or length arguments in the production API.

- [ ] **Step 4: Freeze the expected vector and run accumulated gates**

Create this exact file; `bytes(range(32))` remains only in `test_kdf.py` under name `range-00-1f`:

```json
{"format_version":1,"vectors":[{"name":"range-00-1f","salt":null,"info_ascii":"SAGA-ACT-DERIVE/v1","length":32,"derived_key_hex":"43119e861811e97c6a0c43fa93e1b5fbfd672e52875e44d9e672f65ae7e6c3c2"}]}
```

```python
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
```

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_kdf.py tests/unit/test_key_agreement.py -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: all commands exit 0; every vector is consumed and mismatched info differs.

- [ ] **Step 5: Commit the KDF**

```powershell
git add src/saga/crypto/kdf.py tests/unit/test_kdf.py tests/vectors/hkdf-sha256.json
git commit -m "feat: derive SAGA ACT keys with HKDF"
```

---

### Task 7: ChaCha20-Poly1305 ACT Envelope

**Files:**
- Create: `src/saga/crypto/aead.py`
- Create: `tests/unit/test_aead.py`
- Create: `tests/vectors/chacha20-poly1305.json`

**Interfaces:**
- Consumes: 32-byte SDHK and canonical five-field ACT plaintext bytes.
- Produces: `AeadError`, `ActEnvelope`, `encrypt_act`, and `decrypt_act`.

- [ ] **Step 1: Write failing envelope and tamper tests**

```python
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.exceptions import InvalidTag

from saga.crypto.aead import ActEnvelope, AeadError, decrypt_act, encrypt_act


def test_act_envelope_keeps_version_and_aead_nonce_outside_plaintext() -> None:
    key = bytes(range(32))
    plaintext = b'{"nonce":"AA","issued_at":1,"expires_at":2,"q_max":1,' \
        b'"initiating_agent_access_control_public_key":"AA"}'
    outer_nonce = bytes(range(12))
    envelope = encrypt_act(key, plaintext, nonce=outer_nonce)
    assert envelope.version == 1
    assert envelope.nonce == outer_nonce
    assert envelope.ciphertext != plaintext
    assert decrypt_act(key, envelope) == plaintext


def test_key_version_nonce_and_ciphertext_mutations_fail() -> None:
    key = bytes(range(32))
    envelope = encrypt_act(key, b"public fixture", nonce=bytes(range(12)))
    cases = (
        (bytes(reversed(range(32))), envelope),
        (key, replace(envelope, version=2)),
        (key, replace(envelope, nonce=bytes(reversed(range(12))))),
        (key, replace(envelope, ciphertext=(
            envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
        ))),
    )
    for candidate_key, candidate_envelope in cases:
        with pytest.raises(AeadError, match="ACT decryption failed"):
            decrypt_act(candidate_key, candidate_envelope)


def test_aad_domain_mismatch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes(range(32))
    envelope = encrypt_act(key, b"public fixture", nonce=bytes(range(12)))
    monkeypatch.setattr("saga.crypto.aead.SAGA_ACT_AAD", b"SAGA-ACT/v2")
    with pytest.raises(AeadError, match="ACT decryption failed"):
        decrypt_act(key, envelope)
```

```python
@pytest.mark.parametrize("key", [object(), b"", b"0" * 31, b"0" * 33])
def test_encrypt_rejects_bad_keys(key: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(key, b"p", nonce=b"0" * 12)


@pytest.mark.parametrize("plaintext", [object(), "p", bytearray(b"p")])
def test_encrypt_rejects_non_bytes_plaintext(plaintext: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, plaintext, nonce=b"0" * 12)


@pytest.mark.parametrize("version", [True, 1.0, "1", 2])
def test_decrypt_rejects_non_plain_one_version(version: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(version, b"0" * 12, b"0" * 16))


@pytest.mark.parametrize("nonce", [object(), "n", b"", b"0" * 11, b"0" * 13])
def test_decrypt_rejects_bad_nonce(nonce: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, nonce, b"0" * 16))


@pytest.mark.parametrize("ciphertext", [object(), "c", b"", b"0" * 15])
def test_decrypt_rejects_bad_ciphertext(ciphertext: object) -> None:
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, b"0" * 12, ciphertext))
```

- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_aead.py -q`

Expected: collection FAIL because `aead.py` does not exist.

- [ ] **Step 3: Implement the closed envelope API**

Use this complete, Ruff-sorted import block at the top of `aead.py`:

```python
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
```

```python
class AeadError(ValueError):
    """An ACT envelope is invalid or unauthentic."""


SAGA_ACT_AAD = b"SAGA-ACT/v1"
SAGA_ACT_ENVELOPE_VERSION = 1
CHACHA_NONCE_BYTES = 12


@dataclass(frozen=True, slots=True)
class ActEnvelope:
    version: int
    nonce: bytes
    ciphertext: bytes


def encrypt_act(
    key: bytes,
    plaintext: bytes,
    *,
    nonce: bytes | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> ActEnvelope:
    try:
        if type(key) is not bytes or len(key) != 32 or type(plaintext) is not bytes:
            raise AeadError("ACT encryption input invalid")
        if nonce is None:
            if not callable(random_bytes):
                raise AeadError("ACT encryption input invalid")
            outer_nonce = random_bytes(CHACHA_NONCE_BYTES)
        else:
            outer_nonce = nonce
        if type(outer_nonce) is not bytes or len(outer_nonce) != CHACHA_NONCE_BYTES:
            raise AeadError("ACT encryption input invalid")
        primitive = ChaCha20Poly1305(key)
        ciphertext = primitive.encrypt(outer_nonce, plaintext, SAGA_ACT_AAD)
        if type(ciphertext) is not bytes or len(ciphertext) < 16:
            raise AeadError("ACT encryption input invalid")
        return ActEnvelope(SAGA_ACT_ENVELOPE_VERSION, outer_nonce, ciphertext)
    except AeadError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise AeadError("ACT encryption input invalid") from None


def decrypt_act(key: bytes, envelope: ActEnvelope) -> bytes:
    try:
        if (
            type(key) is not bytes
            or len(key) != 32
            or not isinstance(envelope, ActEnvelope)
            or type(envelope.version) is not int
            or envelope.version != SAGA_ACT_ENVELOPE_VERSION
            or type(envelope.nonce) is not bytes
            or len(envelope.nonce) != CHACHA_NONCE_BYTES
            or type(envelope.ciphertext) is not bytes
            or len(envelope.ciphertext) < 16
        ):
            raise AeadError("ACT decryption failed")
        primitive = ChaCha20Poly1305(key)
        plaintext = primitive.decrypt(envelope.nonce, envelope.ciphertext, SAGA_ACT_AAD)
        if type(plaintext) is not bytes:
            raise AeadError("ACT decryption failed")
        return plaintext
    except AeadError:
        raise
    except (AttributeError, InvalidTag, TypeError, ValueError):
        raise AeadError("ACT decryption failed") from None
```

```python
def _raising(error: BaseException) -> Callable[[int], bytes]:
    def raise_error(_: int) -> bytes:
        raise error
    return raise_error


@pytest.mark.parametrize(
    "rng",
    [object(), lambda _: "x", lambda _: b"0" * 11, lambda _: b"0" * 13,
     _raising(TypeError()), _raising(ValueError())],
)
def test_rng_failures_are_normalized(rng: object) -> None:
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, b"p", random_bytes=rng)


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_rng_system_exceptions_propagate(error: BaseException) -> None:
    with pytest.raises(type(error)):
        encrypt_act(b"0" * 32, b"p", random_bytes=_raising(error))
```

```python
class FakeChaCha20Poly1305:
    mode = "ok"

    def __init__(self, _: bytes) -> None:
        if self.mode == "constructor-error":
            raise ValueError

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        del nonce, plaintext, aad
        if self.mode == "encrypt-error":
            raise TypeError
        if self.mode == "wrong-encrypt-return":
            return cast(bytes, object())
        return b"0" * 16

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        del nonce, ciphertext, aad
        if self.mode == "decrypt-error":
            raise InvalidTag
        if self.mode == "wrong-decrypt-return":
            return cast(bytes, object())
        return b"p"


@pytest.mark.parametrize(
    "mode", ["constructor-error", "encrypt-error", "wrong-encrypt-return"]
)
def test_encrypt_library_failures(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    FakeChaCha20Poly1305.mode = mode
    monkeypatch.setattr("saga.crypto.aead.ChaCha20Poly1305", FakeChaCha20Poly1305)
    with pytest.raises(AeadError):
        encrypt_act(b"0" * 32, b"p", nonce=b"0" * 12)


@pytest.mark.parametrize("mode", ["constructor-error", "decrypt-error", "wrong-decrypt-return"])
def test_decrypt_library_failures(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    FakeChaCha20Poly1305.mode = mode
    monkeypatch.setattr("saga.crypto.aead.ChaCha20Poly1305", FakeChaCha20Poly1305)
    with pytest.raises(AeadError):
        decrypt_act(b"0" * 32, ActEnvelope(1, b"0" * 12, b"0" * 16))
```

- [ ] **Step 4: Freeze one public AEAD vector and run gates**

Create this exact vector file; the key `bytes(range(32))` remains only in test source under the `range-key` mapping:

```json
{"format_version":1,"vectors":[{"name":"range-key","outer_nonce_hex":"000102030405060708090a0b","plaintext_hex":"7075626c69632066697874757265","aad_ascii":"SAGA-ACT/v1","ciphertext_and_tag_hex":"f98e6a6c40748526defb4b86ea78198dec2e407341a7a2dd4f878117872b"}]}
```

```python
def test_all_aead_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/chacha20-poly1305.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    inputs = {"range-key": bytes(range(32))}
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "outer_nonce_hex", "plaintext_hex", "aad_ascii", "ciphertext_and_tag_hex"}
        name = row["name"]
        assert name in inputs and name not in seen and row["aad_ascii"] == "SAGA-ACT/v1"
        seen.add(name)
        nonce = bytes.fromhex(row["outer_nonce_hex"])
        plaintext = bytes.fromhex(row["plaintext_hex"])
        ciphertext = bytes.fromhex(row["ciphertext_and_tag_hex"])
        envelope = encrypt_act(inputs[name], plaintext, nonce=nonce)
        assert envelope.ciphertext == ciphertext
        assert decrypt_act(inputs[name], envelope) == plaintext
        for changed in (
            replace(envelope, nonce=nonce[:-1] + bytes([nonce[-1] ^ 1])),
            replace(envelope, ciphertext=ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])),
        ):
            with pytest.raises(AeadError):
                decrypt_act(inputs[name], changed)
    assert seen == set(inputs)
```

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_aead.py tests/unit/test_protocol_tuples.py -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: all pass; two different nonces yield different ciphertext; mutations fail closed.

- [ ] **Step 5: Commit AEAD envelope**

```powershell
git add src/saga/crypto/aead.py tests/unit/test_aead.py tests/vectors/chacha20-poly1305.json
git commit -m "feat: encrypt ACT envelopes with fixed AEAD context"
```

---

### Task 8: Versioned scrypt Password Records

**Files:**
- Create: `src/saga/crypto/passwords.py`
- Create: `tests/unit/test_passwords.py`
- Create: `tests/vectors/scrypt-records.json`

**Interfaces:**
- Consumes: secure random-byte source.
- Produces: supported persistence API `saga.crypto.passwords.{PasswordRecord, PasswordRecordError, hash_password, verify_password}`; it is not an external result DTO and none of these names is re-exported from top-level `saga.crypto`.

- [ ] **Step 1: Write failing record, verification, and redaction tests**

```python
import json
from collections.abc import Callable
from dataclasses import replace
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


def test_scrypt_record_has_exact_baseline_parameters() -> None:
    record = hash_password("correct horse", salt=bytes(range(16)))
    assert record == PasswordRecord(
        version=1, n=2**15, r=8, p=1, dklen=32,
        salt=bytes(range(16)),
        verifier=bytes.fromhex(
            "5c662628ac4eb1068a287e2aa2a202ae248e98db04d61d3327e7342db6ec7097"
        ),
    )
    assert verify_password("correct horse", record)
    assert not verify_password("wrong", record)


def test_password_and_verifier_are_redacted() -> None:
    record = hash_password("never-log-me", salt=bytes(range(16)))
    assert "never-log-me" not in repr(record)
    assert record.verifier.hex() not in repr(record)


def test_password_api_is_not_reexported_from_saga_crypto() -> None:
    for name in ("PasswordRecord", "PasswordRecordError", "hash_password", "verify_password"):
        assert not hasattr(saga.crypto, name)
```

```python
@pytest.mark.parametrize("password", ["", object(), b"password", "\ud800"])
def test_password_input_failures_are_normalized(password: object) -> None:
    with pytest.raises(PasswordRecordError):
        hash_password(password, salt=b"0" * 16)


@pytest.mark.parametrize("salt", [object(), "salt", b"", b"0" * 15, b"0" * 17])
def test_salt_failures_are_normalized(salt: object) -> None:
    with pytest.raises(PasswordRecordError):
        hash_password("public-test-password", salt=salt)
```

- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_passwords.py -q`

Expected: collection FAIL because `passwords.py` is absent.

- [ ] **Step 3: Implement the exact closed record**

Use this complete, Ruff-sorted import block at the top of `passwords.py`:

```python
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeGuard

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
```

```python
__all__ = (
    "PasswordRecord",
    "PasswordRecordError",
    "hash_password",
    "verify_password",
)


class PasswordRecordError(ValueError):
    """A password record is malformed."""


@dataclass(frozen=True, slots=True, repr=False)
class PasswordRecord:
    version: int
    n: int
    r: int
    p: int
    dklen: int
    salt: bytes
    verifier: bytes

    def __repr__(self) -> str:
        return "PasswordRecord(version=1, redacted=True)"


def hash_password(
    password: str,
    *,
    salt: bytes | None = None,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> PasswordRecord:
    try:
        if not isinstance(password, str) or not password:
            raise PasswordRecordError("password input invalid")
        password_bytes = password.encode("utf-8", errors="strict")
        if salt is None:
            if not callable(random_bytes):
                raise PasswordRecordError("password record invalid")
            selected_salt = random_bytes(16)
        else:
            selected_salt = salt
        if type(selected_salt) is not bytes or len(selected_salt) != 16:
            raise PasswordRecordError("password record invalid")
        primitive = Scrypt(salt=selected_salt, length=32, n=2**15, r=8, p=1)
        verifier = primitive.derive(password_bytes)
        if type(verifier) is not bytes or len(verifier) != 32:
            raise PasswordRecordError("password record invalid")
        return PasswordRecord(1, 2**15, 8, 1, 32, selected_salt, verifier)
    except PasswordRecordError:
        raise
    except (OverflowError, TypeError, UnsupportedAlgorithm, ValueError):
        raise PasswordRecordError("password record invalid") from None


def verify_password(password: str, record: PasswordRecord) -> bool:
    try:
        if not isinstance(password, str) or not password or not _valid_record(record):
            raise PasswordRecordError("password record invalid")
        password_bytes = password.encode("utf-8", errors="strict")
        primitive = Scrypt(
            salt=record.salt, length=record.dklen, n=record.n, r=record.r, p=record.p
        )
        candidate = primitive.derive(password_bytes)
        if type(candidate) is not bytes or len(candidate) != 32:
            raise PasswordRecordError("password record invalid")
        return hmac.compare_digest(candidate, record.verifier)
    except PasswordRecordError:
        raise
    except (OverflowError, TypeError, UnsupportedAlgorithm, ValueError):
        raise PasswordRecordError("password record invalid") from None
```

Add this exact type guard before `verify_password`:

```python
def _valid_record(record: object) -> TypeGuard[PasswordRecord]:
    return (
        isinstance(record, PasswordRecord)
        and type(record.version) is int
        and record.version == 1
        and type(record.n) is int
        and record.n == 2**15
        and type(record.r) is int
        and record.r == 8
        and type(record.p) is int
        and record.p == 1
        and type(record.dklen) is int
        and record.dklen == 32
        and type(record.salt) is bytes
        and len(record.salt) == 16
        and type(record.verifier) is bytes
        and len(record.verifier) == 32
    )
```

```python
VALID_RECORD = PasswordRecord(1, 2**15, 8, 1, 32, b"0" * 16, b"1" * 32)


def _raising(error: BaseException) -> Callable[[int], bytes]:
    def raise_error(_: int) -> bytes:
        raise error
    return raise_error


@pytest.mark.parametrize(
    "changes",
    [
        {"version": True}, {"version": 2}, {"n": True}, {"n": 1},
        {"r": True}, {"r": 1}, {"p": True}, {"p": 2},
        {"dklen": True}, {"dklen": 31}, {"salt": "x"}, {"salt": b"0" * 15},
        {"verifier": "x"}, {"verifier": b"1" * 31},
    ],
)
def test_malformed_records_fail_before_scrypt(changes: dict[str, object]) -> None:
    with pytest.raises(PasswordRecordError):
        verify_password("public-test-password", replace(VALID_RECORD, **changes))


@pytest.mark.parametrize(
    "rng",
    [object(), lambda _: "x", lambda _: b"0" * 15, lambda _: b"0" * 17,
     _raising(TypeError()), _raising(ValueError())],
)
def test_password_rng_failures_are_normalized(rng: object) -> None:
    with pytest.raises(PasswordRecordError):
        hash_password("public-test-password", random_bytes=rng)
```

```python
class FakeScrypt:
    behavior: object = b"0" * 32

    def __init__(self, **_: object) -> None:
        if isinstance(self.behavior, BaseException):
            raise self.behavior

    def derive(self, _: bytes) -> bytes:
        if isinstance(self.behavior, BaseException):
            raise self.behavior
        return cast(bytes, self.behavior)


@pytest.mark.parametrize(
    "behavior", [TypeError(), ValueError(), UnsupportedAlgorithm(), object(), b"0" * 31]
)
def test_scrypt_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, behavior: object
) -> None:
    FakeScrypt.behavior = behavior
    monkeypatch.setattr("saga.crypto.passwords.Scrypt", FakeScrypt)
    with pytest.raises(PasswordRecordError):
        hash_password("public-test-password", salt=b"0" * 16)
```

Encode passwords as UTF-8, call `cryptography.hazmat.primitives.kdf.scrypt.Scrypt`, validate all record parameters before deriving, and compare with `hmac.compare_digest`. The optional salt is keyword-only and test-only public material. `PasswordRecord` models Provider-internal persistence and may be used by later persistence adapters via `saga.crypto.passwords`; it is deliberately excluded from the broad top-level API so it cannot be mistaken for an external response model.

- [ ] **Step 4: Freeze the public-output vector and run gates**

Create this exact public-output vector; the password literal exists only in the unit test:

```json
{"format_version":1,"vectors":[{"name":"correct-horse","version":1,"n":32768,"r":8,"p":1,"dklen":32,"salt_hex":"000102030405060708090a0b0c0d0e0f","verifier_hex":"5c662628ac4eb1068a287e2aa2a202ae248e98db04d61d3327e7342db6ec7097"}]}
```

```python
def test_all_scrypt_vectors_are_consumed() -> None:
    document = json.loads(Path("tests/vectors/scrypt-records.json").read_text("utf-8"))
    assert set(document) == {"format_version", "vectors"}
    passwords = {"correct-horse": "correct horse"}
    seen: set[str] = set()
    for row in document["vectors"]:
        assert set(row) == {"name", "version", "n", "r", "p", "dklen", "salt_hex", "verifier_hex"}
        name = row["name"]
        assert name in passwords and name not in seen
        seen.add(name)
        expected = PasswordRecord(
            row["version"], row["n"], row["r"], row["p"], row["dklen"],
            bytes.fromhex(row["salt_hex"]), bytes.fromhex(row["verifier_hex"]),
        )
        assert hash_password(passwords[name], salt=expected.salt) == expected
        assert verify_password(passwords[name], expected)
    assert seen == set(passwords)
```

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_passwords.py -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: correct password passes, all malformed records fail closed, wrong password returns `False`, and no secret appears in output.

- [ ] **Step 5: Commit scrypt records**

```powershell
git add src/saga/crypto/passwords.py tests/unit/test_passwords.py tests/vectors/scrypt-records.json
git commit -m "feat: store versioned scrypt password records"
```

---

### Task 9: X.509 Trust, Identity, Validity, and Key-Binding Validation

**Files:**
- Create: `src/saga/crypto/certificates.py`
- Create: `tests/helpers/__init__.py`
- Create: `tests/helpers/certificates.py`
- Create: `tests/unit/test_certificates.py`
- Modify: `docs/feature-source-matrix.md`

**Interfaces:**
- Consumes: integer Unix milliseconds and public-key byte encodings.
- Produces: `CertificateValidationError`, `IdentityKind`, `identity_uri`, `load_der_certificate`, and `validate_leaf_certificate`; in-memory fixtures for all profile branches.

- [ ] **Step 1: Write failing identity and trust tests**

```python
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm

import saga.crypto.certificates as certificate_module
from saga.crypto.certificates import (
    CertificateValidationError,
    IdentityKind,
    identity_uri,
    load_der_certificate,
    validate_leaf_certificate,
)
from tests.helpers.certificates import (
    LEAF_AFTER,
    LEAF_BEFORE,
    build_certificate_fixtures,
)

EXPECTED_NEGATIVE_CASES = frozenset({
    "wrong_anchor", "wrong_issuer", "bad_signature", "wrong_san",
    "multiple_saga_san", "dns_san_extra", "wrong_spki", "expired_leaf",
    "future_leaf", "expired_anchor", "future_anchor", "anchor_missing_bc",
    "anchor_ca_false", "anchor_bc_not_critical", "anchor_path_length_one",
    "anchor_missing_ku", "anchor_ku_not_critical", "anchor_bad_key_usage",
    "leaf_missing_bc", "leaf_ca_true", "leaf_bc_not_critical", "leaf_missing_ku",
    "leaf_ku_not_critical", "leaf_bad_key_usage", "leaf_missing_san",
    "leaf_san_critical", "leaf_missing_eku", "leaf_eku_critical",
    "leaf_wrong_eku", "malformed_leaf_der", "malformed_anchor_der",
})


def test_user_provider_and_agent_identity_uris_are_unambiguous() -> None:
    assert identity_uri(IdentityKind.USER, "alice") == "urn:saga:user:alice"
    assert identity_uri(IdentityKind.PROVIDER, "provider-1") == "urn:saga:provider:provider-1"
    assert identity_uri(IdentityKind.AGENT, "alice:worker") == "urn:saga:agent:alice%3Aworker"


def test_valid_agent_certificate_binds_identity_and_key() -> None:
    fixtures = build_certificate_fixtures()
    validate_leaf_certificate(
        leaf_der=fixtures.agent.der,
        trust_anchor_der=fixtures.anchor_der,
        expected_kind=IdentityKind.AGENT,
        expected_identifier="alice:worker",
        expected_public_key_spki_der=fixtures.agent.spki_der,
        now_ms=fixtures.now_ms,
    )


@pytest.mark.parametrize("attribute", ["user", "provider", "agent"])
def test_all_identity_profiles_validate(attribute: str) -> None:
    fixtures = build_certificate_fixtures()
    leaf = getattr(fixtures, attribute)
    validate_leaf_certificate(
        leaf_der=leaf.der,
        trust_anchor_der=fixtures.anchor_der,
        expected_kind=leaf.kind,
        expected_identifier=leaf.identifier,
        expected_public_key_spki_der=leaf.spki_der,
        now_ms=fixtures.now_ms,
    )


@pytest.mark.parametrize("case_name", sorted(EXPECTED_NEGATIVE_CASES))
def test_every_negative_profile_fails(case_name: str) -> None:
    fixtures = build_certificate_fixtures()
    assert set(fixtures.negative) == EXPECTED_NEGATIVE_CASES
    case = fixtures.negative[case_name]
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=case.leaf_der,
            trust_anchor_der=case.anchor_der,
            expected_kind=case.kind,
            expected_identifier=case.identifier,
            expected_public_key_spki_der=case.expected_spki_der,
            now_ms=case.now_ms,
        )


def test_leaf_validity_is_half_open() -> None:
    fixtures = build_certificate_fixtures()
    leaf = fixtures.agent
    common = {
        "leaf_der": leaf.der,
        "trust_anchor_der": fixtures.anchor_der,
        "expected_kind": leaf.kind,
        "expected_identifier": leaf.identifier,
        "expected_public_key_spki_der": leaf.spki_der,
    }
    validate_leaf_certificate(**common, now_ms=int(LEAF_BEFORE.timestamp() * 1000))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(**common, now_ms=int(LEAF_AFTER.timestamp() * 1000))


@pytest.mark.parametrize(
    "change",
    [
        {"leaf_der": b"not-der"}, {"trust_anchor_der": b"not-der"},
        {"expected_kind": object()},
        {"expected_identifier": ""}, {"expected_identifier": object()},
        {"expected_public_key_spki_der": object()}, {"expected_public_key_spki_der": b""},
        {"now_ms": True}, {"now_ms": -1}, {"now_ms": 1.0}, {"now_ms": object()},
    ],
)
def test_validation_rejects_malformed_boundary_inputs(change: dict[str, object]) -> None:
    fixtures = build_certificate_fixtures()
    leaf = fixtures.agent
    arguments: dict[str, Any] = {
        "leaf_der": leaf.der,
        "trust_anchor_der": fixtures.anchor_der,
        "expected_kind": leaf.kind,
        "expected_identifier": leaf.identifier,
        "expected_public_key_spki_der": leaf.spki_der,
        "now_ms": fixtures.now_ms,
    }
    arguments.update(change)
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(**arguments)


class CertificateProxy:
    def __init__(self, certificate: x509.Certificate, failure: str) -> None:
        self._certificate = certificate
        self._failure = failure

    def __getattr__(self, name: str) -> Any:
        if self._failure == "extension" and name == "extensions":
            raise ValueError
        return getattr(self._certificate, name)

    def verify_directly_issued_by(self, issuer: x509.Certificate) -> None:
        if self._failure == "verification":
            raise ValueError
        actual_issuer = issuer._certificate if isinstance(issuer, CertificateProxy) else issuer
        self._certificate.verify_directly_issued_by(actual_issuer)

    def public_key(self) -> Any:
        if self._failure == "public-key-export":
            raise ValueError
        return self._certificate.public_key()


@pytest.mark.parametrize("failure", ["verification", "extension", "public-key-export"])
def test_validation_library_failures_are_normalized(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    fixtures = build_certificate_fixtures()
    leaf = x509.load_der_x509_certificate(fixtures.agent.der)
    anchor = x509.load_der_x509_certificate(fixtures.anchor_der)
    values = iter([CertificateProxy(leaf, failure), CertificateProxy(anchor, failure)])
    monkeypatch.setattr(certificate_module, "load_der_certificate", lambda _: next(values))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der, trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind, expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der, now_ms=fixtures.now_ms,
        )


def test_time_conversion_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = build_certificate_fixtures()
    class FakeDateTime:
        @staticmethod
        def fromtimestamp(*_: object) -> None:
            raise OSError
    monkeypatch.setattr(certificate_module, "datetime", FakeDateTime)
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der, trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind, expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der, now_ms=fixtures.now_ms,
        )


def test_compare_failure_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = build_certificate_fixtures()
    monkeypatch.setattr(certificate_module.hmac, "compare_digest", lambda *_: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(CertificateValidationError):
        validate_leaf_certificate(
            leaf_der=fixtures.agent.der, trust_anchor_der=fixtures.anchor_der,
            expected_kind=fixtures.agent.kind, expected_identifier=fixtures.agent.identifier,
            expected_public_key_spki_der=fixtures.agent.spki_der, now_ms=fixtures.now_ms,
        )


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_validation_system_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    monkeypatch.setattr(
        certificate_module, "load_der_certificate", lambda _: (_ for _ in ()).throw(error)
    )
    with pytest.raises(type(error)):
        validate_leaf_certificate(
            leaf_der=b"x", trust_anchor_der=b"y", expected_kind=IdentityKind.AGENT,
            expected_identifier="alice:worker", expected_public_key_spki_der=b"z", now_ms=1,
        )
```

`tests/helpers/certificates.py` defines frozen `LeafFixture(der: bytes, spki_der: bytes, kind: IdentityKind, identifier: str)`, `ValidationCase(leaf_der: bytes, anchor_der: bytes, kind: IdentityKind, identifier: str, expected_spki_der: bytes, now_ms: int)`, and `CertificateFixtureSet(anchor_der: bytes, now_ms: int, user: LeafFixture, provider: LeafFixture, agent: LeafFixture, negative: Mapping[str, ValidationCase])`. `build_certificate_fixtures() -> CertificateFixtureSet` dynamically builds all material in memory for each test call. Fixed synthetic Ed25519 seeds are literal test-only bytes in this helper, identified in a module docstring as public non-operational material; no private bytes or PEM/DER private-key files are written. The parametrized negative test passes all six `ValidationCase` fields to `validate_leaf_certificate`, so wrong-anchor/time/identity/SPKI cases are unambiguous.

The helper uses fixed serial numbers and UTC instants. Its single self-signed trust anchor has subject=issuer `CN=SAGA Phase 1 Test Root`, validity `[2025-01-01T00:00:00Z, 2035-01-01T00:00:00Z)`, critical `BasicConstraints(ca=True,path_length=0)`, and critical `KeyUsage` with only `key_cert_sign=True` and `crl_sign=True`. Every leaf has issuer equal to that subject, validity `[2026-01-01T00:00:00Z, 2027-01-01T00:00:00Z)`, critical `BasicConstraints(ca=False,path_length=None)`, critical `KeyUsage` with only `digital_signature=True`, and exactly one URI SAN. Exact EKUs are User `{CLIENT_AUTH}`, Provider `{SERVER_AUTH}`, and Agent `{CLIENT_AUTH, SERVER_AUTH}`. Its SPKI is DER `SubjectPublicKeyInfo`.

User `{CLIENT_AUTH}` is classified as an engineering identity-credential profile and never as paper-required user mTLS. The exact positive, half-open-boundary, 31-case negative, malformed-input, and exception assertions are the code blocks in this task.

The helper's complete positive builder is:

`tests/helpers/__init__.py` contains exactly:

```python
"""Test-only fixture builders; never imported by production packages."""

__all__: tuple[str, ...] = ()
```

```python
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from saga.crypto.certificates import IdentityKind, identity_uri

ROOT_BEFORE = datetime(2025, 1, 1, tzinfo=UTC)
ROOT_AFTER = datetime(2035, 1, 1, tzinfo=UTC)
LEAF_BEFORE = datetime(2026, 1, 1, tzinfo=UTC)
LEAF_AFTER = datetime(2027, 1, 1, tzinfo=UTC)
NOW_MS = 1_767_225_600_000


@dataclass(frozen=True, slots=True)
class LeafFixture:
    der: bytes
    spki_der: bytes
    kind: IdentityKind
    identifier: str


@dataclass(frozen=True, slots=True)
class ValidationCase:
    leaf_der: bytes
    anchor_der: bytes
    kind: IdentityKind
    identifier: str
    expected_spki_der: bytes
    now_ms: int


@dataclass(frozen=True, slots=True)
class CertificateFixtureSet:
    anchor_der: bytes
    now_ms: int
    user: LeafFixture
    provider: LeafFixture
    agent: LeafFixture
    negative: Mapping[str, ValidationCase]


def _private(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _anchor_usage() -> x509.KeyUsage:
    return x509.KeyUsage(False, False, False, False, False, True, True, False, False)


def _leaf_usage() -> x509.KeyUsage:
    return x509.KeyUsage(True, False, False, False, False, False, False, False, False)


def _build_anchor(
    key: Ed25519PrivateKey,
    *,
    include_bc: bool = True,
    ca: bool = True,
    path_length: int | None = 0,
    bc_critical: bool = True,
    include_ku: bool = True,
    key_usage: x509.KeyUsage | None = None,
    ku_critical: bool = True,
    not_before: datetime = ROOT_BEFORE,
    not_after: datetime = ROOT_AFTER,
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAGA Phase 1 Test Root")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
        .not_valid_before(not_before).not_valid_after(not_after)
    )
    if include_bc:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=bc_critical)
    if include_ku:
        builder = builder.add_extension(key_usage or _anchor_usage(), critical=ku_critical)
    return builder.sign(key, algorithm=None)


def _eku(kind: IdentityKind) -> x509.ExtendedKeyUsage:
    values = {
        IdentityKind.USER: [ExtendedKeyUsageOID.CLIENT_AUTH],
        IdentityKind.PROVIDER: [ExtendedKeyUsageOID.SERVER_AUTH],
        IdentityKind.AGENT: [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
    }
    return x509.ExtendedKeyUsage(values[kind])


def _build_leaf(
    anchor: x509.Certificate,
    anchor_key: Ed25519PrivateKey,
    *,
    seed_byte: int,
    serial: int,
    kind: IdentityKind,
    identifier: str,
    issuer_name: x509.Name | None = None,
    signer_key: Ed25519PrivateKey | None = None,
    not_before: datetime = LEAF_BEFORE,
    not_after: datetime = LEAF_AFTER,
    include_bc: bool = True,
    ca: bool = False,
    bc_critical: bool = True,
    include_ku: bool = True,
    key_usage: x509.KeyUsage | None = None,
    ku_critical: bool = True,
    include_san: bool = True,
    san_names: list[x509.GeneralName] | None = None,
    san_critical: bool = False,
    include_eku: bool = True,
    eku: x509.ExtendedKeyUsage | None = None,
    eku_critical: bool = False,
) -> LeafFixture:
    key = _private(seed_byte)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identifier)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer_name or anchor.subject).public_key(key.public_key())
        .serial_number(serial).not_valid_before(not_before).not_valid_after(not_after)
    )
    if include_bc:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=bc_critical)
    if include_ku:
        builder = builder.add_extension(key_usage or _leaf_usage(), critical=ku_critical)
    if include_san:
        names = san_names or [x509.UniformResourceIdentifier(identity_uri(kind, identifier))]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=san_critical)
    if include_eku:
        builder = builder.add_extension(eku or _eku(kind), critical=eku_critical)
    certificate = builder.sign(signer_key or anchor_key, algorithm=None)
    return LeafFixture(
        certificate.public_bytes(Encoding.DER),
        key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
        kind,
        identifier,
    )


def build_certificate_fixtures() -> CertificateFixtureSet:
    root_key = _private(1)
    anchor = _build_anchor(root_key)
    anchor_der = anchor.public_bytes(Encoding.DER)
    user = _build_leaf(anchor, root_key, seed_byte=2, serial=2, kind=IdentityKind.USER, identifier="alice")
    provider = _build_leaf(
        anchor, root_key, seed_byte=3, serial=3,
        kind=IdentityKind.PROVIDER, identifier="provider-1",
    )
    agent = _build_leaf(
        anchor, root_key, seed_byte=4, serial=4,
        kind=IdentityKind.AGENT, identifier="alice:worker",
    )
    return CertificateFixtureSet(
        anchor_der, NOW_MS, user, provider, agent,
        MappingProxyType(_build_negative_cases(anchor, root_key, agent, anchor_der)),
    )


def _case(
    leaf: LeafFixture,
    anchor_der: bytes,
    *,
    identifier: str | None = None,
    spki: bytes | None = None,
    now_ms: int = NOW_MS,
) -> ValidationCase:
    return ValidationCase(
        leaf.der, anchor_der, leaf.kind, identifier or leaf.identifier,
        spki or leaf.spki_der, now_ms,
    )


def _build_negative_cases(
    anchor: x509.Certificate,
    root_key: Ed25519PrivateKey,
    agent: LeafFixture,
    anchor_der: bytes,
) -> dict[str, ValidationCase]:
    def leaf(serial: int, **kwargs: Any) -> LeafFixture:
        return _build_leaf(
            anchor, root_key, seed_byte=20 + serial, serial=100 + serial,
            kind=IdentityKind.AGENT, identifier="alice:worker", **kwargs,
        )

    alternate_key = _private(9)
    alternate_anchor = _build_anchor(alternate_key)
    alternate_der = alternate_anchor.public_bytes(Encoding.DER)
    bad_anchor_usage = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
    bad_leaf_usage = x509.KeyUsage(True, False, True, False, False, False, False, False, False)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong issuer")])
    cases = {
        "wrong_anchor": _case(agent, alternate_der),
        "wrong_issuer": _case(leaf(1, issuer_name=other_name), anchor_der),
        "bad_signature": _case(leaf(2, signer_key=alternate_key), anchor_der),
        "wrong_san": _case(agent, anchor_der, identifier="alice:other"),
        "multiple_saga_san": _case(leaf(3, san_names=[
            x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aworker"),
            x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aother"),
        ]), anchor_der),
        "dns_san_extra": _case(leaf(4, san_names=[
            x509.UniformResourceIdentifier("urn:saga:agent:alice%3Aworker"),
            x509.DNSName("example.test"),
        ]), anchor_der),
        "wrong_spki": _case(agent, anchor_der, spki=b"\x30\x00"),
        "expired_leaf": _case(agent, anchor_der, now_ms=1_798_761_600_000),
        "future_leaf": _case(agent, anchor_der, now_ms=1_735_689_600_000),
        "anchor_missing_bc": _case(agent, _build_anchor(root_key, include_bc=False).public_bytes(Encoding.DER)),
        "anchor_ca_false": _case(agent, _build_anchor(root_key, ca=False, path_length=None).public_bytes(Encoding.DER)),
        "anchor_bc_not_critical": _case(agent, _build_anchor(root_key, bc_critical=False).public_bytes(Encoding.DER)),
        "anchor_path_length_one": _case(agent, _build_anchor(root_key, path_length=1).public_bytes(Encoding.DER)),
        "anchor_missing_ku": _case(agent, _build_anchor(root_key, include_ku=False).public_bytes(Encoding.DER)),
        "anchor_ku_not_critical": _case(agent, _build_anchor(root_key, ku_critical=False).public_bytes(Encoding.DER)),
        "anchor_bad_key_usage": _case(agent, _build_anchor(root_key, key_usage=bad_anchor_usage).public_bytes(Encoding.DER)),
        "leaf_missing_bc": _case(leaf(5, include_bc=False), anchor_der),
        "leaf_ca_true": _case(leaf(6, ca=True), anchor_der),
        "leaf_bc_not_critical": _case(leaf(12, bc_critical=False), anchor_der),
        "leaf_missing_ku": _case(leaf(7, include_ku=False), anchor_der),
        "leaf_ku_not_critical": _case(leaf(13, ku_critical=False), anchor_der),
        "leaf_bad_key_usage": _case(leaf(8, key_usage=bad_leaf_usage), anchor_der),
        "leaf_missing_san": _case(leaf(9, include_san=False), anchor_der),
        "leaf_san_critical": _case(leaf(14, san_critical=True), anchor_der),
        "leaf_missing_eku": _case(leaf(10, include_eku=False), anchor_der),
        "leaf_eku_critical": _case(leaf(15, eku_critical=True), anchor_der),
        "leaf_wrong_eku": _case(leaf(11, eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])), anchor_der),
        "malformed_leaf_der": ValidationCase(b"not-der", anchor_der, agent.kind, agent.identifier, agent.spki_der, NOW_MS),
        "malformed_anchor_der": ValidationCase(agent.der, b"not-der", agent.kind, agent.identifier, agent.spki_der, NOW_MS),
    }
    cases["expired_anchor"] = _case(agent, _build_anchor(root_key, not_after=LEAF_BEFORE).public_bytes(Encoding.DER))
    cases["future_anchor"] = _case(agent, _build_anchor(root_key, not_before=LEAF_AFTER).public_bytes(Encoding.DER))
    return cases
```


- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_certificates.py -q`

Expected: collection FAIL because the certificate module is absent.

- [ ] **Step 3: Implement explicit identity URI encoding**

```python
import hmac
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeVar
from urllib.parse import quote

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from saga.domain.encoding import require_unix_ms


class CertificateValidationError(ValueError):
    """A certificate fails the closed SAGA validation profile."""


class IdentityKind(StrEnum):
    USER = "user"
    PROVIDER = "provider"
    AGENT = "agent"


def identity_uri(kind: IdentityKind, identifier: str) -> str:
    """Return urn:saga:<kind>:<percent-encoded UTF-8 identifier>."""
    try:
        if (
            not isinstance(kind, IdentityKind)
            or not isinstance(identifier, str)
            or not identifier
            or any(unicodedata.category(c) == "Cc" for c in identifier)
        ):
            raise CertificateValidationError("certificate identity invalid")
        return f"urn:saga:{kind.value}:{quote(identifier, safe='-._~')}"
    except CertificateValidationError:
        raise
    except (TypeError, ValueError):
        raise CertificateValidationError("certificate identity invalid") from None
```

- [ ] **Step 4: Implement closed validation against one trust anchor**

```python
_EXPECTED_EKU = {
    IdentityKind.USER: frozenset({ExtendedKeyUsageOID.CLIENT_AUTH}),
    IdentityKind.PROVIDER: frozenset({ExtendedKeyUsageOID.SERVER_AUTH}),
    IdentityKind.AGENT: frozenset(
        {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
    ),
}

T = TypeVar("T", bound=x509.ExtensionType)


def _extension(
    certificate: x509.Certificate, extension_type: type[T], *, critical: bool
) -> x509.Extension[T]:
    extension = certificate.extensions.get_extension_for_class(extension_type)
    if extension.critical is not critical:
        raise CertificateValidationError("certificate extension criticality invalid")
    return extension


def _key_usage_values(usage: x509.KeyUsage) -> tuple[bool, ...]:
    encipher_only = usage.encipher_only if usage.key_agreement else False
    decipher_only = usage.decipher_only if usage.key_agreement else False
    return (
        usage.digital_signature,
        usage.content_commitment,
        usage.key_encipherment,
        usage.data_encipherment,
        usage.key_agreement,
        usage.key_cert_sign,
        usage.crl_sign,
        encipher_only,
        decipher_only,
    )


def _anchor_key_usage_is_exact(usage: x509.KeyUsage) -> bool:
    return _key_usage_values(usage) == (False, False, False, False, False, True, True, False, False)


def _leaf_key_usage_is_exact(usage: x509.KeyUsage) -> bool:
    return _key_usage_values(usage) == (True, False, False, False, False, False, False, False, False)

def load_der_certificate(data: bytes) -> x509.Certificate:
    try:
        if type(data) is not bytes or not data:
            raise CertificateValidationError("certificate encoding invalid")
        return x509.load_der_x509_certificate(data)
    except CertificateValidationError:
        raise
    except (OSError, OverflowError, TypeError, UnsupportedAlgorithm, ValueError):
        raise CertificateValidationError("certificate encoding invalid") from None

def validate_leaf_certificate(
    *,
    leaf_der: bytes,
    trust_anchor_der: bytes,
    expected_kind: IdentityKind,
    expected_identifier: str,
    expected_public_key_spki_der: bytes,
    now_ms: int,
) -> None:
    try:
        if not isinstance(expected_kind, IdentityKind):
            raise CertificateValidationError("certificate identity invalid")
        if type(expected_public_key_spki_der) is not bytes or not expected_public_key_spki_der:
            raise CertificateValidationError("certificate key binding invalid")
        leaf = load_der_certificate(leaf_der)
        anchor = load_der_certificate(trust_anchor_der)
        now = datetime.fromtimestamp(require_unix_ms(now_ms, "now_ms") / 1000, UTC)
        expected_uri = identity_uri(expected_kind, expected_identifier)
        anchor_bc = _extension(anchor, x509.BasicConstraints, critical=True).value
        leaf_bc = _extension(leaf, x509.BasicConstraints, critical=True).value
        anchor_ku = _extension(anchor, x509.KeyUsage, critical=True).value
        leaf_ku = _extension(leaf, x509.KeyUsage, critical=True).value
        if (
            not anchor_bc.ca or anchor_bc.path_length != 0 or leaf_bc.ca
            or leaf.issuer != anchor.subject or anchor.subject != anchor.issuer
        ):
            raise CertificateValidationError("certificate chain invalid")
        anchor.verify_directly_issued_by(anchor)
        leaf.verify_directly_issued_by(anchor)
        if not (
            anchor.not_valid_before_utc <= now < anchor.not_valid_after_utc
            and leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc
        ):
            raise CertificateValidationError("certificate validity invalid")
        if not _anchor_key_usage_is_exact(anchor_ku) or not _leaf_key_usage_is_exact(leaf_ku):
            raise CertificateValidationError("certificate usage invalid")
        eku = _extension(leaf, x509.ExtendedKeyUsage, critical=False).value
        if frozenset(eku) != _EXPECTED_EKU[expected_kind]:
            raise CertificateValidationError("certificate usage invalid")
        general_names = _extension(leaf, x509.SubjectAlternativeName, critical=False).value
        uris = general_names.get_values_for_type(x509.UniformResourceIdentifier)
        if len(general_names) != 1 or uris != [expected_uri]:
            raise CertificateValidationError("certificate identity invalid")
        actual_spki = leaf.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        if not hmac.compare_digest(actual_spki, expected_public_key_spki_der):
            raise CertificateValidationError("certificate key binding invalid")
    except CertificateValidationError:
        raise
    except (
        AttributeError,
        InvalidSignature,
        OSError,
        OverflowError,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.ExtensionNotFound,
    ):
        raise CertificateValidationError("certificate validation failed") from None
```

```python
@pytest.mark.parametrize("data", [object(), "der", b""])
def test_load_der_rejects_bad_input(data: object) -> None:
    with pytest.raises(CertificateValidationError):
        load_der_certificate(data)


@pytest.mark.parametrize("error", [OSError(), OverflowError(), TypeError(), UnsupportedAlgorithm(), ValueError()])
def test_der_library_errors_are_normalized(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def raise_error(_: bytes) -> x509.Certificate:
        raise error
    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_error)
    with pytest.raises(CertificateValidationError):
        load_der_certificate(b"not-empty")


@pytest.mark.parametrize("error", [MemoryError(), KeyboardInterrupt(), SystemExit()])
def test_der_system_exceptions_propagate(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    def raise_error(_: bytes) -> x509.Certificate:
        raise error
    monkeypatch.setattr(x509, "load_der_x509_certificate", raise_error)
    with pytest.raises(type(error)):
        load_der_certificate(b"not-empty")


@pytest.mark.parametrize("identifier", ["", "a\x00", "a\x7f", "a\u0085", "\ud800"])
def test_identity_input_failures(identifier: str) -> None:
    with pytest.raises(CertificateValidationError):
        identity_uri(IdentityKind.AGENT, identifier)
```

- [ ] **Step 5: Classify the certificate profile as a reproduction supplement**

In `docs/feature-source-matrix.md`, replace exactly the following three rows. These
replacements change only `复现工程补充`; they retain the exact four-column header
`功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展` and do not move any engineering
choice into `论文原始设计` or any baseline behavior into `后续创新扩展`:

```markdown
| User signature key and certificate | The User generates a signing key pair and obtains `Cert_U` binding `uid_U` to the public key (IV-B Steps 1-2; Fig. 7). | Use a test CA and mature certificate/signature libraries. Phase 1 Task 9 validates User certificate DER, SPKI binding, the single-root URI-SAN BC/KU/EKU profile, and half-open validity only at the certificate boundary. | Hardware-backed User keys and external PKI profiles. |
| Provider identity, certificate, and signing key | The User retrieves and verifies the Provider certificate/public key for TLS; the Provider signs registered Agent information (IV-B Step 3; IV-C Step 7; Figs. 7-8). | Provision a test-CA X.509 identity and separate signing-key configuration for the Provider. Phase 1 Task 3 treats the tuple's `provider_public_key` as opaque non-empty bytes; Task 9 separately owns certificate DER parsing, SPKI binding, the single-root URI-SAN BC/KU/EKU profile, and half-open validity. | Multi-Provider trust anchors. |
| Agent TLS credential and certificate | The User creates Agent TLS credentials and `Cert_A`; the Provider verifies the certificate during registration and peers verify certificates during communication (IV-C Steps 1-2, 5-6; IV-E Steps 3-6; Figs. 8-9). | Use test-CA X.509 certificates and real TLS endpoints. Phase 1 Task 3 treats `agent_tls_public_key` and `agent_certificate` tuple members as opaque non-empty bytes; Task 9 exclusively owns certificate DER parsing, SPKI binding, the single-root URI-SAN BC/KU/EKU profile, and half-open validity. | Production CA enrollment and automated rotation. |
```

Run the material check:

```powershell
rg -ni --hidden 'BEGIN[[:space:]].*PRIVATE KEY|PRIVATE KEY-----|never-log-me|correct horse' src tests/vectors
rg -ni --hidden '"(password|private_key|secret|seed)"[[:space:]]*:' tests/vectors
Get-ChildItem -Recurse tests -File | Where-Object {
  $_.Extension -in '.pem','.key','.p12','.pfx' -or $_.Name -match 'private'
}
```

Expected: both scans return zero matches and the file query returns no files. Synthetic test seeds occur only in `tests/helpers/certificates.py`, remain in memory, and are allowed by the explicit test-material rule.

- [ ] **Step 6: Run focused and accumulated gates**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_certificates.py -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

Expected: all three positive identities, both validity boundaries, every named negative fixture, and accumulated tests exit 0; mypy and both Ruff commands exit 0.

- [ ] **Step 7: Commit certificate validation**

```powershell
git add src/saga/crypto/certificates.py tests/helpers tests/unit/test_certificates.py docs/feature-source-matrix.md
git commit -m "feat: validate SAGA certificate bindings"
```

---

### Task 10: Freeze Public API, Audit Dependencies, and Produce Phase 1 Evidence

**Files:**
- Modify: `src/saga/domain/__init__.py`
- Modify: `src/saga/crypto/__init__.py`
- Modify: `docs/feature-source-matrix.md`
- Create: `tests/unit/test_public_api.py`
- Create: `tests/unit/test_phase_one_scope.py`
- Create: `docs/phase-1-verification.md`

**Interfaces:**
- Consumes: every Task 2–9 stable interface and vector.
- Produces: the convenience top-level `saga.crypto` surface, the separate supported persistence surface `saga.crypto.passwords`, and the ten-part evidence report.

- [ ] **Step 1: Write failing public API and scope tests**

`tests/unit/test_public_api.py` contains:

```python
import saga.crypto as crypto
import saga.domain as domain
from saga.crypto import passwords


def test_crypto_public_api_is_exact() -> None:
    expected = (
        "ActEnvelope", "ActPlaintext", "AeadError", "AgentUserAttestation",
        "CanonicalEncodingError", "CertificateValidationError", "IdentityKind",
        "KeyAgreementError", "KeyDerivationError", "OtkAttestation",
        "ProviderAttestation", "SignatureError",
        "decode_act_plaintext", "decode_agent_user_attestation",
        "decode_otk_attestation", "decode_provider_attestation", "decrypt_act",
        "derive_sdhk", "derive_shared_secret", "ed25519_public_key",
        "ed25519_public_key_bytes", "ed25519_public_key_from_bytes",
        "encode_act_plaintext",
        "encode_agent_user_attestation", "encode_otk_attestation",
        "encode_provider_attestation", "encrypt_act",
        "generate_ed25519_private_key", "generate_x25519_private_key",
        "identity_uri", "load_der_certificate", "sign",
        "validate_leaf_certificate", "verify",
        "x25519_public_key", "x25519_public_key_bytes",
        "x25519_public_key_from_bytes",
    )
    assert crypto.__all__ == expected
    assert len(crypto.__all__) == len(set(crypto.__all__))
    assert all(hasattr(crypto, name) for name in expected)
    assert not hasattr(crypto, "PasswordRecord")
    assert not hasattr(crypto, "hash_password")


def test_password_submodule_api_is_exact() -> None:
    assert passwords.__all__ == (
        "PasswordRecord", "PasswordRecordError", "hash_password", "verify_password"
    )
    assert all(hasattr(passwords, name) for name in passwords.__all__)


def test_domain_public_api_is_exact() -> None:
    expected = (
        "EncodingError", "EndpointValue", "b64url_decode", "b64url_encode",
        "require_unix_ms",
    )
    assert domain.__all__ == expected
    assert len(domain.__all__) == len(set(domain.__all__))
    assert all(hasattr(domain, name) for name in expected)

```

`tests/unit/test_phase_one_scope.py` contains its own import block:

```python
from pathlib import Path


def test_phase_one_has_no_runtime_or_protocol_layers() -> None:
    forbidden = ("protocols", "ports", "adapters", "http", "persistence")
    tracked = {path.as_posix() for path in Path("src/saga").rglob("*.py")}
    assert not any(f"/{name}/" in f"/{path}" for name in forbidden for path in tracked)
```

- [ ] **Step 2: Run and confirm red**

Run: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py tests/unit/test_phase_one_scope.py -q`

Expected: public API assertion FAIL because exports are not yet declared; scope test passes.

- [ ] **Step 3: Add exact tuple exports**

Create `saga.domain.__init__` exactly as follows:

```python
from .encoding import EncodingError, EndpointValue, b64url_decode, b64url_encode, require_unix_ms

__all__ = ("EncodingError", "EndpointValue", "b64url_decode", "b64url_encode", "require_unix_ms")
```

Create `saga.crypto.__init__` exactly as follows (the tuple body is identical to Step 1):

```python
from .aead import ActEnvelope, AeadError, decrypt_act, encrypt_act
from .canonical import (
    ActPlaintext,
    AgentUserAttestation,
    CanonicalEncodingError,
    OtkAttestation,
    ProviderAttestation,
    decode_act_plaintext,
    decode_agent_user_attestation,
    decode_otk_attestation,
    decode_provider_attestation,
    encode_act_plaintext,
    encode_agent_user_attestation,
    encode_otk_attestation,
    encode_provider_attestation,
)
from .certificates import (
    CertificateValidationError,
    IdentityKind,
    identity_uri,
    load_der_certificate,
    validate_leaf_certificate,
)
from .kdf import KeyDerivationError, derive_sdhk
from .key_agreement import (
    KeyAgreementError,
    derive_shared_secret,
    generate_x25519_private_key,
    x25519_public_key,
    x25519_public_key_bytes,
    x25519_public_key_from_bytes,
)
from .signatures import (
    SignatureError,
    ed25519_public_key,
    ed25519_public_key_bytes,
    ed25519_public_key_from_bytes,
    generate_ed25519_private_key,
    sign,
    verify,
)

__all__ = (
    "ActEnvelope", "ActPlaintext", "AeadError", "AgentUserAttestation",
    "CanonicalEncodingError", "CertificateValidationError", "IdentityKind",
    "KeyAgreementError", "KeyDerivationError", "OtkAttestation",
    "ProviderAttestation", "SignatureError", "decode_act_plaintext",
    "decode_agent_user_attestation", "decode_otk_attestation",
    "decode_provider_attestation", "decrypt_act", "derive_sdhk",
    "derive_shared_secret", "ed25519_public_key", "ed25519_public_key_bytes",
    "ed25519_public_key_from_bytes", "encode_act_plaintext",
    "encode_agent_user_attestation", "encode_otk_attestation",
    "encode_provider_attestation", "encrypt_act", "generate_ed25519_private_key",
    "generate_x25519_private_key", "identity_uri", "load_der_certificate", "sign",
    "validate_leaf_certificate", "verify", "x25519_public_key",
    "x25519_public_key_bytes", "x25519_public_key_from_bytes",
)
```

It contains no `.passwords` import. The test asserts `IdentityKind.PROVIDER.value == "provider"` and the separate password submodule tuple.

- [ ] **Step 4: Update source classification without changing the matrix columns**

In `docs/feature-source-matrix.md`, replace exactly the following seven rows. These
replacements change only `复现工程补充`; they preserve the exact four columns and
the existing reproduction/engineering/innovation classification. Task 9 already
owns the three certificate-row replacements above, so Task 10 must not edit them:

```markdown
| X25519 shared-secret derivation | Both Agents compute equivalent DH secrets from the initiator's long-term access-control key and receiver's OTK/SOTK (IV-E Step 6; Fig. 9). | Instantiate the abstract DH operation with X25519 and fixed test vectors. Phase 1 implements this supplement in `src/saga/crypto/key_agreement.py` with RFC 7748 equality vectors; PAC/OTK public values use raw X25519-32 bytes. | Hybrid post-quantum key agreement. |
| HKDF shared-key derivation | Both Agents apply a KDF to the DH result to obtain the same `SDHK` (III, KDF background; IV-E Step 6; Fig. 9). | Use HKDF-SHA256 with the fixed salt/info parameters classified below. Phase 1 implements the fixed-domain `derive_sdhk` wrapper and consumes a public deterministic vector. | Negotiated KDF suites. |
| Canonical serialization | The paper fixes signed/encrypted tuples but does not specify a byte serialization (IV-C Steps 2, 6-7; IV-E Step 7). | Use deterministic JSON with UTF-8, fixed field order, and no floating-point security fields. Phase 1 implements closed schemas and byte-exact vectors in `src/saga/crypto/canonical.py`; Task 3 keeps certificate/TLS-key tuple members opaque, while DER validation remains exclusively at Task 9's certificate boundary. | Standards-based canonical encodings. |
| Ed25519 choice | The protocol requires secure signatures and signature verification but does not mandate Ed25519 at the protocol layer (III, signatures; IV-B-C). | Use Ed25519 for User and Provider signatures and classify it as an engineering choice. Phase 1 implements the mature-library wrapper and public vectors in `src/saga/crypto/signatures.py`; `PK_Prov` is a raw 32-byte Ed25519 public key. | Algorithm agility and post-quantum signatures. |
| ChaCha20-Poly1305 choice and AAD | The ACT is abstractly encrypted under `SDHK`; the paper does not specify an AEAD or AAD (IV-E Step 7; Fig. 9). | Use ChaCha20-Poly1305 with `aad=b"SAGA-ACT/v1"`; reject nonce/ciphertext/AAD tampering. Phase 1 implements the closed versioned envelope in `src/saga/crypto/aead.py` and keeps the outer version and AEAD nonce outside the exact five-field ACT plaintext. | Negotiated AEAD suites. |
| HKDF salt/info domain separation | The paper derives `SDHK` with a KDF and describes HKDF-SHA256, but does not define salt/info domain separation (III, KDF background; IV-E Step 6). | Use HKDF-SHA256 with `salt=None` and `info=b"SAGA-ACT-DERIVE/v1"`. Phase 1 fixes the output length at 32 bytes and exposes no caller-controlled salt, info, or length. | Per-tenant or transcript-bound derivation contexts. |
| scrypt password record | The Provider stores a hash-derived password record and should follow password-management best practices (IV-B Steps 5-6; IV-D cryptographic key management; Fig. 7). | Use scrypt with `N=2^15, r=8, p=1, dkLen=32` and a fresh 16-byte random salt. Phase 1 implements the versioned, redacted persistence record in `src/saga/crypto/passwords.py`; it is supported only through `saga.crypto.passwords` and is not a top-level result DTO. | External passwordless authentication. |
```

- [ ] **Step 5: Run the complete Phase 1 verification suite from a clean process**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m pip check
git diff --check
rg -ni --hidden 'BEGIN[[:space:]].*PRIVATE KEY|PRIVATE KEY-----|never-log-me|correct horse' src tests/vectors
rg -ni --hidden '"(password|private_key|secret|seed)"[[:space:]]*:' tests/vectors
git status --short
```

Expected: pytest exits 0 with zero failures; mypy/Ruff/pip/diff checks exit 0; both case-insensitive secret/schema scans above have zero matches in production/vector material (synthetic test inputs remain only in test source); status shows only intended Task 10 files before commit.

Run this failing collection comparison rather than visually inspecting search output:

```powershell
$expected = @(
  'tests/vectors/canonical-tuples.json',
  'tests/vectors/ed25519-signatures.json',
  'tests/vectors/x25519-agreement.json',
  'tests/vectors/hkdf-sha256.json',
  'tests/vectors/chacha20-poly1305.json',
  'tests/vectors/scrypt-records.json'
) | Sort-Object
$actual = Get-ChildItem tests/vectors -Filter *.json -Recurse |
  ForEach-Object { $_.FullName.Substring((Get-Location).Path.Length + 1).Replace('\','/') } |
  Sort-Object
$difference = @(Compare-Object $expected $actual)
if ($difference.Count -ne 0) { throw "vector file set mismatch: $difference" }
.\.venv\Scripts\python.exe -m pytest tests/unit -q
```

Each owning test has an exact root/record-key assertion and `seen == expected_names`; therefore the pytest command is the executable loader/use gate, while `Compare-Object` proves there are no orphan or undeclared JSON files.

- [ ] **Step 6: Audit implementation ownership and dependencies**

Run:

```powershell
rg -n "Ed25519|X25519|HKDF|ChaCha20Poly1305|Scrypt|x509" src/saga/crypto
rg -n "def .*sha|def .*curve|def .*poly1305|modular|scalar" src/saga/crypto
.\.venv\Scripts\python.exe -m pip freeze --all --exclude-editable
```

Then perform a canonical lock comparison without machine paths:

```powershell
.\.venv\Scripts\python.exe -m pip freeze --all --exclude-editable |
  Sort-Object -CaseSensitive:$false |
  Set-Content -Encoding utf8 .superpowers\sdd\phase1-freeze.normalized.txt
git diff --no-index -- requirements.lock .superpowers\sdd\phase1-freeze.normalized.txt
rg -ni "(^-e|file:|[A-Z]:\\|SAGA，A Security)" requirements.lock
```

Expected: primitive calls resolve to `cryptography`; no custom primitive pattern is present; normalized diff exits 0; the path/editable scan has zero matches. The normalized scratch file is under ignored `.superpowers/` and is never staged.

- [ ] **Step 7: Write the ten-part Phase 1 verification report**

Create the report from this exact template, replacing every bracketed evidence value with observed data before commit; the final placeholder scan rejects any remaining `[` evidence marker:

```markdown
# SAGA Phase 1 Verification

## 1. Completed work
- Scope: canonical encoding, four paper tuples, Ed25519, X25519, HKDF, AEAD, scrypt, X.509 validation.
- Phase boundary: library/vector behavior only.

## 2. Files created/modified
| Path | Action | Responsibility |
|---|---|---|
| [observed path] | [created/modified] | [single responsibility] |

## 3. Paper/source-matrix mapping
| Mechanism | Paper location | Engineering supplement | Test evidence |
|---|---|---|---|
| [mechanism] | [section/step] | [choice] | [test node] |

## 4. Engineering decisions used
| Decision | Exact value | Classification |
|---|---|---|
| [decision] | [value] | 复现工程补充 |

## 5. Commands executed
| Command | UTC timestamp | Exit code |
|---|---|---:|
| [exact command] | [timestamp] | [code] |

## 6. Test results with exact counts and exit codes
| Gate | Passed | Failed | Skipped | Exit code |
|---|---:|---:|---:|---:|
| pytest | [count] | 0 | 0 | 0 |
| mypy | [files/modules] | 0 | n/a | 0 |
| Ruff check/format | [observed] | 0 | n/a | 0 |

## 7. Unresolved paper limitations
- ACT has no task field; no request-level replay detection is claimed.
- [additional evidence-backed limitation]

## 8. Known differences from the paper
- Concrete algorithms, canonical encoding, certificate profile, AAD and KDF domain are engineering supplements.
- [additional known difference]

## 9. Phase 2 plan boundary
- Authorized next action after acceptance: plan User and Agent registration.
- Not authorized: Contact Policy, OTK state, ACT lifecycle, mTLS service, attacks, ProVerif, performance, baseline tag, or innovation branch.

## 10. User acceptance question
Do you accept Phase 1 evidence and authorize Phase 2 planning?
```

Before commit run `rg -n '\[(observed|created|modified|single responsibility|mechanism|section/step|choice|test node|decision|value|exact command|timestamp|code|count|files/modules|additional)' docs/phase-1-verification.md` and require zero matches.

- [ ] **Step 8: Run independent review and final clean verification**

Use the Subagent-Driven whole-branch review package from the Phase 1 base commit to HEAD. Fix every Critical/Important issue through one fresh fix subagent and re-review until the assessment is Ready. Then rerun Step 5 from scratch; do not reuse cached reviewer claims.

- [ ] **Step 9: Commit the Phase 1 evidence gate**

```powershell
git add src/saga/domain/__init__.py src/saga/crypto/__init__.py tests/unit/test_public_api.py tests/unit/test_phase_one_scope.py docs/feature-source-matrix.md docs/phase-1-verification.md
git commit -m "docs: verify SAGA phase one foundations"
```

Expected: worktree clean; no `saga-baseline-v1` tag and no `feature/agent-tool-authorization` branch exist.

---

## Phase 1 Execution and Acceptance Gate

Phase 1 is complete only when all ten tasks have focused review approval, the whole-branch reviewer reports no Critical or Important issue, the complete unit/vector suite and static gates pass from a clean environment, the dependency lock matches the environment, secret scans are clean, and the ten-part report is accepted by the user.

Acceptance of Phase 1 authorizes planning Phase 2 only. It does not authorize protocol implementation beyond Phase 1, tagging `saga-baseline-v1`, or creating the Agent tool-authorization branch.
