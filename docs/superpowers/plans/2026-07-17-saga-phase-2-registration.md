# SAGA Phase 2: User and Agent Registration Implementation Plan

> Status: planning artifact only. Creating or accepting this plan does not authorize Phase 3, a baseline tag, an innovation branch, or Agent-to-Tool authorization work.

## 1. Objective

Implement the paper's User Registration (IV-B Steps 1-6) and Agent Registration (IV-C Steps 1-7) as a pure Python protocol core with deterministic tests, in-memory persistence, and SQLite persistence.

Phase 2 must prove that:

- a User is registered only after identity, certificate, uniqueness, and password-record checks succeed;
- an Agent is registered only after owner authentication, global identity/endpoint uniqueness, certificate validation, exact User metadata signature verification, every exact OTK signature verification, and Provider attestation creation succeed;
- registration is all-or-nothing in both memory and SQLite;
- User passwords, private keys, SOTKs, and other secrets never enter public protocol results, events, exceptions, or test logs; the internal User Registry record necessarily carries the redacted-at-representation password persistence value required for later authentication;
- the main-text IV-C Step 7 Provider tuple is used, while Appendix Figure 8 remains documented as inconsistent;
- Contact Policy and public OTK material are registered but not interpreted, allocated, consumed, refreshed, or updated in this phase.

The implementation remains on `main`, as previously approved. Do not create `saga-baseline-v1`, `feature/agent-tool-authorization`, or any other branch/tag in Phase 2.

## 2. Normative sources and precedence

Use this precedence whenever sources conflict:

1. Paper main-text formulas and numbered protocol steps.
2. Paper figures and notation.
3. Approved reproduction design and ambiguity decisions.
4. Engineering constraints in the feature-source matrix.

Required source mapping:

| Scope | Source |
|---|---|
| User registration | Paper IV-B Steps 1-6; Appendix Figure 7 |
| Agent registration | Paper IV-C Steps 1-7; Appendix Figure 8 |
| Exact signed tuples | `docs/protocol-messages.md`; Phase 1 canonical vectors |
| Figure 8 conflict | `docs/ambiguities-and-decisions.md` Decision 1 |
| External identity assumption | Decision 13; `IdentityVerifier` substitute only |
| CA placement/profile | Decision 14 and Phase 1 X.509 profile |
| Architecture boundaries | `docs/architecture.md` |
| Phase boundary | `docs/implementation-plan.md`, Phase 2 |
| Classification | `docs/feature-source-matrix.md` |

## 3. Approach decision

### Option A - Complete vertical registration core (selected)

Build immutable registration models, ports, User and Agent protocol services, memory persistence, SQLite persistence, protocol coverage tests, rollback/restart tests, and final evidence. Preserve `CP_A` and signed public OTKs as registration material only.

This option best matches the paper and the approved Phase 2 exit gate. It provides persistence evidence without introducing network or authorization behavior.

### Option B - In-memory registration only

This reduces implementation time but cannot prove restart, transaction rollback, uniqueness constraints, or memory/SQLite parity. It does not satisfy the approved exit gate.

### Option C - Registration plus Contact Policy and OTK lifecycle

This would reduce later schema migration, but it would mix Phase 2 with Phase 3. It is explicitly rejected.

## 4. Frozen Phase 2 boundary

### 4.1 Included

- validated `UserId`, `AgentId`, and existing `EndpointValue`;
- immutable User and Agent registration records;
- stable registration failures and secret-safe audit event DTOs;
- `IdentityVerifier`, `Clock`, `RandomSource`, User Registry, Agent Registry, and atomic registration commit ports;
- User certificate validation and extraction of its Ed25519 public key;
- User registration with scrypt password records;
- User authentication for Agent registration;
- Agent certificate validation and extraction of `PK_A`;
- exact verification of `sigma_A^U` and every `sigma_OTKi^U`;
- exact main-text Provider signature `sigma_A^Prov`;
- global uniqueness of `aid_A` and `ED_A`;
- atomic memory and SQLite registration;
- restart, rollback, parity, tamper, and secret-redaction tests;
- feature-source matrix and Phase 2 verification report updates.

### 4.2 Registration-only representations

`CP_A` is required by IV-C, but policy syntax and matching belong to Phase 3. Phase 2 stores it as an immutable, bounded, non-empty UTF-8 byte document named `contact_policy_document`. Phase 2 does not parse rules, choose specificity, interpret budgets, recognize deny values, or update policy.

Public OTKs and their User signatures are required by IV-C. Phase 2 verifies and stores an immutable ordered tuple of unique signed public OTK records. It does not add available/issued/consumed state, allocate an OTK, decrement a counter, replenish a pool, or expose a contact-resolution query.

These are complete registration records, not placeholder authorization behavior.

### 4.3 Excluded

- Contact Policy rule models, wildcard matching, specificity, tie handling, budget semantics, or updates;
- OTK availability state, allocation, issue, consumption, refresh, pair counters, or concurrency;
- Agent deactivation or key rotation;
- ACT creation, encryption flow, state, lifetime, `q_max`, binding, reuse, or revocation;
- FastAPI, Pydantic transport DTOs, TLS listeners, mTLS, HTTP status mapping, or Docker;
- attack-suite execution, ProVerif, performance benchmarks, or demo orchestration;
- external OpenID Connect, proof-of-personhood, or Sybil-resistance claims;
- task/tool/operation/parameter/resource/delegation fields;
- innovation implementation of any kind.

## 5. Frozen data and service contracts

The implementation agent must first encode these contracts as failing tests. A later change requires an explicit plan amendment and user approval.

### 5.1 Domain values

```python
@dataclass(frozen=True, slots=True)
class UserId:
    value: str

@dataclass(frozen=True, slots=True)
class AgentId:
    owner: UserId
    name: str

    @property
    def value(self) -> str: ...  # exactly "<uid_U>:<name_A>"

@dataclass(frozen=True, slots=True, repr=False)
class StoredPasswordRecord:
    version: int
    n: int
    r: int
    p: int
    dklen: int
    salt: bytes
    verifier: bytes

@dataclass(frozen=True, slots=True, repr=False)
class UserRegistration:
    user_id: UserId
    password_record: StoredPasswordRecord
    certificate_der: bytes

@dataclass(frozen=True, slots=True)
class RegisteredPublicOtk:
    public_key: bytes       # exact plain bytes32
    user_signature: bytes   # exact plain bytes64

@dataclass(frozen=True, slots=True, repr=False)
class AgentRegistration:
    agent_id: AgentId
    owner_id: UserId
    endpoint: EndpointValue
    certificate_der: bytes
    access_control_public_key: bytes
    contact_policy_document: bytes
    public_otks: tuple[RegisteredPublicOtk, ...]
    user_metadata_signature: bytes
```

Validation decisions classified as reproduction engineering supplements:

- identifiers are non-empty UTF-8 strings, reject control characters and leading/trailing whitespace; `UserId` is at most 254 UTF-8 bytes and Agent name is at most 128 UTF-8 bytes;
- `UserId` and Agent name reject `:` so `aid_A` has exactly one unambiguous separator;
- `AgentId.owner` must equal the authenticated owner;
- `EndpointValue` remains the Phase 1 canonical device/IP/port value;
- public access-control and OTK keys require exact plain `bytes` length 32;
- Ed25519 signatures require exact plain `bytes` length 64;
- the OTK tuple contains 1 through 1,024 entries and duplicate public OTK values are rejected;
- `contact_policy_document` is exact plain `bytes`, 1 through 65,536 bytes, and strict UTF-8, but is otherwise opaque;
- a registration password is non-empty and at most 1,024 UTF-8 bytes;
- each User or Agent certificate is exact plain `bytes`, 1 through 16,384 bytes;
- secret-bearing records use redacted `repr` and never expose raw password verifiers in results.

`StoredPasswordRecord` is a framework-neutral structural persistence value and is not added to the `saga.domain` convenience exports. `saga.domain` must not import `saga.crypto` or `cryptography`. The User registration protocol explicitly converts between this value and `saga.crypto.passwords.PasswordRecord`, with exact round-trip tests; scrypt computation and validation remain owned only by `saga.crypto.passwords`.

### 5.2 Commands and results

```python
@dataclass(frozen=True, slots=True, repr=False)
class RegisterUserCommand:
    user_id: UserId
    password: str
    certificate_der: bytes

@dataclass(frozen=True, slots=True)
class UserRegistered:
    user_id: UserId

@dataclass(frozen=True, slots=True, repr=False)
class RegisterAgentCommand:
    owner_id: UserId
    password: str
    agent_id: AgentId
    endpoint: EndpointValue
    certificate_der: bytes
    access_control_public_key: bytes
    contact_policy_document: bytes
    public_otks: tuple[RegisteredPublicOtk, ...]
    user_metadata_signature: bytes

@dataclass(frozen=True, slots=True)
class AgentRegistered:
    agent_id: AgentId
    provider_attestation_signature: bytes
```

No command accepts User or Agent private keys, `SAC_A`, SOTKs, ACT data, policy decisions, or transport identity.

The Provider attestation is deliberately absent from `AgentRegistration` and the Provider Registry schema. IV-C Step 7 returns `sigma_A^Prov` for the User/Agent to retain; the paper's `D_A` formula does not store it. Phase 2 returns it only in `AgentRegistered`. Persisting it at the Provider would be a new recovery design and is not added.

### 5.3 Certificate extraction

Do not add a `PK_U` or `PK_A` wire field merely to satisfy the implementation. The paper sends certificates; their public keys are extracted after certificate validation.

Refactor `src/saga/crypto/certificates.py` so the existing public `validate_leaf_certificate(...) -> None` remains backward-compatible. Add one narrow public helper that validates the same closed profile and returns the exact raw 32-byte Ed25519 leaf public key. The implementation must share one internal validation path so profile, time, chain, identity, and extension checks cannot diverge.

### 5.4 Ports

```python
class IdentityVerifier(Protocol):
    def verify(self, user_id: UserId) -> bool: ...

class Clock(Protocol):
    def now_ms(self) -> int: ...

class RandomSource(Protocol):
    def bytes(self, length: int) -> bytes: ...

class ProviderSigner(Protocol):
    def public_key_bytes(self) -> bytes: ...
    def sign(self, message: bytes) -> bytes: ...

class UserCreateOutcome(StrEnum):
    CREATED = "created"
    USER_ID_CONFLICT = "user_id_conflict"

class AgentCreateOutcome(StrEnum):
    CREATED = "created"
    AGENT_ID_CONFLICT = "agent_id_conflict"
    ENDPOINT_CONFLICT = "endpoint_conflict"

class UserRegistry(Protocol):
    def get(self, user_id: UserId) -> UserRegistration | None: ...
    def create_if_absent(self, registration: UserRegistration) -> UserCreateOutcome: ...

class AgentRegistry(Protocol):
    def get(self, agent_id: AgentId) -> AgentRegistration | None: ...
    def create_if_unique(self, registration: AgentRegistration) -> AgentCreateOutcome: ...
```

`src/saga/ports/transactions.py` owns exactly these two closed outcome enums and no transaction manager/context API. `create_if_absent` and `create_if_unique` are the atomic transaction-intent methods. If an Agent input collides on both fields, `AGENT_ID_CONFLICT` wins. Storage/connection/commit/corruption failures are never enum outcomes: adapters raise the fixed `RegistrationPersistenceError("registration persistence failed")` without chained backend details. Stores enforce structure and uniqueness; protocol services own certificate, credential, signature, ownership, and registration decisions.

Freeze service construction as follows; implementations must not invent additional request fields or ambient global dependencies:

```python
UserRegistrationService(
    *,
    identity_verifier: IdentityVerifier,
    user_registry: UserRegistry,
    clock: Clock,
    random_source: RandomSource,
    trust_anchor_der: bytes,
)

AgentRegistrationService(
    *,
    user_registry: UserRegistry,
    agent_registry: AgentRegistry,
    clock: Clock,
    trust_anchor_der: bytes,
    provider_signer: ProviderSigner,
)
```

The concrete `Ed25519ProviderSigner` adapter owns the Provider private key and delegates public-key extraction/signing to Phase 1 wrappers. The Agent service obtains raw `PK_Prov` from that same signer and uses it in `sigma_A^U` verification. It never accepts a caller-supplied Provider public key or private key. Both services receive all time, randomness, trust, signing, and persistence dependencies explicitly; no filesystem, environment, network, or singleton lookup is allowed.

Phase 2 defines a secret-safe registration event DTO schema only. It does not add a logging backend or `EventSink`, and no matrix/report text may claim that structured logging has been implemented. Event emission is deferred until an adapter/service integration phase has an explicit sink contract.

### 5.5 Failure surface

Define stable registration errors with fixed public messages and no chained backend details:

- invalid registration input;
- identity verification rejected;
- User registration already exists;
- Agent owner authentication failed;
- Agent registration verification failed;
- Agent identifier already exists;
- Agent endpoint already exists;
- registration persistence failed.

Certificate/profile and signature failures may remain distinct internally for tests, but the Agent registration service must expose one coarse verification failure so it does not become a certificate/signature oracle. `MemoryError`, `KeyboardInterrupt`, and `SystemExit` propagate.

### 5.6 Protocol ordering

User registration:

1. validate command shape;
2. call `IdentityVerifier` for `uid_U`;
3. validate `Cert_U` identity/profile/time and obtain `PK_U`;
4. derive scrypt password record using injected randomness;
5. atomically create `D_U[uid_U]` if absent;
6. return only `UserRegistered(user_id)`.

Agent registration:

1. validate command shape and owner/Agent-ID relationship;
2. load the owner User record;
3. verify the password with the stored scrypt record;
4. validate `Cert_U` and obtain `PK_U`;
5. validate `Cert_A` for `aid_A` and obtain `PK_A`;
6. canonicalize and verify `sigma_A^U` over exactly `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>`;
7. canonicalize and verify every `sigma_OTKi^U` over exactly `<aid_A, OTK_A^i>`;
8. sign exactly `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>` with `SK_Prov`;
9. atomically insert the complete paper `D_A` registration record, all public OTK rows, and User signatures only if `aid_A` and `ED_A` are globally unique;
10. return only `AgentRegistered(agent_id, provider_attestation_signature)`.

All validation and Provider signing occur before the persistence commit. A signing failure leaves no Agent record.

## 6. SQLite schema boundary

Use built-in `sqlite3`; do not add an ORM.

Minimum registration-only tables:

```text
users
  user_id TEXT PRIMARY KEY
  certificate_der BLOB NOT NULL
  password_version INTEGER NOT NULL
  password_n INTEGER NOT NULL
  password_r INTEGER NOT NULL
  password_p INTEGER NOT NULL
  password_dklen INTEGER NOT NULL
  password_salt BLOB NOT NULL
  password_verifier BLOB NOT NULL

agents
  agent_id TEXT PRIMARY KEY
  owner_id TEXT NOT NULL REFERENCES users(user_id)
  endpoint_device TEXT NOT NULL
  endpoint_ip TEXT NOT NULL
  endpoint_port INTEGER NOT NULL
  certificate_der BLOB NOT NULL
  access_control_public_key BLOB NOT NULL
  contact_policy_document BLOB NOT NULL
  user_metadata_signature BLOB NOT NULL
  UNIQUE(endpoint_device, endpoint_ip, endpoint_port)

registered_public_otks
  agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE
  ordinal INTEGER NOT NULL
  public_key BLOB NOT NULL
  user_signature BLOB NOT NULL
  PRIMARY KEY(agent_id, ordinal)
  UNIQUE(agent_id, public_key)
```

No table/column may contain pair counters, policy versions, active/deactivated states, OTK issued/consumed state, SOTKs, ACTs, quota, tasks, tools, or innovation data.

SQLite requirements:

- `PRAGMA foreign_keys=ON` for every connection;
- explicit transaction for complete Agent registration;
- deterministic schema initialization and version marker;
- no implicit auto-commit between Agent and OTK rows;
- conflict ordering is deterministic and identical across adapters: within one lock/`BEGIN IMMEDIATE` transaction, check Agent ID first and endpoint second, so an input colliding on both reports the Agent-ID conflict;
- rollback on any insert, constraint, serialization, or commit failure;
- reconstruction validates persisted records and fails closed on corruption;
- restart tests reopen a new connection and compare domain records;
- no database exception text reaches protocol results.

## 7. Task execution rules

For every task:

1. the implementer writes the named tests first;
2. run the focused command and preserve the expected RED evidence;
3. implement only enough for GREEN;
4. run focused tests, full unit/protocol tests, mypy, Ruff check, and Ruff format check;
5. self-review scope and secret handling;
6. a separate reviewer inspects the exact task diff;
7. address all Critical/Important findings and rerun gates;
8. the controller stages only the named files and commits after review.

Subagents do not run Git. The controller performs scoped `git add` and `git commit` using the already approved native Git prefixes.

## 8. Implementation tasks

### Task 1 - Certificate-to-registration public-key bridge

**Files:**

- Modify: `src/saga/crypto/certificates.py`
- Modify: `src/saga/crypto/__init__.py`
- Modify: `tests/unit/test_certificates.py`
- Modify: `tests/unit/test_public_api.py`

**Tests first:**

- a valid User certificate returns the exact raw Ed25519 public key;
- a valid Agent certificate returns the exact raw Ed25519 public key;
- wrong identity, wrong kind, invalid time, wrong trust anchor, wrong profile, unsupported key, malformed DER, and backend ordinary failures are normalized;
- exact plain `bytes32` result is enforced under injected malformed backend behavior;
- existing `validate_leaf_certificate` behavior and all Phase 1 tests remain unchanged;
- control-flow/resource exceptions propagate.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_certificates.py tests/unit/test_public_api.py -q
```

**Implementation:** share a single internal certificate-validation function; add only the narrow raw-key extraction helper; preserve the old API.

**Commit:** `feat: expose validated registration public keys`

### Task 2 - Registration domain values, records, results, and failures

**Files:**

- Create: `src/saga/domain/users.py`
- Create: `src/saga/domain/agents.py`
- Create: `src/saga/domain/errors.py`
- Create: `src/saga/domain/events.py`
- Modify: `src/saga/domain/__init__.py`
- Create: `tests/unit/test_registration_domain.py`
- Modify: `tests/unit/test_public_api.py`

**Tests first:**

- exact identifier grammar, canonical `aid_A`, immutability, equality, and the frozen 254/128 UTF-8-byte bounds;
- owner mismatch rejection;
- strict endpoint reuse from Phase 1;
- exact key/signature lengths and rejection of subclasses;
- exact 1..1,024 unique OTK tuple bound;
- exact 1..65,536-byte strict-UTF-8 opaque policy document with no semantic evaluation;
- exact 1..1,024 UTF-8-byte password and 1..16,384-byte certificate input bounds;
- redacted `repr` for password-bearing commands and records;
- exact conversion between `StoredPasswordRecord` and the Phase 1 crypto `PasswordRecord`, without making the persistence DTO a convenience export;
- import-boundary proof that `saga.domain` imports neither `saga.crypto` nor `cryptography`;
- result DTOs contain no password, verifier, private key, SOTK, policy decision, or ACT field;
- errors have fixed messages and suppress backend details;
- event DTO allows only event name, public IDs, coarse result, duration, and correlation ID.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_registration_domain.py tests/unit/test_public_api.py -q
```

**Commit:** `feat: define registration domain contracts`

### Task 3 - Registration ports and deterministic test substitutes

**Files:**

- Create: `src/saga/ports/__init__.py`
- Create: `src/saga/ports/identity.py`
- Create: `src/saga/ports/clock.py`
- Create: `src/saga/ports/random.py`
- Create: `src/saga/ports/signing.py`
- Create: `src/saga/ports/transactions.py`
- Create: `src/saga/ports/registries.py`
- Create: `tests/unit/test_registration_ports.py`
- Create: `tests/helpers/registration.py`

**Tests first:**

- runtime-checkable protocol conformance for deterministic fakes;
- fixed clock rejects invalid Unix milliseconds;
- deterministic random source returns exact requested bytes and rejects malformed lengths/results;
- Provider signer exposes one exact plain `bytes32` public key and exact plain `bytes64` signatures while keeping the private key outside protocol/domain DTOs;
- trusted identity substitute verifies only explicitly enrolled User IDs;
- `UserCreateOutcome` is exactly `{CREATED, USER_ID_CONFLICT}` and `AgentCreateOutcome` is exactly `{CREATED, AGENT_ID_CONFLICT, ENDPOINT_CONFLICT}`;
- `transactions.py` contains only those outcomes; persistence failures raise the fixed `RegistrationPersistenceError` and never masquerade as a conflict outcome;
- registry ports expose only get and atomic create intent, with no policy/OTK/ACT methods;
- helper representations redact secret bytes and passwords.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_registration_ports.py -q
```

**Commit:** `feat: define registration persistence ports`

### Task 4 - User registration and in-memory User Registry

**Files:**

- Create: `src/saga/protocols/__init__.py`
- Create: `src/saga/protocols/user_registration.py`
- Create: `src/saga/adapters/__init__.py`
- Create: `src/saga/adapters/persistence/__init__.py`
- Create: `src/saga/adapters/persistence/memory.py`
- Create: `tests/protocol/test_user_registration.py`
- Create: `tests/integration/test_memory_user_registry.py`

**Tests first:**

- IV-B success returns only the public User ID and stores certificate plus redacted scrypt record;
- IdentityVerifier rejection creates no record and performs no password hash;
- invalid/mismatched/expired certificate creates no record;
- malformed/empty password fails closed and never reaches storage;
- deterministic salt injection produces the expected password record;
- duplicate sequential and concurrent registration has exactly one winner;
- registry getters return immutable records/copies, not writable internal state;
- injected hash, registry, and ordinary backend failures are normalized with no secret detail;
- `MemoryError`, `KeyboardInterrupt`, and `SystemExit` propagate;
- no event, exception, result, `repr`, or captured log contains the password, salt/verifier, or certificate internals.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/protocol/test_user_registration.py tests/integration/test_memory_user_registry.py -q
```

**Commit:** `feat: register users atomically in memory`

### Task 5 - Agent registration and in-memory Agent Registry

**Files:**

- Create: `src/saga/protocols/agent_registration.py`
- Create: `src/saga/adapters/crypto.py`
- Modify: `src/saga/adapters/persistence/memory.py`
- Create: `tests/protocol/test_agent_registration.py`
- Create: `tests/integration/test_memory_agent_registry.py`
- Create: `tests/vectors/registration-records.json`

`registration-records.json` is public-only: certificates, public keys, public tuple bytes, and signatures may appear; passwords, password records/verifiers, private keys, `SAC_A`, and SOTKs may not appear.

**Tests first:**

- IV-C success authenticates owner and stores the complete public registration atomically;
- concrete Provider signer delegates to Phase 1 Ed25519 wrappers, has redacted representation, and never exposes its private key;
- `aid_A` owner prefix must match authenticated `uid_U`;
- wrong/missing owner and wrong password fail before Agent verification and storage;
- duplicate `aid_A` and duplicate exact endpoint are distinct stable conflicts;
- Agent certificate identity/profile/time and extracted `PK_A` are checked;
- exact `sigma_A^U` verification uses `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>`;
- mutation of every tuple member fails;
- every exact OTK signature uses `<aid_A, OTK_A^i>` and all vector records are consumed;
- one invalid OTK signature rejects the entire batch;
- duplicate OTK values reject the entire batch;
- Provider signs exactly `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>`;
- Provider signature mutation and Figure 8 tuple substitution do not verify;
- Provider signing failure leaves no Agent or OTK record;
- Provider signer non-`bytes`, wrong-length public-key/signature results and ordinary exceptions fail before commit with one stable registration-verification failure; control-flow/resource exceptions still propagate;
- Provider attestation is returned to the caller but is absent from the Provider Registry record and schema;
- concurrent same-ID and same-endpoint attempts each have one winner;
- stored policy bytes remain opaque and no matcher/budget/deny semantics exist;
- stored OTKs have no lifecycle state and no allocation method exists;
- no private Agent TLS key, `SAC_A`, SOTK, password, or raw password record enters the Agent Registry or result.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/protocol/test_agent_registration.py tests/integration/test_memory_agent_registry.py -q
```

**Commit:** `feat: register agents atomically in memory`

### Task 6 - SQLite User Registry, schema, rollback, and restart

**Files:**

- Create: `src/saga/adapters/persistence/sqlite.py`
- Create: `tests/integration/test_sqlite_user_registry.py`
- Create: `tests/integration/test_registration_schema.py`

**Tests first:**

- deterministic schema and schema-version creation;
- foreign keys enabled on each connection;
- User success survives close/reopen and password verification still works;
- duplicate User registration has one winner across separate connections;
- all password-record parameters round-trip exactly;
- malformed persisted password values, certificate type/length, and certificate DER parsing fail closed on read;
- persistence reconstruction does not re-run trust-anchor, profile, identity, or time validation; those registration decisions belong only to protocol services and must not change merely because a stored record is read later;
- injected insert/commit failures roll back fully;
- database messages and paths do not escape stable protocol errors;
- SQLite schema contains no Phase 3+, network, ACT, tool, or innovation columns/tables.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration/test_sqlite_user_registry.py tests/integration/test_registration_schema.py -q
```

**Commit:** `feat: persist user registrations in SQLite`

### Task 7 - SQLite Agent Registry atomicity and restart

**Files:**

- Modify: `src/saga/adapters/persistence/sqlite.py`
- Create: `tests/integration/test_sqlite_agent_registry.py`
- Create: `tests/integration/test_registration_rollback.py`

**Tests first:**

- complete Agent and ordered OTK rows survive close/reopen exactly;
- Agent ID and endpoint uniqueness are global and deterministic;
- concurrent separate-connection conflicts have one winner;
- a failure before Agent insert changes nothing;
- a failure after Agent insert but before all OTK rows rolls back Agent and OTK rows;
- a failure during the final OTK insert or transaction commit rolls back everything;
- malformed/corrupt row lengths, ordinals, duplicate/missing OTK rows, invalid UTF-8 policy, and non-parseable certificate DER fail closed structurally;
- registry reconstruction never re-runs X.509 trust/profile/identity/time validation;
- read APIs never return partial records;
- SQLite has no OTK issued/consumed state, pair counter, policy matcher/update state, deactivation state, ACT state, or transport state.

Use SQLite test triggers or transaction-boundary fixtures to force failures; do not add production-only failure backdoors.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration/test_sqlite_agent_registry.py tests/integration/test_registration_rollback.py -q
```

**Commit:** `feat: persist agent registrations atomically`

### Task 8 - Cross-backend parity and IV-B/IV-C protocol coverage

**Files:**

- Create: `tests/protocol/test_registration_messages.py`
- Create: `tests/integration/test_registration_persistence.py`
- Create: `tests/security/test_registration_security.py`
- Create: `tests/unit/test_phase_two_scope.py`

**Tests first:**

- an exact ledger-evidence manifest classifies every IV-B.1-IV-B.6 and IV-C.1-IV-C.7 row as one of: `phase2_executable`, `phase1_primitive_evidence`, `paper_assumption_or_preprovisioned_input`, or `deferred_network_evidence`;
- Phase 2 directly executes command construction/validation, identity substitution, password storage/authentication, certificate consumption/validation, exact signatures, uniqueness, registry transitions, and confirmation results;
- Phase 1 evidence is referenced for local key generation, canonical tuple primitives, certificate profiles, and signature primitives rather than re-claimed as new Phase 2 work;
- CA issuance/external identity strength remain explicit assumptions/preprovisioned inputs, while IV-B.3 and IV-C.4 TLS handshakes are marked deferred network evidence; no report may claim they executed in Phase 2;
- exact signer, tuple, verification key, verifier, and state transition mappings;
- one shared scenario suite runs unchanged against memory and SQLite;
- success, duplicate, tamper, rollback, and restart outcomes match across backends;
- forged User signatures, altered endpoint, altered `PK_A`, altered `PAC_A`, altered `PK_Prov`, altered OTK, metadata replacement, wrong owner, and partial transaction all fail closed at Phase 2 protocol inputs;
- the returned Provider attestation verifies against the exact main-text tuple and configured public key, while a mutated signature or Figure 8 substitute tuple fails cryptographic verification; this is a result-evidence test, not a nonexistent Phase 2 protocol input that accepts Provider signatures;
- secret scan covers passwords, private keys, SOTKs, raw scrypt verifier, and backend exception text;
- package/source scan rejects policy engines, wildcard matching, pair counters, OTK lifecycle/allocation, ACT protocol/state, API routes, FastAPI/Pydantic, network listeners, ProVerif, benchmark, task/tool authorization, and innovation modules;
- no sleeps; clock and randomness remain injected.

**Focused RED/GREEN:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/protocol tests/integration tests/security tests/unit/test_phase_two_scope.py -q
```

**Commit:** `test: prove Phase 2 registration semantics`

### Task 9 - Public API, feature-source matrix, and Phase 2 evidence

**Files:**

- Modify: `src/saga/domain/__init__.py`
- Modify: `src/saga/ports/__init__.py`
- Modify: `src/saga/protocols/__init__.py`
- Modify: `tests/unit/test_public_api.py`
- Modify: `docs/feature-source-matrix.md`
- Create: `docs/phase-2-verification.md`

**Public API gate:** freeze exact exports. Do not expose persistence implementations from `saga`, `saga.domain`, `saga.ports`, or `saga.protocols`. Password hashing remains in `saga.crypto.passwords`, not a result DTO or top-level convenience API.

**Matrix gate:** preserve exactly:

```markdown
| 功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展 |
```

Only append Phase 2 implementation evidence to the `复现工程补充` cells for the applicable existing rows. Do not rewrite `论文原始设计`; do not move any baseline behavior into `后续创新扩展`; do not add innovation behavior.

At minimum audit these rows:

- User identifier and persistent identity verification;
- User signature key and certificate;
- User Registry;
- Agent identifier and Endpoint Descriptor;
- Agent TLS credential and certificate;
- Agent long-term access-control key;
- OTK public/secret key pair;
- User signature over Agent metadata;
- User signature over each OTK;
- Provider signature over Agent registration information;
- Agent Registry;
- scrypt password record;
- stable domain error taxonomy;
- structured secret-safe logging (record only that Phase 2 freezes a secret-safe event DTO schema; do not claim a logger or event sink exists);
- in-memory persistence adapter;
- SQLite persistence adapter.

The OTK row must say Phase 2 stores verified public OTK registration material only; Phase 3 owns lifecycle/allocation. The Contact Policy row, if mentioned, must say Phase 2 preserves an opaque registration document only; matching and budgets remain Phase 3.

**Verification report sections:**

1. completed work;
2. files created/modified;
3. IV-B/IV-C and matrix mapping;
4. engineering decisions;
5. commands executed with timestamps/exit codes;
6. test results with exact counts;
7. memory/SQLite parity, rollback, and restart evidence;
8. security and secret-scan evidence;
9. unresolved paper assumptions and limitations;
10. Phase 3 boundary and user acceptance question.

**Final commands:**

```powershell
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\python.exe -m pytest tests/unit tests/protocol tests/integration tests/security -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Run secret scans over `src`, vectors, and evidence for private-key PEM markers, SOTK/secret-key JSON fields, raw password verifiers, TODO/TBD placeholders, and innovation identifiers. Synthetic passwords may exist as test inputs, so separately assert that captured logs, events, exceptions, results, snapshots, vectors, and reports never contain those known values; do not use an impossible source-code no-match gate for test fixtures.

**Commit:** `docs: verify SAGA phase two registration`

## 9. Review and acceptance gates

After Task 9:

1. generate one complete diff from this plan's commit base to Phase 2 HEAD;
2. assign an independent whole-phase reviewer;
3. require Critical = 0 and Important = 0;
4. fix all accepted findings with TDD and scoped commits;
5. rerun all final commands on the final HEAD;
6. update `docs/phase-2-verification.md` with the final review result;
7. require a clean worktree;
8. stop and ask the User to accept Phase 2 evidence.

Phase 2 acceptance authorizes planning Phase 3 only. It does not authorize implementation of Contact Policy/OTK allocation until a separate detailed Phase 3 plan is reviewed and accepted.

Do not create `saga-baseline-v1` after Phase 2. The baseline tag remains blocked until the complete base protocol plus security and performance gates are stable, exactly as required by the User.

## 10. Definition of done

Phase 2 is complete only when all of the following are true:

- every IV-B and IV-C ledger entry maps to exactly one honest evidence class: Phase 2 executable behavior, Phase 1 primitive evidence, paper assumption/preprovisioned input, or deferred network evidence;
- exact User, OTK, and Provider tuples are verified with Phase 1 canonical encoding;
- User and Agent certificates use the Phase 1 closed X.509 profile;
- memory and SQLite produce the same public outcomes;
- duplicate and concurrent registration has exactly one winner;
- SQLite rollback and restart evidence passes;
- no partial Agent/OTK record is observable;
- no secret appears in public protocol results, events, exceptions, logs, vectors, or reports; only the internal User Registry persistence DTO carries the redacted-at-representation password record needed for authentication;
- the feature-source matrix remains four columns with classifications intact;
- no Phase 3+, network, formal, benchmark, baseline-tag, or innovation behavior exists;
- full tests, mypy, Ruff, format, dependency, scan, and diff gates pass;
- independent whole-phase review reports no Critical or Important issue;
- the User explicitly accepts the Phase 2 evidence.
