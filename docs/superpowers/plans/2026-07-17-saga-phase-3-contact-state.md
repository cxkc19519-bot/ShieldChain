# SAGA Phase 3: Contact Policy, Public OTK Allocation, and Concurrent State Plan

> Status: planning artifact only. It does not authorize Phase 4 ACT work, network work, SOTK work, a baseline tag, or any innovation implementation. Work remains on `main`.

## 1. Objective, sources, and exact boundary

Implement deterministic Contact Policy, public OTK allocation, pair-budget state, policy update, OTK replenishment, Agent deactivation, and linearizable memory/SQLite persistence for paper IV-D and IV-E Steps 1--3. IV-E.2--3 are executable pure-core evidence; IV-E.1 TLS remains explicitly deferred network evidence. Return one public contact bundle and stop before DH, SOTK claim/deletion, ACT creation/encryption/state/use, HTTP, TLS, sockets, or network claims.

Normative precedence: paper main text and numbered steps; paper figures; `docs/protocol-messages.md`; decisions 9--12 in `docs/ambiguities-and-decisions.md`; then reproduction engineering in `docs/feature-source-matrix.md`. Required design inputs are Phase 3 in `docs/implementation-plan.md`, the contact-state port in `docs/architecture.md`, and atomicity cases in `docs/experiment-plan.md`.

The frozen base is `306c913`. Phase 2 offers only `UserRegistry.get/create_if_absent`, `AgentRegistry.get/create_if_unique`, and `AgentRegistration` with an opaque policy document plus ordered verified public OTKs. It does not contain policy evaluation, active state, pair counters, OTK lifecycle, or CAS. Phase 3 adds those explicitly.

Included:

- IV-D policy selection, pair budget, update, signed public-OTK refill, and deactivation;
- IV-E.2 Provider resolution and `Cert_U1, aid_A, ED_A, Cert_A, PAC_A, OTK_A^i, sigma_OTKi^U1, sigma_A^U1` only;
- IV-E.3 offline certificate/User-signature verification;
- protocol-owned versioned snapshot/CAS retry, memory/SQLite parity, deterministic concurrency, restart, rollback, and delivery-failure evidence.

Excluded and forbidden from Phase 3 production roots:

- X25519/DH, `SDHK`, SOTK values/mappings/claim/delete/retry, ACT schema/ciphertext/state/lifetime/`q_max`/use/revocation;
- FastAPI/Pydantic, HTTP, TLS/mTLS, socket, CA deployment, real transport, ProVerif, benchmarks, demos, sharding/federation, Byzantine defenses;
- task/tool/operation/parameter/resource/delegation fields and all innovation extensions.

Public OTK consumption is a Provider-side Phase 3 transition. SOTKs remain Agent-local and first appear in Phase 4. Do not create a placeholder SOTK table, intention record, distributed rollback, or ACT recovery flow.

## 2. Frozen policy semantics and contracts

### 2.1 Strict policy representation

New or updated policies use strict, closed UTF-8 JSON in Phase 3 (an engineering serialization decision, not a new paper field):

```json
{"version":1,"rules":[
  {"kind":"exact","agent_id":"uid:name","budget":3},
  {"kind":"user","user_id":"uid","budget":2},
  {"kind":"type","name":"name","budget":1},
  {"kind":"global","budget":-1}
]}
```

- Root fields are exactly `version` and `rules`; `version` is integer `1`; 1..1,024 rules.
- A rule has exactly `kind`, `budget`, and its one required selector: `agent_id` (`exact`), `user_id` (`user`), `name` (`type`), or no selector (`global`).
- `budget` is an exact plain integer in `{-1} union [1, 1_000_000]`; bool, float, zero, and other negative values fail closed.
- `exact` matches `aid_B`; `user` matches `aid_B.owner`; `type` matches `aid_B.name`; `global` matches every Agent.
- Specificity is exactly `exact > user > type > global`. Equal-specificity overlap rejects at parse/update time: same exact Agent, same user wildcard, same type wildcard, or multiple globals. Different-specificity overlap is legal and the fixed order wins. Rule order cannot affect an answer.
- No match, explicit `-1` deny, exhausted pair budget, exhausted OTK pool, inactive receiver, and CAS conflict stay distinct stable outcomes.

Phase 2 admitted any bounded non-empty UTF-8 `contact_policy_document`. Migration and ordinary registration reads therefore never parse, rewrite, reject, normalize, or replace legacy policy bytes. On every resolution attempt, the protocol parses the snapshot's bytes immediately before authorization. A legacy document that is not this Phase 3 closed JSON form returns fixed `InvalidContactPolicy` and performs no counter, OTK, revision, or active-state mutation. A policy replacement is accepted only when the submitted replacement parses under the new closed form; it does not repair old bytes silently.

New immutable domain models are `PolicyRule`, `ContactPolicy`, `PolicyMatch`, `PublicOtkId`, `AvailablePublicOtk`, `PairCounter`, `ContactSnapshot`, `ContactCommit`, `ContactBundle`, `ResolveContactCommand`, `UpdateContactPolicyCommand`, `AppendPublicOtksCommand`, and `DeactivateAgentCommand`. Counts/revisions/ordinals are plain non-negative integers; public key/signature constraints reuse Phase 2. Password-bearing management commands use redacted `repr`.

### 2.2 Errors and public OTK lifetime

Add a closed contact error family without weakening Phase 2 registration errors: invalid contact input, invalid contact policy, policy no match, policy denied, pair budget exhausted, OTK pool exhausted, Agent inactive, contact-bundle verification failed, concurrent conflict, and contact persistence failed. Messages are fixed and backend details suppressed; `MemoryError`, `KeyboardInterrupt`, and `SystemExit` propagate.

Every Phase 2 Agent enters Phase 3 `active=True`; all its public OTKs are initially `available`. OTK identity is `(receiving aid, ordinal)` and allocation selects the lowest available ordinal. It becomes terminally `issued` and cannot be reissued.

- First successful permitted resolution writes `remaining = selected_budget - 1`.
- If pool is empty, no pair counter is created or changed.
- Existing counter: compute `min(old_remaining, current_budget)`, require positive, then decrement.
- A lower policy caps at the next request; a higher policy and refill never restore spent quota. No-match/deny do not mutate state.
- Refill accepts only newly signed, previously unseen keys, appends after the largest ordinal, changes only pool revision, and never resets counters.
- Deactivation is terminal `active=True -> False`; no reactivation. It blocks discovery/allocation for receiving A. B only must be registered in this pure-core phase; mTLS identity assurance remains Phase 5.

The successful Provider CAS is the public-OTK linearization point. A post-commit serialization/delivery/client-observation/restart failure leaves OTK and pair decrement persisted; retry requests a fresh OTK if permitted. SOTK behavior is intentionally absent; Phase 4 owns SOTK claim/delete and crash rules.

### 2.3 Snapshot/CAS contract and retry ownership

Create runtime-checkable `ContactStateStore`:

```python
class ContactStateStore(Protocol):
    def read_snapshot(
        self, *, receiving_agent_id: AgentId, initiating_agent_id: AgentId
    ) -> ContactSnapshot: ...
    def try_commit(self, command: ContactCommit) -> ContactCommitOutcome: ...
    def replace_policy(self, command: PolicyReplaceCommit) -> ContactCommitOutcome: ...
    def append_otks(self, command: OtkAppendCommit) -> ContactCommitOutcome: ...
    def deactivate(self, command: DeactivateCommit) -> ContactCommitOutcome: ...
```

Snapshots contain receiving/initiating registrations, receiving active state and `agent_revision`, policy bytes and `policy_version`, optional counter `(remaining, revision)`, available OTKs ordered by ordinal, and `otk_pool_revision`.

`ContactCommit` carries the selected ordinal, protocol-computed remaining value, and expected `agent_revision`, active value, `policy_version`, counter presence/value/revision, and pool revision. `try_commit` returns exactly `COMMITTED | CONFLICT`; on exact match it writes counter and marks one OTK issued in one transaction, otherwise it changes nothing. Stores must not parse/match policy, authorize, cap, or select an OTK. Management mutations likewise carry expected state/revisions; protocol services own owner/password/signature verification and authorization.

Every protocol operation owns at most 8 total CAS attempts: one initial attempt plus at most 7 retries. For resolution, every conflict obtains a complete fresh snapshot, rereads the receiving owner certificate described below, rechecks active state, reparses/rematches current policy, recomputes capping/check/decrement, and reselects an OTK. Retrying an old write is forbidden; a conflict on total attempt 8 returns stable `ConcurrentConflict` with no additional write.

Policy replacement, OTK append, and deactivation use the same initial-plus-seven-retries rule. On every conflict their protocol service rereads the target snapshot, rereads/authenticates the owner User, rechecks ownership and active state, reparses the submitted policy or reverifies every submitted OTK signature, recreates the structural mutation, and then submits a fresh CAS. Failed owner authentication, invalid policy/signature, inactive state, or a conflict makes no write. Their respective linearization points are only their successful structural CAS: policy replacement updates policy bytes and increments `policy_version` and `agent_revision`; append writes the complete new OTK set and increments `otk_pool_revision` and `agent_revision`; deactivation writes `active=False` and increments `agent_revision`. The 8th conflict is `ConcurrentConflict`. Adapters do not make authorization retries. SQLite lock exhaustion normalizes to retryable conflict; other ordinary persistence errors normalize to contact persistence failure.

### 2.4 IV-E.3 bundle verifier

`ContactResolutionService` receives `UserRegistry` explicitly. On every resolution attempt, after reading the snapshot and before any CAS, it calls `UserRegistry.get(snapshot.receiving_registration.owner_id)`, requires an exact `UserRegistration` whose `user_id` equals that owner, and copies only its persisted `certificate_der` into the future `ContactBundle` as `Cert_U1`. Missing, corrupt, malformed, mismatched, or ordinary read-failure User records normalize to contact persistence failure before CAS, so no public OTK or counter changes. The service must repeat this read/binding check after every CAS conflict; it never accepts a caller-supplied `Cert_U1` and never tries to fetch it after a successful allocation.

`ContactBundleVerifier` receives injected `Clock`, trust anchor, and Provider public signing key. It validates that precommitted User/Agent certificate material with the Phase 1 closed certificate boundary, extracts the User signing key, verifies exact `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>` metadata and `<aid_A, OTK_A^i>` signatures. It has no network behavior. Bundle verification failures happen after allocation and never roll allocation back.

## 3. Persistence design

The current `saga_registration_schema` is fixed at version 1. Preserve it and create independent `saga_contact_state_schema(version=1)`. In one idempotent migration transaction:

- add `active`, `agent_revision`, `policy_version`, `otk_pool_revision` to `agents`, with defaults `1,0,0,0`;
- add `issued INTEGER NOT NULL DEFAULT 0` to `registered_public_otks`;
- create `pair_otk_counters(receiving_agent_id, initiating_agent_id, remaining, revision, PRIMARY KEY(receiving_agent_id, initiating_agent_id))` and necessary available-pool indexes.

Test fresh and existing Phase 2 databases. SQLite snapshots use one read transaction; CAS uses `BEGIN IMMEDIATE`, validates all expected fields, then atomically mutates counter plus issued flag. Memory uses one `RLock` and identical ordering/revision/conflict/zero-partial-write semantics. Phase 2 `get/create_if_unique` behavior remains compatible.

## 4. TDD, review, and commits

For every task: write named tests first, record focused RED, implement minimum GREEN, run focused and cumulative gates, self-review scope and secrets, then obtain a separate review. All Critical/Important findings require fixes plus re-review. Only the controller stages the named allowlist and commits; implementers/reviewers do not run Git.

Each task also runs:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit tests/protocol tests/integration tests/security -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
```

### Task 0 — Plan commit

Allowlist: this plan only. Commit: `docs: plan SAGA phase three contact state`.

### Task 1 — Domain policy and Phase 3 scope guard

Allowlist:

- Create `src/saga/domain/policies.py`, `src/saga/domain/otk.py`, `src/saga/domain/contact.py`
- Modify `src/saga/domain/errors.py`, `src/saga/domain/__init__.py`
- Create `tests/unit/test_policy_matching.py`, `tests/unit/test_contact_domain.py`, `tests/unit/test_phase_three_scope.py`
- Modify `tests/unit/test_phase_two_scope.py`, `tests/unit/test_public_api.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_policy_matching.py tests/unit/test_contact_domain.py tests/unit/test_phase_two_scope.py tests/unit/test_phase_three_scope.py tests/unit/test_public_api.py -q
```

Cover strict JSON, four specificity classes/ties, every stable policy outcome, DTO bounds, redaction, and exact public exports. Narrow the Phase 2 guard to registration modules so it does not falsely forbid legal Phase 3 code; add a recursive Phase 3 guard prohibiting ACT/SOTK/DH/HKDF/AEAD/network/formal/benchmark/tool behavior.

Commit: `feat: define contact policy domain semantics`.

### Task 2 — Versioned port and deterministic fixtures

Allowlist:

- Create `src/saga/ports/contact_state.py`, `tests/unit/test_contact_state_ports.py`, `tests/helpers/contact_state.py`
- Modify `src/saga/ports/__init__.py`, `tests/unit/test_public_api.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_contact_state_ports.py tests/unit/test_public_api.py -q
```

Test runtime conformance, exact snapshot/commit fields, closed outcomes, synthetic conflict zero mutation, deterministic barriers without `sleep`, and a synthetic adapter proving persistence cannot match policy.

Commit: `feat: define versioned contact state port`.

### Task 3 — Memory state, resolution, management, and verification

Allowlist:

- Modify `src/saga/adapters/persistence/memory.py`, `src/saga/protocols/__init__.py`
- Create `src/saga/protocols/contact_resolution.py`, `src/saga/protocols/contact_management.py`
- Create `tests/protocol/test_contact_resolution.py`, `tests/protocol/test_policy_updates.py`, `tests/integration/test_memory_contact_state.py`
- Modify `tests/unit/test_public_api.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/protocol/test_contact_resolution.py tests/protocol/test_policy_updates.py tests/integration/test_memory_contact_state.py tests/unit/test_public_api.py -q
```

Cover one lowest-ordinal bundle; no-match/deny/inactive/budget/pool zero mutation; legacy arbitrary UTF-8 policy parsing to `InvalidContactPolicy` with zero mutation; owner/password/signed-OTK management checks; management conflict retry/re-authentication/reverification and each operation's linearization; decrease/increase/deny updates; refill without quota restore; deactivation; exact IV-E.3 verification/mutations; missing/mismatched/corrupt/failing receiving-owner `UserRegistry` read before CAS; post-commit delivery failure without reissue; exact protocol public exports; and no SOTK/SDHK/ACT surface.

Commit: `feat: resolve contacts atomically in memory`.

### Task 4 — SQLite migration, state, and CAS

Allowlist:

- Modify `src/saga/adapters/persistence/sqlite.py`, `tests/integration/test_registration_schema.py`
- Create `tests/integration/test_sqlite_contact_state.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration/test_sqlite_contact_state.py tests/integration/test_registration_schema.py -q
```

Cover fresh/Phase-2 migration, idempotence, restart preservation, coherent snapshots, CAS mismatch, migration/insert/update/commit rollback, lock normalization, secret-safe errors, and unchanged registration behavior. Seed a real Phase 2 database with arbitrary bounded UTF-8 policy bytes that are invalid under the new policy grammar; migration must preserve the exact bytes and succeed, while later resolution returns `InvalidContactPolicy` with zero counter/OTK mutation.

Commit: `feat: persist contact state in SQLite`.

### Task 5 — Parity, races, restart, and crash evidence

Allowlist:

- Create `tests/integration/test_contact_atomicity.py`, `tests/integration/test_contact_restart.py`, `tests/integration/test_contact_parity.py`, `tests/security/test_contact_security.py`
- Modify `tests/helpers/contact_state.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration/test_contact_atomicity.py tests/integration/test_contact_restart.py tests/integration/test_contact_parity.py tests/security/test_contact_security.py -q
```

Use `threading.Barrier`, never sleeps. At 2/8/32 workers last-OTK, last-budget, and dual-last cases have exactly one winner and every loser has no partial mutation. Include memory/SQLite parity fixtures carrying an arbitrary legacy Phase 2 UTF-8 policy and assert fixed invalid-policy failure with zero state mutation. Cover separate-connection SQLite races, all management-operation conflict retries, policy update/deactivate races, restart, injected rollback, and commit-before-delivery failure. Assert only Provider public-OTK semantics, never SOTK/ACT behavior.

Commit: `test: prove Phase 3 contact atomicity`.

### Task 6 — Evidence, source matrix, and public API

Allowlist:

- Create `tests/protocol/test_contact_messages.py`, `docs/phase-3-verification.md`
- Modify `docs/feature-source-matrix.md`, `tests/unit/test_public_api.py` only if final frozen export coverage requires it

```powershell
.\.venv\Scripts\python.exe -m pytest tests/protocol/test_contact_messages.py tests/unit/test_public_api.py -q
```

The evidence manifest honestly classifies IV-D, IV-E.1, IV-E.2, IV-E.3: TLS Step 1 remains deferred network evidence; Provider resolution and offline Step 3 verification are executable; SOTK/DH/ACT remain Phase 4.

The feature-source matrix must retain exactly:

```markdown
| 功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展 |
```

Update only existing Contact Policy, specificity, pair counter, single allocation, public OTK consumption, policy update, deactivation, receiving lookup, stable-error, atomic-operation, and memory/SQLite rows. Record JSON policy, tie rejection, revisions/CAS, capping, retry, and migration only under `复现工程补充`. Never put base work under `后续创新扩展`; do not change SOTK/ACT rows to imply completion.

Commit: `docs: verify SAGA phase three contact state`.

## 5. Whole-phase exit gate

An independent whole-phase reviewer must find zero Critical/Important issues in exact IV-D/IV-E mapping, CAS ownership, memory/SQLite parity, secret safety, and scope. Fixes require focused RED/GREEN and re-review.

Controller final commands:

```powershell
.\.venv\Scripts\ruff.exe format src tests
.\.venv\Scripts\python.exe -m pytest tests/unit tests/protocol tests/integration tests/security -q
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Run an expected-no-match scan over Phase 3 implementation roots for `SOTK|SDHK|derive_shared_secret|derive_sdhk|encrypt_act|decrypt_act|ActPlaintext|ActEnvelope|FastAPI|socket|http.server|proverif|benchmark|tool.*authoriz`; any match fails scope.

Phase 3 passes only when both adapters have matching public outcomes; each last-OTK/last-budget race has one winner; losers have zero partial mutation; management is owner-authenticated/signature-verified; restart/delivery evidence proves public OTKs never return; IV-E.3 is covered; all gates/reviews pass; and no DH, SOTK, ACT, transport, or innovation implementation exists.
