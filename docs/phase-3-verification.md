# SAGA Phase 3 Verification

## 1. Scope and result

Phase 3 reproduces the Provider-side Contact Policy, public one-time-key (OTK) allocation, pair-budget, policy-management, and Agent-deactivation boundary in paper IV-D and IV-E Steps 2--3. It provides matching in-memory and SQLite Contact State implementations with versioned compare-and-swap (CAS), bounded retry, rollback, restart, deterministic concurrency, and secret-safe closed errors.

It does **not** implement an Agent-to-Provider TLS connection. IV-E.1 remains deferred network evidence. The executable Phase 3 path begins at Provider resolution (IV-E.2) and ends with offline `ContactBundle` certificate and exact User-signature verification (IV-E.3).

## 2. Paper mapping and evidence classification

| Paper item | Classification | Executable evidence / boundary |
|---|---|---|
| IV-D.1 Contact Policy | executable | Closed JSON v1 policy parser, fixed specificity, equal-specificity tie rejection, deny/no-match outcomes, update CAS, and policy tests. |
| IV-D.2 pair budget and one public OTK | executable | Fresh-snapshot policy evaluation, lowest available public-OTK choice, pair counter capping/decrement, one atomic Provider CAS, and deterministic race tests. |
| IV-D management/revocation | executable | Owner/password-gated policy replacement, signed public-OTK append, and terminal deactivation with bounded CAS retry. |
| IV-E.1 Agent-to-Provider TLS | deferred network evidence | No TLS, HTTP, socket, route, or transport implementation is present in Phase 3. |
| IV-E.2 Provider resolution | executable | `ContactResolutionService` returns one typed `ContactBundle` after active/policy/budget/public-OTK commit. |
| IV-E.3 offline verification | executable | `ContactBundleVerifier` validates the precommitted `Cert_U1` and `Cert_A`, then verifies exact `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>` and `<aid_A, OTK_A^i>` User-signature tuples. |

`tests/protocol/test_contact_messages.py` freezes this ledger and checks the bundle-to-paper-field mapping plus both exact tuple verifications. It deliberately makes no TLS claim.

## 3. Implementation and persistence evidence

- Policy syntax is a bounded, strict UTF-8 JSON v1 representation. Its specificity is `exact > user > type > global`; equal-specificity overlap is rejected. Phase 2's previously accepted opaque policy bytes are migrated unchanged and fail later resolution as `InvalidContactPolicy` when they do not satisfy the Phase 3 grammar.
- Public OTK identity is receiver plus ordinal. Provider allocation selects the lowest available ordinal and atomically marks it issued with the pair-counter transition. A post-commit delivery/verification failure does not reissue it.
- A policy decrease caps an existing pair counter at `min(old remaining, current budget)` on the next request. A policy increase or OTK refill never restores consumed quota.
- Memory and SQLite stores expose policy-blind structural snapshots and versioned CAS. SQLite uses an idempotent contact-state migration, transactions, rollback, restart preservation, and lock-to-conflict normalization; memory uses the corresponding lock-protected semantics.
- Deterministic `threading.Barrier` scenarios cover 2, 8, and 32 contenders for final OTK, final budget, and dual-final cases. Exactly one resolution succeeds and losing operations make no partial state change.

## 4. Function-source matrix

The required matrix at [feature-source-matrix.md](feature-source-matrix.md) retains exactly these four columns:

| 功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展 |
|---|---|---|---|

Phase 3 updates only its existing rows: policy syntax/specificity, pair counter, single allocation, public-OTK consumption, policy update, deactivation, receiving lookup, stable errors, atomic operations, and memory/SQLite persistence. Fixed JSON syntax, revisions/CAS, bounded retry, capping, migration, and concurrency controls appear only under `复现工程补充`. No base behavior appears under `后续创新扩展`.

## 5. Verification commands and truthful outcomes

All commands below were run on 2026-07-20 (Asia/Shanghai). The full pytest gate is recorded as split suites because the integration/security portion approached the execution-channel limit.

| Command | Outcome |
|---|---|
| `./.venv/Scripts/python.exe -m pytest tests/protocol/test_contact_messages.py tests/unit/test_public_api.py -q` | 9 passed in 0.70s. |
| `./.venv/Scripts/python.exe -m pytest tests/unit -q` | 429 passed in 2.78s. |
| `./.venv/Scripts/python.exe -m pytest tests/protocol -q` | 66 passed in 13.86s. |
| `./.venv/Scripts/python.exe -m pytest tests/integration tests/security -q` | 106 passed in 27.55s. |
| `./.venv/Scripts/python.exe -m mypy src` | Success: no issues in 36 source files. |
| `./.venv/Scripts/ruff.exe check src tests` | All checks passed. |
| `./.venv/Scripts/ruff.exe format --check src tests` | 79 files already formatted. |
| `./.venv/Scripts/python.exe -m pip check` | No broken requirements found. |
| `git diff --check` | Exit 0. |
| Phase 3 production-root exclusion scan for SOTK/DH/ACT/network/formal/benchmark/tool authorization names | Expected no-match (`rg` exit 1). |

The Task 6 additions are evidence-only tests and documentation over pre-existing Tasks 1--5 behavior, so there is no meaningful implementation RED to claim. The first focused run did expose an error in the new test's fixture attribute access; it was corrected to use the real certificate-validation boundary. That was a test-authoring error, not a protocol RED, and is not presented as TDD evidence.

## 6. Security and scope conclusions

The verifier rejects tampering of public bundle certificate, endpoint, access-control public key, User metadata signature, and public OTK material with the closed `ContactBundleVerificationFailed` result. `ContactBundle` contains public bundle material only and is redacted in `repr`; it has no password, private-key, SOTK, shared-secret, or ACT fields. Ordinary persistence failures are normalized to closed contact persistence errors, while process-control exceptions propagate.

The production-root exclusion scan covers only Phase 3 domain/contact protocol/persistence modules. Its expected `rg` exit code is 1: exit 0 would indicate forbidden Phase 4 or transport/formal/performance/tool-authorization behavior and would fail this phase gate.

## 7. Limitations and Phase 4 boundary

- CA issuance, User/Agent key generation, and Provider provisioning remain preprovisioned inputs; persistent human-identity assurance remains an adapter boundary.
- IV-E.1 TLS and all network transport are deferred; offline certificate validation is not evidence of a TLS handshake.
- Phase 3 consumes only Provider-held **public** OTK state. It contains no `SOTK`, OTK-to-SOTK mapping, DH, `SDHK`, ACT plaintext/ciphertext/state, ACT lifetime/quota/use, or rollback/recovery protocol for those later transitions.
- Phase 4 alone may implement receiving-Agent SOTK claim/delete and ACT lifecycle. It must preserve this Phase 3 public-OTK linearization boundary and remain separate from later Agent tool-call authorization innovation.
- FastAPI/HTTP, mTLS, ProVerif, benchmarks, distributed replication, and all tool/operation/parameter/resource authorization extensions remain outside Phase 3.
