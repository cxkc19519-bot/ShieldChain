# SAGA Phase 2 Verification

## 1. Completed work

Phase 2 reproduces the IV-B User registration and IV-C Agent registration boundary only. It defines validated registration values, closed errors and a secret-safe event DTO; verifies identity, certificates, User signatures, OTK signatures, and the Provider's main-text attestation; and commits User and complete Agent-plus-public-OTK registrations atomically through interchangeable in-memory and SQLite registries.

It does not implement Contact Policy matching or budgets, OTK lifecycle/allocation, Agent activation, ACT state, TLS handshakes, routes, formal verification, performance experiments, or Agent tool authorization.

## 2. Files created or modified

| Area | Paths | Purpose |
|---|---|---|
| Domain and ports | `src/saga/domain/{users,agents,errors,events}.py`; `src/saga/ports/{clock,identity,random,registries,signing,transactions}.py` | Closed registration values/errors/events and narrow injected dependencies. |
| Protocol services | `src/saga/protocols/{user_registration,agent_registration}.py` | Paper-order IV-B and IV-C orchestration. |
| Adapters | `src/saga/adapters/crypto.py`; `src/saga/adapters/persistence/{memory,sqlite}.py` | Provider signing plus atomic memory/SQLite registries. |
| Tests and vectors | Registration files under `tests/helpers`, `tests/unit`, `tests/protocol`, `tests/integration`, `tests/security`; `tests/vectors/registration-records.json` | Contract, protocol, parity, rollback, restart, scope, and secret-boundary evidence. |
| API and evidence | `src/saga/{domain,ports,protocols}/__init__.py`; `tests/unit/test_public_api.py`; `docs/feature-source-matrix.md` | Exact exports and the required source classification. |

`StoredPasswordRecord` remains internal and password hashing remains under `saga.crypto.passwords`; no persistence implementation is exported from `saga.domain`, `saga.ports`, or `saga.protocols`.

## 3. IV-B/IV-C and feature-source mapping

| Paper step / evidence class | Phase 2 evidence |
|---|---|
| IV-B.1--IV-B.2, preprovisioned input | User key generation, CA issuance, and persistent-identity strength are inputs; Phase 2 does not claim to execute them. |
| IV-B.3, deferred network evidence | Provider TLS certificate retrieval/handshake is not implemented. |
| IV-B.4--IV-B.6, executable | `UserRegistrationService` validates input, calls `IdentityVerifier` first, consumes the Phase 1 User certificate boundary, hashes the password with injected randomness, and atomically creates the User record. |
| IV-C.1--IV-C.2, paper assumption plus Phase 1 primitive evidence | Agent material is supplied as a command; Phase 1 supplies canonical tuples, Ed25519 verification, and the closed certificate boundary. |
| IV-C.3--IV-C.7, executable | `AgentRegistrationService` authenticates the owner, validates User/Agent certificates, verifies exact User metadata and OTK tuples, signs/verifies the exact IV-C Step 7 Provider tuple, then atomically creates the Agent-plus-public-OTK record. |
| IV-C.4, deferred network evidence | Agent/Provider TLS handshakes are not executed. Registration certificate validation is not a TLS handshake claim. |

The [feature-source matrix](feature-source-matrix.md) retains exactly `功能 | 论文原始设计 | 复现工程补充 | 后续创新扩展`. Phase 2 additions are only in the reproduction-engineering column: verified public OTK registration material only (lifecycle/allocation is Phase 3), an opaque bounded UTF-8 Contact Policy document only (matching/budgets are Phase 3), and the `RegistrationEvent` schema only (no logger or event sink claim).

## 4. Engineering decisions

- `IdentityVerifier`, `Clock`, `RandomSource`, and `ProviderSigner` are injected ports.
- User records contain the certificate and redacted scrypt record; Agent records contain public registration material only. The returned Provider attestation is not stored in the Agent record.
- Memory registries lock atomic uniqueness. SQLite uses transactional writes, uniqueness constraints, structural read checks, and rollback for incomplete Agent/OTK writes.
- Ordinary backend exceptions normalize to closed registration errors; `MemoryError`, `KeyboardInterrupt`, and `SystemExit` propagate.

## 5. Commands executed

| Command | UTC timestamp | Exit code |
|---|---|---:|
| Public-API RED: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py -q` | 2026-07-17, Task 9 | 1 |
| Public-API GREEN: `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py -q` | 2026-07-17, Task 9 | 0 |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py -q` (review-fix confirmation) | 2026-07-17T10:44:11Z | 0 |
| `.\.venv\Scripts\python.exe -m pytest tests/unit tests/protocol tests/integration tests/security -q` | 2026-07-17T10:58:04Z | 0 |
| `.\.venv\Scripts\python.exe -m mypy src` | 2026-07-17T10:44:11Z | 0 |
| `.\.venv\Scripts\ruff.exe check src tests`; `.\.venv\Scripts\ruff.exe format --check src tests` | 2026-07-17T10:44:11Z | 0; 0 |
| `.\.venv\Scripts\python.exe -m pip check`; `git diff --check` | 2026-07-17T10:44:11Z | 0; 0 |
| Public-surface security test; public-vector/evidence secret-field scan; production scope scan | 2026-07-17T10:52:37Z | 0; 1 expected no-match; 1 expected no-match |

The RED was intentional: the new exact public-surface test expected `AgentRegistrationService`, absent from `saga.protocols.__all__`; it produced one failure and four passes before the one-line export change. Task 8 adds evidence over completed Tasks 4--7, so its report honestly records no manufactured behavioral RED.

## 6. Test results

| Gate | Result |
|---|---|
| Public API review-fix confirmation | 6 passed in 0.20s; exit 0 |
| Registration protocol, integration, security, and Phase 2 scope suite | 509 passed in 24.69s; started 2026-07-17T10:58:04Z, completed 2026-07-17T10:58:29Z; exit 0 |
| `.\.venv\Scripts\python.exe -m mypy src` | no issues in 30 source files; exit 0 |
| Ruff check and format check | all checks passed; 59 files formatted; exit 0 |
| `.\.venv\Scripts\python.exe -m pip check` and `git diff --check` | no broken requirements; clean diff check; exit 0 |
| Public-surface secret assertion | `tests/security/test_registration_security.py::test_public_results_errors_and_source_tree_do_not_contain_known_secrets`: 1 passed in 0.37s; exit 0 |
| Public-vector/evidence structured-secret scan | no matches; `rg` exit 1, which is the expected no-match result |
| Production Phase 2 scope scan | no matches; `rg` exit 1, which is the expected no-match result |

## 7. Memory/SQLite parity, rollback, and restart evidence

Shared scenarios exercise matching memory/SQLite outcomes for success, duplicate conflicts, signature tamper rejection, and no partial records after injected failure. SQLite tests close and reopen the database to prove User records, complete ordered public OTK rows, and uniqueness survive restart. Failure before/after the Agent row, during the final OTK row, and at commit leaves no observable partial Agent/OTK record.

## 8. Security and secret-scan evidence

Registration tests reject forged User metadata/OTK signatures, altered endpoint, `PAC_A`, `PK_Prov`, certificate/identity mismatches, wrong owner/password, malformed records, and backend-detail leakage. Results, exceptions, event DTOs, representations, vectors, and this report must not expose passwords, private keys, `SAC_A`, SOTKs, raw password verifiers, or Provider private material. Synthetic passwords are test inputs only; captured public outputs are asserted separately.

The following commands are the reproducible Phase 2 secret and scope gates. The first command checks public result/error/representation text against known synthetic credentials and source/vector PEM/SOTK markers. The second command scans only the public registration vector and this evidence report: it rejects PEM private-key blocks and structured JSON-like fields named `sotk`, `secret_key`, `private_key`, `password`, `password_hash`, `password_verifier`, or `password_record`. Its expected successful result is `rg` exit code 1 (no matches); exit 0 means a prohibited public artifact was found, and any other exit code is a scan failure.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/security/test_registration_security.py::test_public_results_errors_and_source_tree_do_not_contain_known_secrets -q
rg -n -i -e '-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----' -e '"(?:sotk|secret[_-]?key|private[_-]?key|password(?:[_-]?(?:hash|verifier|record))?)"\s*:' tests/vectors/registration-records.json docs/phase-2-verification.md
```

The production scope command scans exactly the Phase 2 implementation roots `src/saga/protocols`, `src/saga/adapters/persistence`, and `src/saga/ports` (Python files only). It rejects Phase 3 policy/OTK/ACT behavior, network/API/formal/performance surfaces, and task/tool authorization. It likewise passes only when `rg` exits 1 with no matches; exit 0 is a scope violation and another exit code is a scan failure.

```powershell
rg -n -i --glob '*.py' -e 'fastapi|pydantic|proverif|benchmark|contactpolicymatcher|wildcard|pair_counter|otk_allocate|otk_consume|act_service|task_authorization|tool_authorization|socket\.|http\.server|time\.sleep' src/saga/protocols src/saga/adapters/persistence src/saga/ports
```

Rerun at `2026-07-17T10:52:37Z`: the public-surface test passed (exit 0); both `rg` commands returned the expected no-match exit 1.

## 9. Unresolved paper assumptions and limitations

- CA issuance, User/Agent key generation, Provider provisioning, and persistent identity assurance are preprovisioned assumptions.
- TLS certificate retrieval and all Provider/Agent or Agent/Agent handshakes are deferred network evidence.
- Contact Policy interpretation, budgets, pair counters, OTK lifecycle/allocation, activation/deactivation, ACT use, transport, ProVerif, and performance experiments remain outside Phase 2.
- SQLite is a reproduction engineering choice; the paper does not require it.

## 10. Phase 3 boundary and user acceptance question

After whole-phase independent review has zero Critical and Important findings and final gates are recorded here, Phase 3 may be planned to address Contact Policy interpretation, pair budgets, and public OTK lifecycle/allocation. It must not add ACT, network, or innovation behavior without its own approved boundary.

Do you accept the completed Phase 2 registration evidence and authorize Phase 3 planning (not implementation)?
