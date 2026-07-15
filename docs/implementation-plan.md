# SAGA Base Reproduction Master Implementation Plan

This document defines phase boundaries and release gates. Before implementation of each phase, create a dedicated `docs/superpowers/plans/YYYY-MM-DD-saga-phase-N-<name>.md` with exact files, tests, interfaces, commands, expected failures, minimal implementation steps, and commits. No phase may borrow future-extension behavior.

## Program Contract

The paper's protocol text is normative. Figures, evaluation text, approved reproduction decisions, and reference-code observations follow the precedence recorded in `docs/ambiguities-and-decisions.md`. Every executable behavior, protocol field, security test, and performance metric must have a classified row in `docs/feature-source-matrix.md`; an unclassified item fails the phase gate.

The implementation uses a pure protocol core with infrastructure adapters. `domain` has no Web, database, or concrete-cryptography dependency; `crypto` wraps mature libraries; `protocols` depends on `domain`, `crypto`, and `ports`; `adapters` implements ports and transports protocol calls. FastAPI routes contain no authorization decisions, and persistence adapters contain no policy decisions.

The baseline excludes tool/task/resource capability fields, risk-adaptive Token policy, prompt-injection detection, active Token revocation, malicious/Byzantine Provider defenses, federation, NAT traversal, and other innovation extensions. These remain documentation-only future directions until the complete base-reproduction gate passes and `saga-baseline-v1` exists.

## Global TDD Rule

For every protocol behavior: write a failing test, run it and record the expected failure, implement the minimum behavior, run the focused test, then run the phase regression suite. Never weaken an assertion or remove a test to obtain green status.

Before touching implementation files in any phase, commit a separate detailed TDD plan at `docs/superpowers/plans/YYYY-MM-DD-saga-phase-N-<name>.md`. That plan must split work into independently reviewable red-green-refactor slices, name exact interfaces and files, include test bodies or complete fixture expectations, give exact focused and regression commands with expected results, and define each commit. A phase cannot start from this master plan alone.

Cross-phase regression is cumulative. A phase exit requires its focused tests, all earlier-phase tests, static lint, type checking, `git diff --check`, source-matrix classification, and an explicit review that no later-phase behavior entered the commit.

---

## Phase 1 - Canonical serialization and cryptographic foundations

**Goal:** Establish library-level deterministic encoding and mature-library cryptographic primitives, fixed vectors, and strict validation without implementing any registration, policy, Token state machine, persistence workflow, HTTP service, or network protocol.

**Inputs:** The cryptographic decisions in the design specification and architecture; protocol tuple definitions in `docs/protocol-messages.md`; decisions 1–5 and 14 in `docs/ambiguities-and-decisions.md`; the classified primitive and encoding rows in `docs/feature-source-matrix.md`.

**Expected packages/files:** `pyproject.toml` and a locked dependency file; `src/saga/domain/encoding.py` for schema-safe values; `src/saga/crypto/canonical.py`, `signatures.py`, `key_agreement.py`, `kdf.py`, `aead.py`, `passwords.py`, and `certificates.py`; `tests/unit/test_canonical.py`, `test_signatures.py`, `test_key_agreement.py`, `test_kdf.py`, `test_aead.py`, `test_passwords.py`, and `test_certificates.py`; fixed public-only vectors under `tests/vectors/`. Package `__init__.py` files expose only stable primitive interfaces.

**Tests written first:** Deterministic UTF-8 JSON and fixed field order; rejection of unknown and duplicate fields, floats in security fields, non-integer Unix milliseconds, malformed or padded Base64URL; Ed25519 sign/verify and every signed-byte mutation; X25519 two-party agreement; HKDF-SHA256 with `salt=None` and exact `info=b"SAGA-ACT-DERIVE/v1"`, including domain-separation mismatch; ChaCha20-Poly1305 with exact `aad=b"SAGA-ACT/v1"`, fresh outer nonce, and nonce/ciphertext/tag/AAD tampering; scrypt `N=2^15, r=8, p=1, dkLen=32` with 16-byte secure salt; X.509 chain, identity, key-binding, validity, and wrong-anchor cases. Each vector test is first observed failing before the smallest wrapper exists.

**Security invariants:** No custom cryptographic algorithm; binary values use strict unpadded Base64URL; security times are integer Unix milliseconds; canonical parsers fail closed; keys and plaintext secrets are never logged; outer message `version` is not silently inserted into a paper-defined signed tuple or ACT plaintext; an AEAD nonce is not the ACT's paper plaintext nonce `N`; algorithm and serialization choices are reproduction engineering supplements, not paper-mandated suites.

**Deliverables:** Importable, typed primitive interfaces; public fixed vectors for every primitive and paper-defined signature tuple; deterministic parser/serializer fixtures; negative tamper vectors; dependency/version documentation sufficient to reproduce the vectors.

**Exit gate:** All Phase 1 unit/vector tests, lint, and type checks pass on a clean run; repeated serialization is byte-identical; every mutation fails closed; dependency audit confirms only mature libraries implement primitives; no `protocols`, policy, ACT lifecycle, HTTP, database, or service behavior exists.

**Known paper mapping:** IV-A cryptographic assumptions; IV-B Steps 1–4; IV-C Steps 2, 5–7 and exact main-text Provider tuple `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>`; IV-E Steps 3, 6–8. Deterministic JSON, concrete algorithms, HKDF constants, AAD, Base64URL, and scrypt parameters are explicitly reproduction choices.

**Commit boundary:** One or more reviewable commits limited to project setup, `domain` encoding values, `crypto` wrappers, public test vectors, and Phase 1 tests. The last Phase 1 commit must leave no registration, Contact Policy, OTK allocation, ACT issuance/use, persistence, FastAPI, or transport implementation.

---

## Phase 2 - User and Agent registration

**Goal:** Implement pure-core User and Agent registration with certificates, exact signatures, uniqueness, password storage, identity-verifier substitution, and atomic registry semantics, but no Contact Policy evaluation, OTK issuance, or ACT behavior.

**Inputs:** Phase 1 interfaces/vectors; paper IV-B and IV-C; architecture registration/state/error contracts; the User/Agent message ledger; ambiguity decisions 1, 13, and 14. Phase 2's detailed TDD plan must freeze exact registration command/result and repository-port signatures before implementation.

**Expected packages/files:** `src/saga/domain/users.py`, `agents.py`, `endpoints.py`, `errors.py`, and `events.py`; `src/saga/ports/identity.py`, `clock.py`, `random.py`, `registries.py`, and `transactions.py`; `src/saga/protocols/user_registration.py` and `agent_registration.py`; `src/saga/adapters/persistence/memory.py` and `sqlite.py` for registration records and atomic commits; `tests/protocol/test_user_registration.py`, `test_agent_registration.py`, and `test_registration_messages.py`; `tests/integration/test_registration_persistence.py` and restart/rollback tests.

**Tests written first:** User success and invalid identity/certificate/password input; duplicate `uid_U`; scrypt record verification without secret disclosure; exact Agent tuple and OTK-signature verification; exact Provider main-text five-item attestation tuple; duplicate `aid_A` and duplicate endpoint; invalid owner/Agent certificate, altered `ED_A`, `PK_A`, `PAC_A`, or `PK_Prov`; partial-failure rollback; memory/SQLite parity and restart. The deterministic `IdentityVerifier` test adapter and local trusted demo record are tested as substitutes for the paper assumption, never as OpenID Connect or Sybil-proof reproduction.

**Security invariants:** User and Agent registration are all-or-nothing; the Provider verifies certificate bindings and every exact signature before commit; `aid_A` and endpoint are globally unique; Agent private TLS key, `SAC_A`, and SOTKs remain Agent-local; password material and private keys never enter logs or registry responses; stable errors fail closed without verification oracles; the Figure 8 mismatch never overrides IV-C Step 7.

**Deliverables:** Typed immutable User/Agent records, registration protocol services, identity and registry ports, memory and SQLite registration adapters, stable domain errors/audit events, and IV-B/IV-C protocol-coverage tests.

**Exit gate:** Registration tests pass identically for memory and SQLite, including rollback and restart; every IV-B/IV-C message, signature object, and verifier maps to a test; no policy matcher, pair budget, contact resolution, OTK allocation/consumption, ACT plaintext/ciphertext, quota, HTTP route, or network completion claim exists.

**Known paper mapping:** IV-B User Registration and IV-C Agent Registration; Appendix Figure 8 is retained only as a documented inconsistency. External persistent-human identity and certificate placement are assumptions/deployment details; local adapters do not reproduce OpenID Connect or prove Sybil resistance.

**Commit boundary:** Commits contain registration domain/ports/protocols, registration-only persistence, and tests. Phase 2 is rejected if any commit implements Contact Policy, pair counters, discovery/OTK issuance, ACT creation/use, or transport endpoints.

---

## Phase 3 - Contact Policy, OTK allocation, and concurrent state

**Goal:** Implement deterministic Contact Policy and linearizable contact resolution/OTK allocation with memory and SQLite parity, while stopping before DH completion or ACT issuance.

**Inputs:** Phase 2 registries and transaction ports; IV-D and IV-E Steps 1–3; architecture persistence/CAS contract; ambiguity decisions 9–12; atomicity experiments in `docs/experiment-plan.md`. The detailed TDD plan must specify transaction snapshots, expected revisions, CAS retry ownership, barriers, crash points, and stable error outcomes.

**Expected packages/files:** `src/saga/domain/policies.py`, `otk.py`, and `contact.py`; `src/saga/ports/contact_state.py` with versioned snapshot and compare-and-swap contracts; `src/saga/protocols/contact_resolution.py`; memory and SQLite contact-state implementations in `src/saga/adapters/persistence/`; `tests/unit/test_policy_matching.py`; `tests/protocol/test_contact_resolution.py` and `test_policy_updates.py`; `tests/integration/test_contact_atomicity.py`, `test_contact_restart.py`, and adapter parity tests; deterministic concurrency helpers under `tests/support/`.

**Tests written first:** Specificity exact Agent ID > User-domain wildcard > Agent-type wildcard > global wildcard; reject equal-specificity overlaps; distinguish explicit deny (`budget=-1`), no match, budget exhaustion, pool exhaustion, inactive Agent, and conflict; initialize pair budget once; atomically read policy/active state, cap/check/decrement pair counter, and allocate one public OTK; last-OTK and last-budget barriers with one winner; no duplicate OTK under concurrency; replenishment does not reset budget; policy decreases cap with `min(old_remaining,new_budget)`, increases do not restore spent quota, and deny/no-match immediately blocks new requests; deactivation blocks discovery; SQLite rollback/restart and injected failures.

**Security invariants:** The protocol layer owns authorization decisions and rereads/revalidates after every structural CAS conflict; adapters only atomically compare/replace versioned state and never decide policy. Policy, active state, pair counter, and OTK pool change in one transaction. A returned public OTK is consumed once and is never reissued, even after delivery failure. OTK refill never restores spent pair budget. Existing ACT revocation is not introduced. Concurrency tests use barriers, not sleeps.

**Deliverables:** Deterministic policy validation/matching, versioned contact-state ports, protocol-owned CAS retry loop, memory/SQLite atomic adapters, one-OTK contact bundle, audit-safe stable failures, and concurrency/restart evidence.

**Exit gate:** All policy, contact, adapter-parity, deterministic race, rollback, and restart tests pass; one-item pool and budget-one cases each yield exactly one winner; all losers have no partial mutation; IV-E Steps 1–3 inputs/verification are covered; there is no DH-derived `SDHK`, SOTK destruction, ACT creation/encryption/state/use, FastAPI, or network-completion claim.

**Known paper mapping:** IV-D Contact Policy, OTK budget, refill, update, and deactivation; IV-E Steps 1–3. Specificity tie rejection, update/capping rules, transaction isolation, stable errors, and CAS retry are reproduction engineering decisions. Provider is honest-but-curious/protocol-following, not Byzantine.

**Commit boundary:** Separate reviewable commits for policy semantics, port/CAS contract, memory adapter, SQLite adapter, and concurrency/restart tests. Every Phase 3 commit must remain ACT-free; the first ACT code belongs only to Phase 4 after Phase 3 exit.

---

## Phase 4 - ACT creation, encryption, binding, lifetime, and q_max

**Goal:** Complete the in-memory protocol state machine for SOTK claim, DH/HKDF, exact five-field ACT creation/encryption, binding, lifetime, legal reuse, and linearizable quota, without claiming HTTP, certificates-in-flight, or network completion.

**Inputs:** Phase 1 crypto, Phase 2 registrations, Phase 3 OTK/contact state; IV-E Steps 4–8 logical protocol; ACT lifecycle and failure semantics; ambiguity decisions 3, 5–8, 10–12, and 17. The detailed TDD plan must name the authorization snapshot/CAS API, handler-admission boundary, and no-crash versus crash assertions.

**Expected packages/files:** `src/saga/domain/act.py` and `token_state.py`; `src/saga/ports/token_state.py`; `src/saga/protocols/agent_handshake.py`, `act_establishment.py`, and `act_use.py`; memory and SQLite SOTK/Token-state adapters; `tests/unit/test_act_plaintext.py`; `tests/protocol/test_act_establishment.py`, `test_act_use.py`, and `test_act_lifecycle.py`; `tests/integration/test_token_atomicity.py`, `test_sotk_atomicity.py`, `test_token_restart.py`, and deterministic crash/race fixtures.

**Tests written first:** Exact plaintext fields only `nonce`, `issued_at`, `expires_at`, `q_max`, `initiating_agent_access_control_public_key`; outer `version`; B/A X25519 and fixed HKDF yield the same `SDHK`; wrong signatures/cert bindings or missing/consumed SOTK fail before ACT creation; simultaneous SOTK claim has one winner; crash before SOTK claim/delete consumes nothing, crash after claim/delete and before ACT storage loses the OTK, and crash after ACT storage and before response may leave an orphan ACT at `A`; AEAD envelope/tamper behavior; mTLS-authenticated-peer identity is represented only by an injected verified identity at this phase; constant-time semantic `PAC_B` binding; future-issued, boundary `[issued_at, expires_at)`, expired, exhausted, malformed, and wrong-Agent cases; legal same-Agent reuse within quota, including a simulated reconnect; task-completion discard; policy update/deactivation do not revoke an issued ACT; `q_max=1` barriers at 2/8/32/128 workers.

**Security invariants:** ACT plaintext remains exactly five paper fields—no `token_id`, issuer/subject IDs, `task_id`, context hash, tool, action, parameter, or resource. A atomically claims/deletes SOTK as an irreversible linearization commit before a separate ACT create/store commit; deletion is never rolled back, every later failure requires a fresh OTK, and the two commits are never modeled as one all-or-nothing transaction. The receiving protocol owns versioned snapshot validation and CAS retry; failed validation consumes no quota. In no-crash races, exactly one `q_max=1` winner enters the handler and produces one test side effect; losers produce none. Crash injection requires persisted `use_count <= 1`, no loser effect, and recoverable state, but makes no exactly-once claim for the winner's external side effect. No outbox/idempotency mechanism is added.

**Deliverables:** Pure/in-process Agent-to-Agent protocol calls, ACT codecs and state machines, SOTK/Token persistence ports and adapters, deterministic time/concurrency/crash tests, and an explicit limitation note that task binding and semantic duplicate-request detection are absent.

**Exit gate:** Phase 1–4 regression passes for memory and SQLite; ACT vectors and lifecycle boundaries pass without `sleep`; SOTK and `q_max` races linearize; restart/crash assertions meet the bounded non-exactly-once contract; protocol mappings cover IV-E Steps 4–8 logically. No FastAPI route, live socket, test CA deployment, TLS handshake, certificate-to-peer mapping, or real end-to-end/network completion claim is permitted.

**Known paper mapping:** IV-E Steps 4–8 and Figure 9; Appendix E A3, A5, and A8 behavior. Half-open time validity, future-issued rejection, persistent CAS, and crash semantics are reproduction engineering. Legal ACT reuse is paper behavior; TLS record replay and application-semantic deduplication are not modeled as ACT rejection.

**Commit boundary:** Reviewable commits separate exact ACT schema/crypto, SOTK establishment, validation/lifecycle, persistence/CAS, and concurrency/crash tests. Phase 4 ends at in-memory/in-process protocol completion and must say so in commit messages and documentation.

---

## Phase 5 - FastAPI services, test CA, real mutual TLS, and end-to-end demo

**Goal:** Expose the completed core through real FastAPI Provider/Agent services, an independent test CA, server-authenticated User–Provider TLS, and real Agent mTLS, then demonstrate IV-B–IV-E end to end over sockets.

**Inputs:** Phase 1–4 protocols and adapters; network architecture and trust-boundary rules; certificate ambiguity decision 14; reachability/environment decision 16; network cases in `docs/experiment-plan.md`. The detailed TDD plan must specify processes, ports, certificate identities, trust stores, timeouts, failure injection, Step 6 `Cert_U2` engineering supply path, and cleanup.

**Expected packages/files:** `src/saga/adapters/http/provider.py`, `agent.py`, `schemas.py`, `errors.py`, `identity.py`, and `middleware.py`; `src/saga/adapters/tls/config.py` and `peer_identity.py`; `scripts/create_test_ca.py`, `run_provider.py`, `run_agent.py`, and `demo.py`; test-only CA fixtures under `tests/fixtures/pki/` or generated temporary directories; `tests/integration/test_provider_tls.py`, `test_agent_mtls.py`, `test_network_protocol.py`, `test_network_failures.py`, and `test_demo.py`; deployment/example configuration with secrets excluded.

**Tests written first:** Provider rejects untrusted, expired, wrong-EKU, wrong-SAN, or mismatched Agent client certificates; Agent-to-Agent handshake requires both valid Agent certificates and maps authenticated certificate identity to registered `aid`; wrong-Agent ACT is rejected from that identity; User registration uses server-authenticated TLS plus User protocol authentication, with no User client-certificate/mTLS requirement; real test-CA chain and hostname checks; timeout, interruption, malformed response, TLS record replay, reconnection, and legal ACT reuse; full registration/contact/ACT/use flow; external Step 6 `Cert_U2` transport/retrieval is labeled and tested as an engineering supplement rather than silently added to the paper tuple.

**Security invariants:** FastAPI routes only parse/map/dispatch and contain no policy or Token decision. Agent service boundaries enforce real mTLS; User–Provider is server-authenticated TLS plus User authentication, not User mTLS. TLS identity, claimed `aid`, registry binding, and `PAC` binding must agree. Secret values and ACT plaintext never enter responses/logs. Test CA is independent from Provider protocol logic and is never represented as production PKI. Local reachability does not claim public routing, NAT traversal, or DoS resistance.

**Deliverables:** Runnable Provider and multiple Agent services, independent test-CA tooling, real TLS/mTLS identity adapter, network error mapping, reproducible end-to-end demo, and process-level integration evidence.

**Exit gate:** Real X.509 Provider/Agent cases and full network demo pass with bounded timeouts; negative certificate and identity cases fail before state mutation; reconnection/replay boundaries are distinct; User–Provider tests prove server-auth TLS plus User authentication rather than User mTLS; network tests execute protocol decisions only through the existing core; no claim of Internet reachability, production CA, DoS defense, or external identity-provider reproduction is made.

**Known paper mapping:** III-C transport and environmental assumptions; IV-B–IV-E network flow; VI-A CA deployment observation. Certificate placement and the missing Step 5 transport source for `Cert_U2` remain documented paper inconsistencies; the concrete supply path is classified as reproduction engineering.

**Commit boundary:** Separate commits for TLS identity/config, Provider API, Agent API, CA/fixtures, end-to-end harness, and demo documentation. No attack-suite completion, ProVerif proof claim, benchmark result, or baseline tag enters Phase 5.

---

## Phase 6 - Twenty attack experiments and ProVerif

**Goal:** Execute the exact twenty runtime attack categories with provenance and invariant assertions, and independently model the paper's three formal security claim families with non-vacuity/reachability sanity checks.

**Inputs:** Phase 1–5 tested system; exact attack inventory and concurrency/crash experiments in `docs/experiment-plan.md`; threat-model classifications; paper IV-F, Appendix D, Appendix E A1–A8; feature-source matrix. The detailed TDD plan must give one failing security test per heading before harness/defense completion and exact ProVerif invocation/result parsing.

**Expected packages/files:** `tests/security/test_01_forged_user_signature.py` through `test_20_concurrent_qmax_race.py` (or an equally one-to-one named inventory); shared mutation/proxy/race helpers under `tests/security/support/`; `verification/proverif/agent_provider.pv` and `agent_agent.pv`; `scripts/run_security_suite.py` and `scripts/run_proverif.py`; versioned, secret-free result summaries under `results/security/` and `results/proverif/`; source-matrix updates for every executable test and claim.

**Tests written first:** The exact headings are (1) Forged User signature, (2) Forged Provider signature, (3) Forged Agent identity, (4) Modified Agent endpoint, (5) Modified Agent access-control public key, (6) Modified OTK, (7) Reuse of a consumed OTK, (8) ACT ciphertext tampering, (9) ACT encryption-nonce tampering, (10) ACT used by the wrong Agent, (11) ACT use after expiration, (12) ACT use beyond `Q_max`, (13) Token replay / replay-boundary confusion, (14) Unauthorized Agent obtains OTK, (15) Contact Policy OTK budget exceeded, (16) Deactivated Agent remains discoverable, (17) Malicious Agent shares a Token, (18) Man-in-the-middle modifies a request, (19) Agent metadata replaced after registration, and (20) Concurrent `Q_max` race bypass. Each asserts the specified rejection/admission point, unchanged losing state, provenance category, and the distinct positive controls for legal reuse and A8 bounded accepted use.

**Security invariants:** Results separate Appendix E direct evaluation, threat-model/protocol inference, reproduction engineering hardening, paper assumptions, and formal claims. The three and only three ProVerif security claim families are: (1) Token/ACT secrecy against the modeled Dolev–Yao attacker, (2) injective Agent–Provider authentication/correspondence, and (3) injective Agent–Agent authentication/correspondence. Successful reachability/non-vacuity queries are sanity checks showing modeled honest executions can reach relevant events; they are not a fourth security property. ProVerif does not prove Contact Policy semantics, OTK/pair-budget/`q_max` atomicity, availability, DoS resistance, malicious-Provider security, TLS/library correctness, secure deletion, serialization correctness, crash safety, or absence of implementation vulnerabilities. Twenty passing attacks do not expand formal claims.

**Deliverables:** Twenty one-to-one security tests and provenance records; deterministic OTK/budget/SOTK/`q_max` races across memory, SQLite, and relevant real-network paths; crash-injection report with no exactly-once overclaim; two executable ProVerif models; parsed query results and reachability sanity evidence; Appendix E A1–A8 mapping.

**Exit gate:** All twenty headings run and assert their invariant; legal ACT reuse, wrong-Agent transfer, expired/exhausted reuse, and TLS record replay have separate outcomes; no-crash races meet exact single-winner/side-effect rules and crash tests retain only the bounded recovery claims; ProVerif reports success for exactly the three scoped claim families and the reachability/non-vacuity sanity checks; unexpected model results or unavailable ProVerif fail the phase rather than being waived.

**Known paper mapping:** IV-F and Appendix D for the three formal properties and reachability checks; Appendix E A1–A8 and capabilities C1–C6 for experimental provenance. A8 is accepted-but-bounded valid use, C5/C6 are not falsely assigned direct Appendix E rows, and engineering tests remain distinct from proof.

**Commit boundary:** Commits separate runtime attack groups, deterministic concurrency/crash security experiments, Agent–Provider model, Agent–Agent/Token-secrecy model, and result parsing. No performance acceptance, baseline tag, or innovation branch is part of Phase 6.

---

## Phase 7 - Directional performance reproduction and result artifacts

**Goal:** Run the already preregistered microbenchmarks and protocol/network experiments, evaluate fixed same-environment directional/repeatability gates, and emit complete raw/summary/trend artifacts without post-hoc changes.

**Inputs:** Phase 1–6 stable implementation; every fixed parameter, seed, order formula, warmup, repetition, bootstrap, tolerance, failure rule, schema, and paper comparison in `docs/experiment-plan.md`. The detailed TDD plan must first encode the preregistration as schema/validator tests; it may not revise thresholds after observing data.

**Expected packages/files:** `tests/performance/test_result_schema.py`, `test_qmax_trend.py`, `test_lifetime_trend.py`, `test_agent_scale.py`, and `test_concurrent_throughput.py`; `scripts/benchmark.py`, `validate_results.py`, and `compare_paper.py`; `src/saga/verification/benchmark_schema.py` and `statistics.py` isolated from runtime authorization; `results/benchmark-samples.csv`, `results/benchmark-summary.csv`, `results/benchmark-trend-gates.csv`, and a versioned equivalent JSON document such as `results/benchmark-results.json`; environment/configuration manifests and comparison output.

**Tests written first:** Schema version exactly `saga-benchmark/v1`; three CSVs never mix row types; CSV/JSON field-for-field canonical equivalence; every offered warmup/measured success/failure retained; exactly one summary per measured grouping and no trend row in summaries; complete deterministic gate-ID set; type-7 quantiles, sample standard deviation, Theil–Sen slope, paired bootstrap over repetition IDs, fixed orientation, and non-finite/missing/extra/duplicate/post-hoc rows rejected. Harness tests freeze: `q_max=[1,2,4,8,16,32,64]`, lifetime `[1,5,30,60,300]`, Agent counts `[1,10,100]` × concurrency `[1,8,32]`, and throughput concurrency `[1,2,4,8,16,32,64]` for `q_max=1` and `64`, using the exact seeds/orders/counts/durations from the preregistration.

**Security invariants:** Benchmarks never log or persist passwords, private keys, SOTKs, `SDHK`, or ACT plaintext. Dirty runs are retained and labeled. Failures, warmups, saturation, outliers, and telemetry gaps are recorded, not deleted. No adaptive stopping, extra repetitions after inspection, threshold manipulation, or cross-hardware absolute gate is allowed. Network, memory, and SQLite scenarios remain separate; microbenchmark setup does not leak into timed operations unless explicitly part of the registered metric.

**Deliverables:** Cryptographic microbenchmark and registration/authorization measurements; the fixed `q_max`, Token-lifetime, 1/10/100 receiving-Agent, and concurrent-throughput experiments; full environment fingerprint/configuration; the three CSV artifacts plus equivalent JSON; schema/trend validator; paper comparison with comparability and deviation explanations.

**Exit gate:** Every registered point and required trend row is present and validates. `q_max` requires endpoint delta `<= -0.10` with upper 95% CI `< 0` and negative slope-CI upper bound; lifetime requires every paired adjacent count non-increasing, endpoint ratio `<= 0.20`, and ratio-CI upper bound `< 0.50`; every Agent-scale cell has throughput CV and relative CI half-width `<= 0.15` and each concurrency has a non-inconclusive direction classification; every adjacent concurrent-throughput comparison is non-inconclusive. Any missing/invalid sample, unmet fixed condition, or inconclusive required classification fails the gate and is reported without changing the preregistration. Paper absolute values are comparison data, not cross-environment thresholds.

**Known paper mapping:** Section VI performance/evaluation figures and tables as identified in the comparison artifact; the paper motivates direction and comparison, while precise portable gates are preregistered reproduction engineering. Appendix E, ProVerif properties, reachability sanity, and engineering tests remain separate evidence categories.

**Commit boundary:** Commits separate schema/statistics tests, each benchmark harness family, artifact validation, and final captured results. Result commits identify the tested 40-character Git revision, dirty flag, environment fingerprint, and fixed configuration. No tag or future-feature branch is created in Phase 7.

---

## Phase 8 - Reproduction report, complete regression, baseline tag, and branch gate

**Goal:** Audit all evidence, run the complete clean-tree regression and release gates, publish an honest reproduction report, and only then create the immutable baseline tag that unlocks separately scoped innovation work.

**Inputs:** All Phase 0 documents; Phase 1–7 code, detailed TDD plans, commits, tests, formal outputs, and performance artifacts; complete source matrix and ambiguity register. The Phase 8 detailed TDD plan must define report-lint/schema checks, clean checkout commands, tag preconditions, failure handling, and exact evidence links before report editing or tagging.

**Expected packages/files:** `docs/reproduction-report.md`; final updates to `docs/feature-source-matrix.md` and `docs/ambiguities-and-decisions.md`; release/audit scripts such as `scripts/check_source_matrix.py`, `scripts/check_claims.py`, and `scripts/release_baseline.py`; report validation tests; finalized `results/security/`, `results/proverif/`, and benchmark artifacts; annotated Git tag `saga-baseline-v1`. No future-extension runtime package belongs in the baseline commit.

**Tests written first:** Fail report validation for an unclassified executable behavior, missing IV-B–IV-E mapping, missing attack, broadened ProVerif claim, reachability described as security, missing artifact/schema row, unexplained performance deviation, secret in output, dirty/untraceable run, unsupported public-reachability/DoS/human-identity claim, or absent limitation. Fail release logic if any global checklist item is false, the working tree is dirty, the tag points to an unverified commit, or creation of `feature/agent-tool-authorization` is attempted before `saga-baseline-v1` exists.

**Security invariants:** The report preserves the exact five-field ACT and admits absent cryptographic task/tool/resource binding; distinguishes paper design, engineering supplements, reference observations, formal proofs, reachability sanity, Appendix E evaluation, and twenty engineering attacks; preserves honest-but-curious Provider, external identity, routing/DoS, crash, and legal-reuse limitations. No passing test is elevated into a broader claim. Secrets are absent from committed artifacts. Active revocation, risk adaptation, prompt-injection defense, tool authorization, and all other innovation remain deferred.

**Deliverables:** Reproduction report with exact paper/result traceability and deviations; complete clean-run verification transcript; no-unclassified-behavior audit; finalized artifacts; annotated `saga-baseline-v1` tag on the verified baseline commit; documented post-baseline branch protocol.

**Exit gate:** Every item in the Base-Reproduction Completion Gate below is independently evidenced on the exact clean commit; report and artifacts pass validation; tag creation is the final baseline action. If any item fails, no tag is created and no innovation branch is permitted. Only after verifying that `saga-baseline-v1` resolves to the accepted commit may a later, separate action create `feature/agent-tool-authorization` from that tag; Phase 8 itself does not implement that branch's feature.

**Known paper mapping:** Complete IV-B–IV-E protocol mapping; IV-F/Appendix D three formal properties plus separate reachability sanity; Appendix E A1–A8; Section VI performance comparisons; all known discrepancies and unsupported claims enumerated in the report.

**Commit boundary:** Commit final report, matrix/decision updates, validators, and immutable result artifacts first. Run the full gate against that exact clean commit, then create annotated tag `saga-baseline-v1`. It is forbidden to create `feature/agent-tool-authorization`, commit tool-authorization code, or otherwise start innovation before the tag exists and resolves to the verified commit.

---

## Base-Reproduction Completion Gate

- [ ] Static lint passes.
- [ ] Type checking passes.
- [ ] Unit, protocol, integration, security, and performance-trend tests pass.
- [ ] Real Provider/Agent mTLS end-to-end tests pass.
- [ ] Concurrent `q_max=1` permits exactly one request.
- [ ] OTK and pair-budget operations are atomic under concurrency.
- [ ] ProVerif token-secrecy query passes.
- [ ] ProVerif Agent-Provider authentication queries pass.
- [ ] ProVerif Agent-Agent authentication queries pass.
- [ ] Performance trends are reproducible and deviations are explained.
- [ ] Feature-source matrix has no unclassified executable behavior.
- [ ] Paper differences, limitations, and unsupported claims are documented.
- [ ] `saga-baseline-v1` is created before any tool-authorization branch.

## Global Release Gate and Innovation Lock

The checklist is conjunctive: all items must be true for one exact, clean Git commit, with evidence traceable to that commit, its environment, raw samples, configuration, and tool versions. A partial pass, waived test, stale artifact, dirty result, unavailable ProVerif run, missing comparison, inconclusive required trend, or unexplained deviation is a release failure. The tag must never be moved to conceal a later change.

Until the annotated `saga-baseline-v1` tag has been created on that verified commit and independently resolved back to it, no person or automation may create `feature/agent-tool-authorization` or any equivalent tool-authorization branch, and no tool/task/resource authorization code may enter the baseline. After the tag, innovation begins from an explicitly separate branch and specification; it must not rewrite the base ACT or retroactively expand SAGA's paper claims.
