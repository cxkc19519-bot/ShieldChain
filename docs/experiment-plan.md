# SAGA Reproduction Experiment Plan

## Reproducibility Metadata

Every run receives a unique `run_id`, UTC timestamp, Git commit, dirty-tree flag, phase/scenario identifier, random seed where a deterministic harness uses one, and a normalized environment fingerprint. The fingerprint includes CPU model/count, memory, OS/kernel, architecture, Python implementation/version, dependency lock hash and relevant library versions, ProVerif version, TLS/OpenSSL backend, SQLite version/journal mode, network topology, storage location/type, power/performance mode when observable, and all benchmark configuration.

Each experiment records adapter (`memory`, `sqlite`, or network), warmup count, formal sample count, concurrency, process/thread model, request and payload sizes, `q_max`, lifetime, Agent counts, OTK/pair budgets, timeout, and clock mode. Raw immutable CSV/JSON results precede summaries and charts. Secret-bearing values are represented only by safe identifiers or sizes; no private key, SOTK, `SDHK`, password material, or ACT plaintext is persisted.

## Unit and Protocol Verification

Unit tests cover deterministic UTF-8 encoding, strict unpadded Base64URL, integer time, rejection of unknown/duplicate/floating security fields, fixed Ed25519/X25519/HKDF/AEAD vectors, certificate bindings, signature input mutation, HKDF domain separation, and AEAD nonce/ciphertext/AAD mutation.

Protocol tests map every IV-B–IV-E step, signed tuple, verifier, key relationship, and state transition. They cover duplicate registration, endpoint/Agent uniqueness, policy specificity/ties, distinct policy/budget/pool failures, one-OTK issuance, SOTK deletion, exact five-field ACT creation, legal same-Agent ACT reuse, `[issued_at, expires_at)` engineering semantics, atomic quota, policy updates, deactivation, task-completion discard, and memory/SQLite parity. Time tests inject `Clock`; none use `sleep`.

## Twenty Required Security Attacks

The following inventory preserves the exact 20 requirement categories. “Appendix E direct evaluation” is experimental paper provenance, not formal proof. “Threat-model/protocol inference” maps a paper capability or verification rule not directly isolated in A1–A8. “Reproduction engineering hardening” covers implementation properties the paper does not prove.

Capability and evaluation labels remain exact: C1 is a registered adversarial Agent, C2 a compromised legitimate Agent, C3 an unregistered self-replicated child with shared parent material, C4 adversarial key/Token sharing, C5 attempted Sybil identities, and C6 the network Dolev-Yao attacker. Appendix E maps A1–A4 to C1/C2, A5–A6 and A8 to C1/C2/C3/C4, and A7 to C3. A8 is accepted-but-bounded valid ACT use, not rejection. Table IV maps no A1–A8 row directly to C5 or C6; C6 instead scopes the symbolic models, while runtime transport tests rely on the paper's TLS assumption.

### Attack 1: Forged User signature

- **Setup:** Register a User and construct an otherwise valid Agent registration or OTK record.
- **Mutation/adversarial action:** Replace `sigma_A^U` or `sigma_OTKi^U` with a signature from another key or random bytes.
- **Expected rejection point:** Provider IV-C Step 6 verification; no Agent/OTK state commits.
- **Invariant:** Only exact tuples signed by the owning User key are accepted; registries remain unchanged on failure.
- **Paper provenance category:** Threat-model/protocol inference from IV-C Steps 2, 5–6 (C6-style message manipulation).
- **Test layer:** Crypto unit plus protocol/integration transaction test.

### Attack 2: Forged Provider signature

- **Setup:** Establish a legitimate initiating Agent identity and receiving-side mTLS connection.
- **Mutation/adversarial action:** Present a fabricated `sigma_B^Prov` over otherwise plausible B metadata.
- **Expected rejection point:** Receiving Agent `A` at IV-E Step 6 Provider-attestation verification.
- **Invariant:** No SOTK is consumed and no ACT is created when Provider attestation fails.
- **Paper provenance category:** Appendix E direct evaluation A4; C1/C2.
- **Test layer:** Protocol security test and real mTLS integration test.

### Attack 3: Forged Agent identity

- **Setup:** Register benign `B`; attacker `M` knows public identifiers but lacks B's Agent TLS private key/certificate binding.
- **Mutation/adversarial action:** Claim `aid_B` using an invalid certificate, a certificate for M, or a mismatched authenticated peer identity.
- **Expected rejection point:** Agent-Agent mTLS handshake at IV-E Step 4, or peer-identity mapping before IV-E Step 6.
- **Invariant:** Claimed Agent identity must equal the certificate-authenticated registered identity; protocol state is untouched.
- **Paper provenance category:** Appendix E direct evaluation A1, with A2/A5 identity-binding context; C1/C2.
- **Test layer:** Real mTLS network test plus protocol identity-resolver test.

### Attack 4: Modified Agent endpoint

- **Setup:** Obtain a valid receiving-Agent discovery response.
- **Mutation/adversarial action:** Change `ED_A` after the User signature was created.
- **Expected rejection point:** Initiating `B` at IV-E Step 3 verification of `sigma_A^U`.
- **Invariant:** Endpoint is inseparable from `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>`; no connection is attempted to unauthenticated metadata.
- **Paper provenance category:** Threat-model/protocol inference from IV-C Step 2 and IV-E Step 3; C6.
- **Test layer:** Protocol security test; optional network proxy mutation harness.

### Attack 5: Modified Agent access-control public key

- **Setup:** Obtain signed registration metadata for A or B.
- **Mutation/adversarial action:** Substitute another `PAC` while retaining the original User/Provider signatures.
- **Expected rejection point:** IV-E Step 3 User-signature verification for receiver data, or IV-E Step 6 Provider-signature verification for initiator data.
- **Invariant:** A PAC substitution cannot alter DH inputs or ACT binding without invalidating an attestation; no SOTK/ACT state changes.
- **Paper provenance category:** Appendix E direct evaluation A4 (C1/C2); separate C6 message-mutation inference.
- **Test layer:** Protocol security test and canonical-signature unit test.

### Attack 6: Modified OTK

- **Setup:** Provider returns one valid signed `OTK_A^i` to B.
- **Mutation/adversarial action:** Flip an OTK byte or replace it with another public key while retaining `sigma_OTKi^U1`.
- **Expected rejection point:** B at IV-E Step 3 verification of `Sign_SK_U1(<aid_A, OTK_A^i>)`.
- **Invariant:** Only the exact User-signed OTK enters DH; the attacker cannot force an attacker-chosen shared secret.
- **Paper provenance category:** Threat-model/protocol inference from IV-C Step 2 and IV-E Step 3; C6.
- **Test layer:** Crypto unit and protocol security test.

### Attack 7: Reuse of a consumed OTK

- **Setup:** Complete one OTK allocation and ACT establishment so the Provider public OTK is issued and A's SOTK mapping is consumed.
- **Mutation/adversarial action:** Re-present the same OTK to A, including two simultaneous establishment attempts.
- **Expected rejection point:** IV-E Step 6 local OTK-to-SOTK existence/unused check.
- **Invariant:** One OTK/SOTK pair establishes at most one ACT; the losing attempt cannot derive/store a second authoritative Token state.
- **Paper provenance category:** Threat-model/protocol inference from IV-D.2/IV-E Step 6 plus reproduction engineering hardening for atomic consumption.
- **Test layer:** Protocol security, SQLite restart, and concurrency tests.

### Attack 8: ACT ciphertext tampering

- **Setup:** Issue a valid ACT envelope to B.
- **Mutation/adversarial action:** Flip, truncate, extend, or replace ciphertext/tag bytes.
- **Expected rejection point:** Receiving A's AEAD open before any Step 8 state check.
- **Invariant:** Tampered ciphertext is never parsed or counted; quota and application effects remain unchanged.
- **Paper provenance category:** Reproduction engineering hardening of the paper's abstract `Enc` under C6.
- **Test layer:** Crypto unit, protocol security, and network test.

### Attack 9: ACT encryption-nonce tampering

- **Setup:** Issue a valid ChaCha20-Poly1305 ACT envelope; keep the paper plaintext nonce `N` unchanged inside the ciphertext.
- **Mutation/adversarial action:** Alter the outer AEAD nonce used for encryption.
- **Expected rejection point:** AEAD authentication before ACT plaintext is released.
- **Invariant:** The AEAD nonce is not a sixth ACT plaintext field; tampering cannot consume quota or reveal parsing differences.
- **Paper provenance category:** Reproduction engineering hardening; the paper specifies abstract `Enc`, not an AEAD nonce format.
- **Test layer:** Crypto unit and protocol security test.

### Attack 10: ACT used by the wrong Agent

- **Setup:** Issue a valid ACT to B; authenticate a distinct registered Agent M over mTLS.
- **Mutation/adversarial action:** M presents B's unchanged ACT.
- **Expected rejection point:** A at IV-E Step 8 when the mTLS-authenticated M's registered PAC differs from ACT `PAC_B`.
- **Invariant:** An otherwise valid Token is usable only by its bound initiating Agent; failed transfer does not consume B's quota.
- **Paper provenance category:** Appendix E direct evaluation A5; C1/C2/C3/C4.
- **Test layer:** Protocol security and real mTLS network test.

### Attack 11: ACT use after expiration

- **Setup:** Issue an ACT and advance injected time to exactly `expires_at` and beyond.
- **Mutation/adversarial action:** The correct Agent presents the unchanged Token after expiration.
- **Expected rejection point:** A at IV-E Step 8 expiration check.
- **Invariant:** Validity is the engineering half-open interval `[issued_at, expires_at)`; no post-expiry request succeeds or increments quota.
- **Paper provenance category:** Appendix E direct evaluation A3; C1/C2. Half-open boundary is reproduction engineering.
- **Test layer:** Protocol security test with injected Clock; no `sleep`.

### Attack 12: ACT use beyond Q_max

- **Setup:** Issue an ACT with small `q_max` and complete exactly that many successful uses.
- **Mutation/adversarial action:** The correct Agent submits one additional request.
- **Expected rejection point:** A at IV-E Step 8 atomic `< q_max` check.
- **Invariant:** Successful uses never exceed `q_max`; rejected attempts do not change count or application state.
- **Paper provenance category:** Appendix E direct evaluation A3; C1/C2.
- **Test layer:** Protocol security and persistence integration test.

### Attack 13: Token replay / replay-boundary confusion

- **Setup:** Capture an encrypted TLS record carrying a valid ACT request; separately retain the same ACT ciphertext at legitimate B.
- **Mutation/adversarial action:** Replay the captured TLS record on the same/new connection. As a positive control, B submits the same ACT in a newly formed application request while still below quota and before expiry.
- **Expected rejection point:** TLS rejects/ignores stale record-layer sequence data before application delivery. The positive-control ACT reuse is accepted and counted; it must not be rejected as replay.
- **Invariant:** Four meanings remain distinct: legal same-Agent ACT reuse is allowed; wrong-Agent transfer is Attack 10; expired/exhausted reuse is Attacks 11/12; TLS record replay is a transport failure. Baseline SAGA does not claim semantic request deduplication.
- **Paper provenance category:** Paper assumption (III-C TLS replay protection) and IV-E legal Token reuse; Appendix E A3 covers only expired/exhausted reuse.
- **Test layer:** Real TLS/mTLS network harness plus protocol positive-control test.

### Attack 14: Unauthorized Agent obtains OTK

- **Setup:** A's Contact Policy has no permitting match or an explicit `-1` rule for M.
- **Mutation/adversarial action:** Authenticated M requests contact resolution and an OTK for A.
- **Expected rejection point:** Provider policy decision at IV-D.1/IV-E Step 2 before counter or OTK mutation.
- **Invariant:** Unauthorized requests reveal no receiving contact bundle/OTK and consume neither pair budget nor OTK.
- **Paper provenance category:** Appendix E direct evaluation A6; C1/C2/C3/C4.
- **Test layer:** Protocol security and Provider mTLS API test.

### Attack 15: Contact Policy OTK budget exceeded

- **Setup:** A permits B with a finite budget and enough public OTKs; consume the full pair budget.
- **Mutation/adversarial action:** B requests one more OTK, including concurrent last-budget attempts.
- **Expected rejection point:** Provider atomic positive-counter check at IV-D.2/IV-E Step 2.
- **Invariant:** Successful issuance count never exceeds the selected pair budget; pool and counter update together.
- **Paper provenance category:** Threat-model/protocol inference from IV-D.2 and bounded-contact design; concurrency is reproduction engineering.
- **Test layer:** Protocol security, memory/SQLite parity, and concurrency test.

### Attack 16: Deactivated Agent remains discoverable

- **Setup:** Register A, then have its owning User deactivate it in a committed transaction.
- **Mutation/adversarial action:** B requests A's contact information/OTK after deactivation; also test restart.
- **Expected rejection point:** Provider active-state check before discovery/policy/OTK response.
- **Invariant:** No new contact bundle or OTK is issued for inactive A. Existing ACTs retain the documented natural-expiry/exhaustion semantics and are not silently revoked.
- **Paper provenance category:** Threat-model/protocol inference from IV-D Agent deactivation; existing-ACT behavior is reproduction engineering.
- **Test layer:** Protocol security, SQLite restart, and network API test.

### Attack 17: Malicious Agent shares a Token

- **Setup:** A issues a valid ACT to malicious/compromised B; B sends the ciphertext to distinct Agent M.
- **Mutation/adversarial action:** M authenticates as itself and presents B's ACT.
- **Expected rejection point:** A at IV-E Step 8 PAC binding, exactly as in Attack 10.
- **Invariant:** Token sharing without the bound authenticated Agent identity is rejected; if an unregistered child possesses and presents all of the parent's private credentials, SAGA may observe it as the parent and only the same ACT limits apply.
- **Paper provenance category:** Appendix E direct evaluation A5 and C3/C4 inference; bounded accepted valid use corresponds to A8.
- **Test layer:** Multi-Agent real mTLS security test plus protocol test.

### Attack 18: Man-in-the-middle modifies a request

- **Setup:** Run real Provider/Agent TLS endpoints with a proxy; also prepare a protocol-harness copy of signed/encrypted messages.
- **Mutation/adversarial action:** Modify, reorder, truncate, or inject registration, discovery, Step 5, or ACT-use bytes in transit.
- **Expected rejection point:** TLS integrity/sequence validation before application delivery; if a mutation is injected after TLS termination in the harness, certificate/signature/AEAD/schema verification rejects it at the owning protocol step.
- **Invariant:** No modified unauthenticated message causes a state transition; the test does not claim security after TLS compromise.
- **Paper provenance category:** C6 threat-model inference and III-C TLS assumption; ProVerif scope is reported separately.
- **Test layer:** Real network proxy test and protocol security mutation test.

### Attack 19: Agent metadata replaced after registration

- **Setup:** Persist a valid Agent record and Provider attestation, then prepare a substituted endpoint, certificate, PAC, owner signature, or registry response.
- **Mutation/adversarial action:** Serve the replacement while retaining the original User/Provider signature, and separately attempt an unauthorized persistence write through public ports.
- **Expected rejection point:** B's IV-E Step 3 User-signature verification or A's IV-E Step 6 Provider-signature verification; unauthorized public-port mutation is unavailable/rejected.
- **Invariant:** Registered metadata cannot be changed through supported interfaces without new valid attestations and an authorized lifecycle transition. Direct registry compromise remains outside the paper threat model.
- **Paper provenance category:** Appendix E direct evaluation A4 plus reproduction engineering hardening of adapter interfaces.
- **Test layer:** Protocol security and persistence integration test.

### Attack 20: Concurrent Q_max race bypass

- **Setup:** Issue a persistent ACT with `q_max=1`; synchronize many workers so they present it concurrently.
- **Mutation/adversarial action:** Trigger simultaneous validate-and-increment attempts through memory, SQLite, and real network paths.
- **Expected rejection point:** Receiving Agent's atomic compare/check-and-increment; all losing requests receive `TokenExhausted` or a bounded/retried concurrency outcome that cannot become success.
- **Invariant:** Exactly one request succeeds, persisted `use_count` is exactly one after restart, and no losing request causes application effects.
- **Paper provenance category:** Reproduction engineering hardening implementing IV-E Step 8 quota; ProVerif does not prove atomicity.
- **Test layer:** Deterministic concurrency, SQLite restart, and real mTLS load test.

## Concurrent q_max=1 Experiment

Use a barrier, not timing sleeps, to release 2, 8, 32, and 128 workers against one fresh `q_max=1` ACT. Run each level repeatedly for memory, SQLite, and network adapters. Assert one success, `workers-1` non-successes, receiver count `1`, one application side effect, and the same state after SQLite close/reopen. Inject transaction conflicts and process interruption around the commit point to show that retries cannot duplicate success. Record linearization outcome per worker and latency distribution.

## OTK and Pair-Budget Atomicity Experiments

For a one-item OTK pool and sufficiently large pair budget, concurrently request contact from many initiators/requests and assert that one response contains the OTK and no OTK ID appears twice. For a pair budget of one and a multi-OTK pool, assert exactly one successful allocation and one decrement. For both last-OTK and last-budget races, verify that no partial state pairs “budget spent but OTK available” or “OTK issued without the corresponding committed budget transition.”

Repeat against memory and SQLite, reopen SQLite after each terminal race, and inject rollback/lock-conflict faults. Separately race SOTK claim/ACT establishment and assert one ACT. A public OTK committed as issued is never made reissuable after a later Agent/network failure; the experiment does not invent cross-service rollback.

## Real mTLS Network Experiments

Use an independent test CA to issue Provider and Agent certificates and start real loopback/container TCP services. Agent-Agent and the approved Agent-Provider deployment profile use mTLS; User-Provider uses server-authenticated TLS followed by account/identity authentication and must not require a User client certificate.

Cases include valid chains, unknown CA, expired/not-yet-valid certificate, wrong Agent/Provider identity, certificate/key mismatch, missing client certificate where mTLS is required, timeout, truncated body, connection interruption before/after commit, reconnect, and TLS record replay. The same valid ACT must remain legally reusable by B after a fresh mTLS session while within lifetime/quota. Network success does not demonstrate public routability, NAT traversal, DoS resistance, or TLS implementation correctness beyond the tested configuration.

## ProVerif Models and Queries

Pin the ProVerif version and preserve model source, command, stdout/stderr, exit status, and a query-result manifest under `verification/proverif/`. Maintain two models:

1. **Agent registration model:** registration reachability and injective Agent-Provider authentication correspondences.
2. **Agent communication model:** communication reachability, Token secrecy, and bilateral Agent-Agent authentication correspondences; Provider interactions needed by communication remain authenticated.

Only three security properties are accepted and reported:

1. **SAGA Token secrecy:** attacker cannot derive the modeled ACT/Token secret term.
2. **Agent-Provider authentication:** required injective event correspondences hold for modeled registration/Provider exchanges.
3. **Agent-Agent authentication:** required injective correspondences hold in both communication directions.

Reachability queries must also succeed as executability sanity checks for honest registration, contact, and Token-use events. Reachability is not a fourth security property. A vacuous authentication result fails the gate if its corresponding reachability event cannot occur.

Claims are strictly symbolic and under the Dolev-Yao/cryptographic assumptions. They do not prove Contact Policy semantics, OTK or `q_max` atomicity, availability, DoS resistance, malicious-Provider security, TLS/library correctness, secure deletion, serialization correctness, or absence of implementation vulnerabilities.

## Cryptographic Microbenchmarks

Measure Ed25519 KeyGen, sign, and verify separately; X25519 key generation/exchange; HKDF-SHA256; ChaCha20-Poly1305 ACT encrypt/decrypt; certificate parsing/verification where stable; and scrypt separately from protocol latency. Pre-generate inputs when measuring one operation, prevent setup from leaking into samples, warm up, and retain raw per-sample durations. Parameterize payload/key sizes only where the primitive permits and label failures rather than discarding them.

## Registration and Authorization Benchmarks

Benchmark User registration, Agent registration at multiple OTK-batch sizes, signed OTK append, contact resolution/one-OTK issuance, ACT establishment, and ACT validation/use. Run memory and SQLite separately, and network end-to-end separately from in-process protocol calls. Record transaction mode, database size, policy-rule count, OTK-pool size, certificate path length, concurrency, and whether cryptographic setup is included.

## q_max Trend Experiment

For fixed request count, lifetime, Agents, hardware, storage, and network mode, compare `q_max` values such as 1, 2, 4, 8, 16, 32, and 64. Include reauthorization (Provider lookup, OTK, DH/HKDF, ACT creation) whenever the quota is exhausted, then compute total and amortized authorization cost per successful application request.

Accepted directional trend: `q_max` 增大时，每请求授权开销下降. Report raw distributions and confidence/repeatability; do not force strict monotonicity at every adjacent point or compare absolute paper timings as a cross-hardware gate.

## Token Lifetime Trend Experiment

Use a fixed simulated time window and deterministic request-arrival trace. Hold `q_max`, Agents, policy, storage, and network constant while varying lifetime. Expire naturally, reacquire a fresh OTK/ACT, and count reauthorizations; do not use wall-clock sleeps.

Accepted directional trend: lifetime 增大时，固定时间窗口内重新授权次数下降. Also report amortized latency and the fraction limited by quota rather than time so the interpretation is explicit.

## 1/10/100 Receiving-Agent Experiment

Run identical workloads against 1/10/100 receiving agents with controlled per-Agent policy, OTK pool, Token parameters, and request rate. Record aggregate/per-Agent throughput, latency, Provider lookup/issuance cost, error rate, and resource consumption. Randomize or rotate target order to avoid warm-cache bias.

Accepted directional trend: receiving Agent 数量和并发度变化时，吞吐与开销趋势可解释且可重复. There is no mandated improvement direction; repeated runs must show a stable, explainable relationship tied to measured CPU, storage, network, and contention.

## Concurrent Throughput Experiment

Sweep client concurrency (for example 1, 2, 4, 8, 16, 32, 64) for authorization-heavy and ACT-reuse-heavy mixes. Measure completed successful requests/second, offered load, rejection/error class, latency percentiles, CPU/memory, SQLite lock retries, and connection/TLS overhead. Keep a closed-loop and, if used, an open-loop workload as separate scenarios. Saturation and failure modes are results, not discarded outliers.

## Result Schemas

CSV uses one raw-sample row per operation attempt and one separately typed summary row (or separate `benchmark-samples.csv` and `benchmark-summaries.csv`). Required raw fields are:

```text
schema_version, run_id, timestamp_utc, git_commit, dirty,
scenario, operation, parameters, sample_index, duration_ns, success,
error_class, environment_fingerprint, adapter, concurrency,
warmup_count, sample_count
```

`parameters` is canonical JSON. `environment_fingerprint` is a stable SHA-256 identifier whose expanded object is included in JSON metadata. Required summary fields are:

```text
schema_version, run_id, scenario, operation, parameters,
environment_fingerprint, mean, median, P95, P99,
standard_deviation, sample_count, success_count, failure_count,
throughput_per_second
```

Thus the schema explicitly contains mean, median, P95, P99, standard deviation, and sample count. Durations use integer nanoseconds in raw rows and one documented unit in summaries.

JSON is an object with `schema_version`, `run`, `environment`, `configuration`, `samples`, `summaries`, and `comparison`. Each `samples[]` item contains `operation`, structured `parameters`, `sample_index`, `duration_ns`, `success`, `error_class`, and `environment_fingerprint`. Each `summaries[]` item contains the full statistical summary fields above. `comparison` records paper figure/table/section, comparable/not-comparable status, paper value/unit if extractable, reproduction value/unit, relative difference where meaningful, trend result, and explanation.

## Statistical Summaries

Warmups are excluded by an explicit flag/count, never silently. For every operation/parameter group, retain all formal attempts and separately summarize successes and failure classes. Report arithmetic mean, median, P95, P99, sample standard deviation, sample count, and confidence intervals or repeated-run ranges where meaningful. Define percentile interpolation in the schema/version notes.

Use enough samples to stabilize percentiles and publish the chosen stopping/sample rule before looking at results. Outliers remain in raw data; any secondary trimmed view is labeled and cannot replace the primary summary. Trend experiments run multiple independent repetitions with controlled order/randomization and report both within-run and across-run variability.

## Comparison with Paper Results

Map each reproduced metric to the exact paper section/figure/table and state whether inputs, scope, hardware, storage, cryptographic work, and network path are comparable. Compare direction first and absolute values only when units and operations match. Explain deviations using captured CPU, network, storage, Python/library, adapter, scale, and protocol-coverage differences.

Paper hardware numbers are never cross-environment hard thresholds. Regression gates use a documented, loose same-environment historical relative threshold with enough samples and no threshold manipulation. Appendix E A1–A8 attack observations, the three ProVerif properties, reachability sanity, and reproduction engineering tests are reported in separate evidence categories.

## Exit Criteria

The experiment phase passes only when:

- all unit/protocol mappings and all 20 attack headings execute with provenance and expected invariant assertions;
- legal ACT reuse, wrong-Agent transfer, expired/exhausted reuse, and TLS record replay have separate outcomes;
- memory and SQLite atomicity tests pass, including exactly one success for concurrent `q_max=1`, last OTK, last pair budget, and SOTK claim;
- real X.509 network cases pass, Agent mTLS is enforced, and User-Provider remains server-authenticated TLS plus User authentication rather than User mTLS;
- ProVerif reports exactly the three scoped security properties and successful non-vacuity/reachability sanity checks, with no expanded claims;
- raw CSV and JSON validate against the documented schemas and contain complete environment metadata and all required statistics;
- the three accepted directional trends are reproducible or a failed trend is transparently reported and investigated; results are never altered to obtain acceptance;
- every result is traceable to Git commit, configuration, source category, raw samples, and an explanation of material paper deviation.
