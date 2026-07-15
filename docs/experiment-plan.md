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
- **Expected rejection point:** Provider protocol's positive-counter decision at IV-D.2/IV-E Step 2, before submitting the structural CAS.
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
- **Expected rejection point:** Receiving protocol's `< q_max` decision followed by an expected-revision/use-count CAS; all losing requests reread/revalidate and receive `TokenExhausted` or a bounded conflict outcome that cannot become success.
- **Invariant:** In a no-crash race, exactly one CAS winner enters the handler, persisted `use_count` is one, one handler side effect occurs, and losing requests cause none. Under crash injection, persisted `use_count <= 1`, losers cause no side effect, and state is recoverable; no exactly-once claim is made for the winner's external side effect.
- **Paper provenance category:** Reproduction engineering hardening implementing IV-E Step 8 quota; ProVerif does not prove atomicity.
- **Test layer:** Deterministic concurrency, SQLite restart, and real mTLS load test.

## Concurrent q_max=1 Experiment

Use a barrier, not timing sleeps, to release 2, 8, 32, and 128 workers against one fresh `q_max=1` ACT. In ordinary no-crash runs for memory, SQLite, and network adapters, assert one successful CAS/admission, `workers-1` non-successes, receiver count `1`, exactly one handler entry and one test handler side effect, and no loser side effect.

Run crash injection as a separate experiment before the count commit, immediately after commit/before handler entry, and during the external test handler. After restart assert only persisted `use_count <= 1`, no losing-request side effect, rejection of any second admission when the count is one, and a readable/recoverable state. The winner's external effect may be absent, partial, or complete depending on the crash point. Count commit and external side effects are not exactly-once without an outbox/idempotency protocol, and this phase adds neither. Record each worker's CAS/admission outcome, crash point, persisted count, handler-entry marker when observable, side-effect observation, and latency.

## OTK and Pair-Budget Atomicity Experiments

For a one-item OTK pool and sufficiently large pair budget, concurrently request contact from many initiators/requests and assert that one response contains the OTK and no OTK ID appears twice. For a pair budget of one and a multi-OTK pool, assert exactly one successful allocation and one decrement. For both last-OTK and last-budget races, verify that no partial state pairs “budget spent but OTK available” or “OTK issued without the corresponding committed budget transition.”

Repeat against memory and SQLite, reopen SQLite after each terminal race, and inject rollback/lock-conflict faults. Separately race SOTK claim/ACT establishment and assert one ACT. A public OTK committed as issued is never made reissuable after a later Agent/network failure; the experiment does not invent cross-service rollback.

Also force stale contact snapshots by changing Agent active revision, policy version, counter revision/value, and OTK-pool revision between protocol decision and CAS. Assert that the store returns `Conflict` without mutation, never evaluates a policy rule, and never returns allow/deny. The protocol must reread the complete snapshot and rerun active-state, most-specific policy, budget/cap, and OTK selection before attempting a new CAS; a stale allow decision cannot survive a policy deny/deactivation race.

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

This gate is preregistered as follows:

- **Parameters:** `q_max = [1, 2, 4, 8, 16, 32, 64]`; one initiating/one receiving Agent; lifetime `3_600_000 ms`; 4,096 successful requests per repetition; 1,024-byte application payload; one exact-match permitting policy with sufficient pair budget/OTKs; memory and SQLite are separate scenarios, with the network scenario reported separately.
- **Warmup and samples:** three recorded warmup repetitions per scenario/point (excluded from primary summaries), then ten independent measured repetitions. For measured repetition `r=0..9`, point order is the base list cyclically left-rotated by `(3*r) mod 7`; seeds are `41001..41010`. There is no adaptive stopping.
- **Aggregation unit:** for each repetition, total authorization-path duration (including every required reauthorization, Provider lookup, OTK, DH/HKDF, ACT creation, and validation) divided by 4,096 successes. The point estimate is the median of the ten repetition means.
- **Comparison and uncertainty:** compute the endpoint relative change `delta = median(q64)/median(q1)-1`, the Theil-Sen slope of repetition mean versus `log2(q_max)`, and paired bootstrap 95% percentile confidence intervals using 10,000 resamples of repetition IDs with seed `41999`.
- **Pass rule:** `delta <= -0.10`, the upper bound of the bootstrap CI for `delta` is `< 0`, and the upper bound of the slope CI is `< 0`. Any missing point, excess failure preventing 4,096 successes, or failed condition fails the gate.

Accepted directional trend: `q_max` 增大时，每请求授权开销下降. The 10% endpoint tolerance avoids treating measurement noise as reproduction while remaining a same-environment relative rule. Absolute paper timings are comparison data, never a cross-hardware threshold.

## Token Lifetime Trend Experiment

This gate is preregistered as follows:

- **Parameters:** lifetime in seconds `[1, 5, 30, 60, 300]`; a 600-second injected-clock window; mean request rate 10/s; `q_max=100_000` so quota never triggers; one initiating/receiving pair, one exact allow rule, sufficient OTK/budget, and a 1,024-byte payload in each fixed adapter/network scenario. For trace seed `s` and event index `i`, derive `u` from the first 53 bits of `SHA-256("SAGA-LIFETIME/v1" || uint64be(s) || uint64be(i))` mapped strictly into `(0,1)`, then use exponential inter-arrival `-ln(1-u)/10` seconds until the next event would exceed 600 seconds.
- **Warmup and samples:** three recorded warmup traces with seeds `50998..51000`, then ten independent measured arrival traces generated from fixed seeds `51001..51010`; each seed's exact timestamp trace is saved and replayed for every lifetime. Lifetime order for measured repetition `r` is the base list cyclically left-rotated by `(2*r) mod 5`. No wall-clock sleeps or adaptive stopping are allowed.
- **Aggregation unit:** per trace/lifetime, count initial authorization plus every expiration-driven reauthorization in the 600-second window. Also summarize authorization duration per successful request, but reauthorization count is the gate metric.
- **Comparison and uncertainty:** require non-increasing counts at every adjacent lifetime for every paired trace; compute `ratio = median(count_300s)/median(count_1s)` and a paired 10,000-resample bootstrap 95% percentile CI using seed `51999`.
- **Pass rule:** all paired adjacent comparisons are non-increasing, `ratio <= 0.20`, and the upper CI bound for `ratio` is `< 0.50`. A quota-driven renewal, missing trace, or failed condition fails the gate.

Accepted directional trend: lifetime 增大时，固定时间窗口内重新授权次数下降. The fixed 80% endpoint reduction is a relative same-environment/event-trace criterion; it does not impose paper hardware timing.

## 1/10/100 Receiving-Agent Experiment

This scale/repeatability gate is preregistered as follows:

- **Parameters:** receiving-Agent counts `[1, 10, 100]` crossed with closed-loop concurrency `[1, 8, 32]`; identical single exact-match policy and prefilled OTK/pair budget per Agent, `q_max=64`, lifetime 10 minutes, 1,024-byte request payload, round-robin target selection, and constant total client concurrency (not per-Agent concurrency).
- **Warmup and samples:** two recorded 15-second warmup intervals per cell, then eight independent 30-second measured repetitions using target-order seeds `61001..61008`. Number the nine `(agent_count, concurrency)` cells in the written Cartesian-product order; measured repetition `r=0..7` visits cells in the base order cyclically left-rotated by `(4*r) mod 9`. No adaptive extension is allowed.
- **Aggregation unit:** per repetition/cell, aggregate successful requests per second and request-weighted P95 latency; also record per-Agent throughput, failure rate, CPU, memory, SQLite lock retries, and TLS connection counts.
- **Direction classification:** for each concurrency, fit the Theil-Sen slope of `log(throughput)` versus `log(agent_count)`. Use a 10,000-resample paired bootstrap by repetition ID (seed `61999`) and a preregistered practical-equivalence band `[-0.05, +0.05]`: classify **increase** if the CI is wholly above `+0.05`, **decrease** if wholly below `-0.05`, **stable** if the CI is wholly inside the band, otherwise **inconclusive**.
- **Repeatability pass rule:** every cell has throughput coefficient of variation `<= 0.15`; its bootstrap 95% CI half-width divided by median throughput is `<= 0.15`; and every concurrency receives a non-inconclusive direction classification. A metric/telemetry gap or any failed condition fails the gate. The report must explain the classified direction using the measured CPU, lock, TLS, latency, and failure telemetry without changing the classification.

Accepted directional trend: receiving Agent 数量和并发度变化时，吞吐与开销趋势可解释且可重复. No increase/decrease is mandated, but “repeatable and explainable” is now a calculable gate rather than narrative discretion; no absolute throughput number is compared across hardware.

## Concurrent Throughput Experiment

Sweep closed-loop client concurrency `[1, 2, 4, 8, 16, 32, 64]` for two fixed 1,024-byte mixes: authorization-heavy (`q_max=1`) and ACT-reuse-heavy (`q_max=64`), both with 10-minute lifetime and sufficient OTK/pair budget. Use two recorded 15-second warmups and eight fixed 30-second measured repetitions per point with seeds `71001..71008`; measured repetition `r=0..7` visits the base concurrency list cyclically left-rotated by `(3*r) mod 7`. There is no adaptive stopping. The aggregation unit is one repetition/point. Measure successful requests/second, offered attempts, rejection/error class, median/P95/P99 latency, CPU/memory, SQLite lock retries, and connection/TLS overhead. Open-loop workloads, if added, are separate scenarios and cannot replace this gate. Saturation and failures remain recorded samples.

For each mix and adjacent concurrency pair, compute paired repetition throughput change `delta=median(high)/median(low)-1` and a 10,000-resample paired bootstrap 95% percentile CI using seed `71999`. Classify increase if the CI is wholly above `+0.05`, decrease if wholly below `-0.05`, stable if wholly inside `[-0.05,+0.05]`, and otherwise inconclusive; any inconclusive point is a gate failure. This experiment characterizes saturation and is not an additional paper-direction claim. It uses only relative same-environment comparisons.

## Result Schemas

Schema version `saga-benchmark/v1` produces three distinct CSV files, never mixed row types, plus one equivalent versioned JSON document.

`benchmark-samples.csv` contains every warmup and measured attempt. All columns are required to exist:

| Field | Type/unit | Required/nullable | Rule |
|---|---|---|---|
| `schema_version` | string | required, non-null | Enum: `saga-benchmark/v1` |
| `run_id` | UUID string | required, non-null | One experiment invocation |
| `timestamp_utc` | RFC3339 UTC string | required, non-null | Sample completion time |
| `git_commit` | 40-char lowercase hex string | required, non-null | Tested revision |
| `dirty` | boolean | required, non-null | `true` is retained, not hidden |
| `scenario` | string | required, non-null | Registered scenario name |
| `operation` | string | required, non-null | Registered operation enum/name |
| `parameters` | canonical JSON object string | required, non-null | Typed scenario parameters and units |
| `repetition_index` | integer >= 0 | required, non-null | Independent measured/warmup repetition |
| `sample_index` | integer >= 0 | required, non-null | Unique within repetition/operation |
| `phase` | string enum | required, non-null | `warmup` or `measured` |
| `duration_ns` | integer >= 0 | required, non-null | Attempt duration, including failed attempts |
| `success` | boolean | required, non-null | Outcome of this attempt |
| `error_class` | string enum | required, nullable | Null iff success; otherwise stable domain/transport error enum |
| `environment_fingerprint` | 64-char lowercase SHA-256 hex | required, non-null | References JSON `environments` entry |
| `adapter` | string enum | required, non-null | `memory`, `sqlite`, or `network` |
| `concurrency` | integer >= 1 | required, non-null | Active closed-loop clients/workers |

Every offered attempt is recorded, including warmups and failures; warmups are selected by `phase`, not deleted. A failed sample still has `duration_ns`, `success=false`, and non-null `error_class`.

`benchmark-summary.csv` contains exactly one row per `(run_id, scenario, operation, canonical parameters, environment_fingerprint, adapter, concurrency)` measured group. Duration statistics use successful measured attempts only; failed-attempt durations remain in `benchmark-samples.csv`, while counts preserve the full offered workload:

| Field | Type/unit | Required/nullable | Rule |
|---|---|---|---|
| `schema_version`, `run_id`, `scenario`, `operation`, `parameters`, `environment_fingerprint`, `adapter`, `concurrency` | as above | required, non-null | Exact grouping key |
| `mean_ns`, `median_ns`, `p95_ns`, `p99_ns`, `standard_deviation_ns` | number, ns | required, nullable | Successful measured-attempt durations; all null iff `success_count=0`, otherwise finite and >= 0 |
| `sample_count`, `success_count`, `failure_count` | integer >= 0 | required, non-null | `sample_count = success_count + failure_count =` all measured attempts in the group |
| `throughput_per_second` | number >= 0 | required, nullable | Non-null for throughput scenarios; null otherwise |

`benchmark-trend-gates.csv` contains exactly one row per preregistered comparison or gate and is structurally isomorphic to JSON `trend_gates[]`. All columns are required to exist:

| Field | Type/unit | Required/nullable | Rule |
|---|---|---|---|
| `schema_version` | string enum | required, non-null | Exactly `saga-benchmark/v1` |
| `run_id` | UUID string | required, non-null | Must match root run/sample/summary run |
| `environment_fingerprint` | 64-char lowercase SHA-256 hex | required, non-null | Must resolve in JSON `environments` |
| `adapter` | string enum | required, non-null | `memory`, `sqlite`, or `network` |
| `gate_id` | string | required, non-null | Unique in the run; stable registered identifier |
| `experiment` | string enum | required, non-null | `q_max`, `token_lifetime`, `agent_scale`, or `concurrent_throughput` |
| `metric` | string enum | required, non-null | Registered metric: `authorization_ns_per_request`, `reauthorization_count`, `throughput_per_second`, `throughput_cv`, or `throughput_ci_relative_half_width` |
| `unit` | string enum | required, non-null | `fraction`, `ratio`, `log_slope`, `count`, `requests_per_second`, or `dimensionless` |
| `comparison_kind` | string enum | required, non-null | `endpoint_delta`, `endpoint_ratio`, `slope`, `adjacent_ratio`, `adjacent_delta`, `coefficient_of_variation`, or `ci_relative_half_width` |
| `lhs_parameters` | canonical JSON object string | required, non-null | High/target endpoint or the single cell/series definition |
| `rhs_parameters` | canonical JSON object string | required, nullable | Required for endpoint/adjacent comparisons; null for slope and single-cell dispersion/precision gates |
| `estimate` | finite number | required, nullable | Non-null when computable; null only for missing/invalid data with `gate_pass=false` and non-null `notes` |
| `ci_lower`, `ci_upper` | finite number | required, nullable | Non-null and ordered when `bootstrap_resamples > 0`; both null when resamples are 0; computation failure also requires false gate and non-null notes |
| `tolerance` | finite number | required, non-null | Exact preregistered threshold in the metric's declared unit |
| `classification` | string enum | required, nullable | `increase`, `decrease`, `stable`, `inconclusive`; non-null for Agent-scale slopes and concurrency adjacent deltas, null otherwise |
| `pass_rule` | string | required, non-null | Exact registered Boolean expression over estimate/CI/tolerance/classification |
| `gate_pass` | boolean | required, non-null | Must equal deterministic reevaluation of `pass_rule`; missing/inconclusive data is false |
| `repetitions` | integer > 0 | required, non-null | Must equal preregistered completed-repetition requirement |
| `bootstrap_resamples` | integer >= 0 | required, non-null | `10000` where a CI is required; `0` only for the direct CV limit row |
| `bootstrap_seed` | integer >= 0 | required, nullable | Non-null iff `bootstrap_resamples > 0` and equal to registered seed |
| `notes` | string | required, nullable | Required when computation/validation fails; optional explanatory text otherwise |

Required trend rows are deterministic. For each adapter/scenario, q_max emits separate `qmax.endpoint_delta` and `qmax.slope` rows: the former stores q64 versus q1 `endpoint_delta`, and the latter stores the whole-series `slope` with null `rhs_parameters`. Token lifetime emits one `adjacent_ratio` row for each of 1→5, 5→30, 30→60, and 60→300 seconds plus one 1→300 `endpoint_ratio` row. Agent scale emits one slope/classification row for each concurrency 1/8/32 and, for every 3×3 Agent/concurrency cell, one `coefficient_of_variation` row and one `ci_relative_half_width` row. Concurrent throughput emits one independent `adjacent_delta` row for every adjacent concurrency pair in each of the two workload mixes (12 rows per adapter/scenario). No aggregate row may stand in for any required comparison.

Validation parses both parameter fields as canonical JSON objects, checks `gate_id` uniqueness and the complete expected gate-ID set, checks metric/unit/comparison compatibility, validates repetition/resample/seed values against preregistration, recomputes estimates/type-7 bootstrap bounds/classification/pass rule from summary plus raw repetition data, and rejects extra, missing, duplicated, non-finite, wrong-unit, or post-hoc-threshold rows. `lhs_parameters` is always the higher/target setting and `rhs_parameters` the lower/reference setting, so delta/ratio orientation is fixed.

JSON root is an object with required, non-null `schema_version` (string), `run` (object), `environments` (object map), `configuration` (object), `samples` (array), `summaries` (array), `trend_gates` (array), and `comparison` (array). `schema_version` is exactly `saga-benchmark/v1`. `run` requires typed `run_id` (UUID string), `timestamp_utc` (RFC3339 UTC string), `git_commit` (40-char hex string), and `dirty` (boolean). `environments` maps each 64-char fingerprint to a non-null object containing CPU string/count, memory bytes integer, OS/kernel/architecture/Python strings, dependency version map, TLS backend/version strings, and SQLite version/journal-mode strings. `configuration` requires the structured preregistered parameters, seed list, order formula, warmup count/duration, repetition count/duration, resample count/seed, tolerances, and pass rules. `samples[]` and `summaries[]` use the same required types/nullability as their CSV tables with `parameters` as an object rather than a string, and `summaries[]` has exactly one object per measured group with no trend/gate fields. `trend_gates[]` has exactly the same fields, enum values, units, conditional nullability, one-gate-per-object cardinality, and validation rules as `benchmark-trend-gates.csv`; only `lhs_parameters`/`rhs_parameters` are JSON objects instead of CSV JSON strings. CSV rows and JSON objects must match field-for-field after canonicalization. `comparison[]` requires paper location string, comparability enum (`comparable`, `partially_comparable`, `not_comparable`), nullable numeric paper/reproduction values with nullable unit strings, nullable relative difference, trend result enum, and explanation string. Unknown schema versions fail validation; additions require a new version.

## Statistical Summaries

All warmup/sample counts, repetition counts, seeds, order, resamples, thresholds, and failure rules are fixed above; there is no data-dependent stopping. Warmup attempts remain in `benchmark-samples.csv` with `phase=warmup` and are excluded from primary summaries. Every measured success and failure remains in the raw file; each measured group has exactly one summary row, successful durations supply its latency statistics, and success/failure counts expose the full offered workload. Every comparison and gate exists only in `benchmark-trend-gates.csv`/JSON `trend_gates[]`, never as an extra summary row.

Arithmetic mean is `sum(x)/n`; sample standard deviation uses denominator `n-1` and is `0` for `n=1`. Median, P95, and P99 use Hyndman-Fan type 7 linear interpolation: for sorted zero-based values `x[0..n-1]`, `h=(n-1)p`, `j=floor(h)`, `g=h-j`, and quantile `x[j] + g*(x[min(j+1,n-1)]-x[j])`. Empty populations have nullable statistics and `sample_count=0`. Primary summaries are untrimmed. Outliers are never removed; any labeled sensitivity analysis is secondary.

All specified confidence intervals are paired percentile bootstrap intervals over independent repetition IDs, 10,000 resamples, using the fixed per-experiment seed and the 2.5th/97.5th type-7 percentiles. Resampling never treats requests within one repetition as independent. A missing/invalid sample, schema violation, insufficient completed repetitions, inconclusive required classification, or unmet preregistered threshold is a gate failure, not grounds to collect extra repetitions after inspecting results.

## Comparison with Paper Results

Map each reproduced metric to the exact paper section/figure/table and state whether inputs, scope, hardware, storage, cryptographic work, and network path are comparable. Compare direction first and absolute values only when units and operations match. Explain deviations using captured CPU, network, storage, Python/library, adapter, scale, and protocol-coverage differences.

Paper hardware numbers are never cross-environment hard thresholds. Regression gates use a documented, loose same-environment historical relative threshold with enough samples and no threshold manipulation. Appendix E A1–A8 attack observations, the three ProVerif properties, reachability sanity, and reproduction engineering tests are reported in separate evidence categories.

## Exit Criteria

The experiment phase passes only when:

- all unit/protocol mappings and all 20 attack headings execute with provenance and expected invariant assertions;
- legal ACT reuse, wrong-Agent transfer, expired/exhausted reuse, and TLS record replay have separate outcomes;
- memory and SQLite atomicity tests pass, including protocol-owned authorization with versioned snapshot/CAS retry, exactly one no-crash success/handler side effect for concurrent `q_max=1`, and one winner for last OTK, last pair budget, and SOTK claim; crash injection must show persisted `use_count <= 1`, no loser effect, and recoverable state without claiming exactly-once winner effects;
- real X.509 network cases pass, Agent mTLS is enforced, and User-Provider remains server-authenticated TLS plus User authentication rather than User mTLS;
- ProVerif reports exactly the three scoped security properties and successful non-vacuity/reachability sanity checks, with no expanded claims;
- `benchmark-samples.csv`, `benchmark-summary.csv`, `benchmark-trend-gates.csv`, and JSON validate against `saga-benchmark/v1`; samples preserve every success/failure/warmup attempt, summaries contain exactly one row per measured group with no trend/gate rows, and CSV trend gates are field-for-field isomorphic to JSON `trend_gates[]` with every required comparison present;
- each preregistered trend runs exactly its fixed parameters, warmups, repetitions, seeds, aggregation, bootstrap, tolerance, and pass rule; any failed/inconclusive condition fails the gate and is reported without post hoc sample extension or threshold changes;
- every result is traceable to Git commit, configuration, source category, raw samples, and an explanation of material paper deviation.
