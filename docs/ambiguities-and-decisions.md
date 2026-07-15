# SAGA Ambiguities and Decisions

The paper protocol is the only normative source. Decisions below follow this precedence: explicit protocol formulas and steps, protocol figures/notation, implementation and evaluation text, then approved reproduction decisions. Each record resolves one implementation choice without enlarging the paper's formal claims.

## 1. Provider signature tuple mismatch between IV-C Step 7 and Figure 8

- **Evidence:** IV-C Step 7 defines `sigma_A^Prov = Sign_SK_Prov(<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>)`. Appendix Figure 8 displays a tuple beginning with `Cert_U` and omits/replaces the main text's `aid_A, Cert_A` placement. IV-E Step 6 verifies the Provider attestation over the initiating Agent's registered information.
- **Ambiguity:** The main-text formula and diagram cannot both define the same signed byte tuple.
- **Decision:** The reproduction signs and verifies exactly the IV-C Step 7 five-field tuple `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>`. Figure 8 remains documented as a source discrepancy and never overrides the formula.
- **Classification:** Paper internal inconsistency resolved by source precedence.
- **Consequence:** All serialization vectors, registration tests, tamper tests, and IV-E Step 6 verification use the main-text tuple; artifacts must not claim that Figure 8 agrees.

## 2. Generic signature requirement versus Ed25519 reproduction choice

- **Evidence:** IV-A requires an EUF-CMA-secure signature scheme and gives ECDSA and Ed25519 as examples; it does not choose one protocol-wide. The approved design selects Ed25519 for User and Provider signatures.
- **Ambiguity:** Interoperable bytes and keys require one concrete algorithm even though the protocol is algorithm-generic.
- **Decision:** Use Ed25519 for User and Provider signatures in the baseline reproduction, through a mature cryptographic library. Do not describe Ed25519 as a mandatory SAGA protocol field or algorithm.
- **Classification:** Reproduction engineering choice within a paper-permitted primitive class.
- **Consequence:** Test vectors and key formats are Ed25519-specific; later algorithm agility requires an outer-version/suite change and new vectors, not reinterpretation of existing signatures.

## 3. Abstract symmetric `Enc` versus ChaCha20-Poly1305

- **Evidence:** IV-E Step 7 defines `token = Enc_SDHK(<N, T_issued, T_expire, Q_max, PAC_B>)` without specifying encryption mode, authentication, nonce format, or wire envelope. The approved design selects ChaCha20-Poly1305.
- **Ambiguity:** Confidentiality-only abstract encryption is insufficient to determine implementation integrity and ciphertext layout.
- **Decision:** Instantiate `Enc` with ChaCha20-Poly1305, using a fresh unique AEAD nonce for every ACT encryption. Keep the AEAD nonce outside the paper's five-field ACT plaintext.
- **Classification:** Reproduction cryptographic engineering choice.
- **Consequence:** Ciphertext, nonce, and authentication-tag tampering fail closed. The AEAD nonce is not a sixth ACT field and the paper is not credited with selecting ChaCha20-Poly1305.

## 4. Unspecified canonical serialization

- **Evidence:** IV-C Steps 2, 6, and 7 and IV-E Step 7 specify ordered logical tuples but no byte serialization. The approved design requires UTF-8 deterministic JSON, fixed field order, integer security fields, strict unpadded Base64URL for binary values, and an outer protocol version.
- **Ambiguity:** Two correct logical implementations could serialize the same tuple differently, breaking signatures or decryption and permitting type confusion.
- **Decision:** Use deterministic UTF-8 JSON with schema-fixed field order, reject unknown/duplicate fields and floating-point security fields, encode binary values as strict unpadded Base64URL, and place `version` only in the outer message envelope.
- **Classification:** Reproduction interoperability and validation decision.
- **Consequence:** Signed/encrypted inputs have stable test vectors. `version`, encoding metadata, and parser controls do not enter the five-field ACT plaintext or any paper-defined tuple unless that tuple explicitly includes them.

## 5. Unspecified HKDF salt/info and AEAD AAD

- **Evidence:** IV-A names HKDF-SHA256 and IV-E Step 6 applies a KDF to DH output, but no salt/info is given. IV-E Step 7 gives abstract `Enc` and no AAD. The approved design fixes `salt=None`, `info=b"SAGA-ACT-DERIVE/v1"`, and `aad=b"SAGA-ACT/v1"`.
- **Ambiguity:** Domain separation and authenticated context are necessary implementation parameters but are absent from the protocol text.
- **Decision:** Derive `SDHK` with HKDF-SHA256 using `salt=None` and `info=b"SAGA-ACT-DERIVE/v1"`; encrypt/decrypt ACTs with `aad=b"SAGA-ACT/v1"` exactly.
- **Classification:** Reproduction cryptographic domain-separation decision.
- **Consequence:** Any parameter or AAD mismatch fails derivation/decryption tests. These constants are engineering parameters, not additional formal inputs proved in Appendix D.

## 6. Task-scoped prose versus ACT with no task field

- **Evidence:** IV-E describes the ACT as scoped to a specific task, while Step 7 defines exactly `<N, T_issued, T_expire, Q_max, PAC_B>` and Step 8 contains no task identifier or context hash.
- **Ambiguity:** The prose suggests task binding that the cryptographic tuple cannot enforce.
- **Decision:** Preserve exactly the five paper fields and do not add `task_id`, context hash, operation, tool, parameter, or resource constraints to the baseline ACT. Treat task completion only as the local discard trigger in IV-E Step 8.
- **Classification:** Paper limitation resolved by protocol-formula precedence.
- **Consequence:** The base reproduction makes no cryptographic task-binding claim. A task/tool/resource capability must be a separate future token family and branch.

## 7. Legal ACT reuse versus application-level duplicate requests

- **Evidence:** IV-E Token reuse explicitly permits the same ACT until expiration or `Q_max`, including after the existing TLS session resets and the Agents establish a new TLS session. Step 8 requires `PAC_B` binding, expiration, and quota checks. The ACT has no request ID or idempotency key. Appendix E A3 tests expired/exhausted use, and A5 tests wrong-Agent transfer.
- **Ambiguity:** The word "replay" can mean TLS-record replay, prohibited Token transfer/invalid reuse, or a semantically duplicate application request by the legitimate holder.
- **Decision:** Treat same-Agent ACT reuse within lifetime and quota, including across TLS reconnection, as legal. Rely on TLS for record-layer replay protection; reject wrong-Agent, expired, and exhausted ACT use; do not claim or implement baseline application-semantic deduplication.
- **Classification:** Paper behavior plus an explicit claim boundary.
- **Consequence:** Tests separate four cases and may not label legal reuse as an attack. Request IDs/idempotency are future application features, not SAGA ACT fields.

## 8. `q_max` persistent state and concurrent linearization

- **Evidence:** IV-E Steps 7-8 require a maximum use count and rejection after the limit, but do not specify storage, crash recovery, or concurrency. The approved design places authoritative ACT/use state at the receiving Agent.
- **Ambiguity:** Concurrent presentations can all observe a stale count and exceed `q_max` unless the transition is linearizable and persistent.
- **Decision:** Persist receiving-Agent ACT state and execute one atomic `< q_max` check-and-increment for every successful request. Failed validation does not consume quota; `q_max=1` permits exactly one concurrent success.
- **Classification:** Reproduction state-safety engineering decision implementing paper quota semantics.
- **Consequence:** Memory and SQLite adapters must expose identical atomic behavior and crash tests; ProVerif results must not be cited as proof of counter correctness.

## 9. Contact Policy specificity ties

- **Evidence:** IV-D.1 says the highest-specificity matching rule wins and gives examples, but does not fully order wildcard classes or define equal-specificity overlap. The approved design orders exact Agent ID, User-domain wildcard, Agent-type wildcard, then global wildcard.
- **Ambiguity:** Equal-specificity overlap could make authorization depend on input/storage iteration order.
- **Decision:** Apply the fixed order exact > User-domain wildcard > Agent-type wildcard > global wildcard, and reject any policy at registration/update time if two overlapping rules have equal specificity.
- **Classification:** Reproduction deterministic policy decision.
- **Consequence:** Runtime evaluation has one winner or a stable denial/no-match; policy order cannot change authorization. This decision is engineering-tested, not covered by ProVerif.

## 10. Policy update effect on initialized pair counters

- **Evidence:** IV-D permits policy updates and OTK replenishment, while IV-D.2 initializes `Counter_OTK[aid_A][aid_B]` on first contact. The paper gives no migration rule for an already initialized counter.
- **Ambiguity:** A later higher/lower/deny budget could reset, preserve, or cap the remaining quota.
- **Decision:** Apply the new policy to the next OTK request and set effective remaining quota to `min(old_remaining, new_budget)` for a permitting rule. A deny/no-match rejects immediately. Higher budgets and OTK replenishment never restore consumed quota.
- **Classification:** Reproduction persistent-state engineering decision.
- **Consequence:** Policy reads, active-state checks, counter capping/check/decrement, and OTK allocation occur in one transaction; update tests cover lower, higher, deny, and concurrent cases.

## 11. Existing ACT after policy update or Agent deactivation

- **Evidence:** IV-D updates policies and deactivates Agents for future discovery/contact, while IV-E Token reuse permits an already issued valid ACT until expiration or quota exhaustion. The paper defines no ACT revocation message or list.
- **Ambiguity:** It is unspecified whether management actions retroactively invalidate issued ACTs.
- **Decision:** Policy update or deactivation immediately blocks new discovery/OTK issuance, but existing ACTs remain usable until natural expiration, quota exhaustion, or explicit task-completion discard. Do not implement an active revocation list in the baseline.
- **Classification:** Reproduction lifecycle decision filling a paper omission.
- **Consequence:** Tests distinguish future-contact denial from existing-ACT validity. Active revocation is an explicitly separate extension and cannot be claimed as paper behavior.

## 12. OTK public allocation versus receiving-side SOTK destruction timing

- **Evidence:** IV-D.2/IV-E Step 2 allocate one public OTK and decrement the pair counter at the Provider. IV-E Step 6 and Appendix Figure 9 delete the receiving Agent's `OTK_A^i -> SOTK_A^i` mapping after DH/KDF and before Token generation.
- **Ambiguity:** Provider public-key consumption and receiving-side secret destruction occur in different components and phases; retries/concurrency could otherwise reissue or reuse either half.
- **Decision:** Atomically mark the public OTK consumed within the Provider's contact-resolution transaction so it is issued once. At `A`, atomically verify the mapping, derive `SDHK`, mark/delete the SOTK mapping, and only then create/store/send the ACT; any missing/consumed mapping fails closed.
- **Classification:** Paper lifecycle ordering plus reproduction atomicity hardening.
- **Consequence:** A failed delivery does not make the public OTK reissuable, and a consumed SOTK cannot generate a second ACT. Recovery requires a fresh OTK; distributed rollback/reconciliation is not invented as paper protocol.

## 13. External human identity verification in a local research prototype

- **Evidence:** III-C and IV-B Step 5 assume robust authentication and a trusted external persistent-identity/human-verification service. The paper mentions OpenID Connect as an example. The approved design avoids a production external dependency.
- **Ambiguity:** A local prototype cannot truthfully claim to reproduce an external proof-of-human service merely by stubbing a boolean.
- **Decision:** Define an `IdentityVerifier` port. Use a deterministic trusted adapter in tests and a local trusted identity record in the demo; label both as substitutes for a paper assumption, not OpenID Connect reproduction or Sybil-proof evidence.
- **Classification:** Assumption-boundary engineering adapter.
- **Consequence:** A7 tests exercise protocol behavior given verifier output. They do not validate real human identity, identity-provider security, or global Sybil prevention.

## 14. Internal versus external CA wording across paper sections

- **Evidence:** IV-B Steps 2-3 and IV-C Step 2 describe obtaining certificates from an external CA. VI-A describes an internal CA deployed as part of the Provider. IV-E Step 6 requires `A` to verify `Cert_U2`, yet Step 5/Figure 9 do not explicitly transport `Cert_U2`.
- **Ambiguity:** Protocol trust wording and evaluation deployment differ, and the initiating User certificate needed by Step 6 has an unresolved source in the normative message flow.
- **Decision:** Use an independent test CA/trust anchor for the reproduction and treat internal/external placement as deployment, not a protocol-field change. Preserve the `Cert_U2` source omission explicitly: do not silently add it to the normative IV-E Step 5 tuple; any concrete retrieval/transport mechanism must be labeled an engineering supplement while Step 6 verification remains required.
- **Classification:** Paper deployment inconsistency plus a retained protocol transport gap.
- **Consequence:** Certificate tests validate bindings and trust independent of Provider protocol logic. The message ledger continues to show the Step 5 omission, and later implementation documentation must expose—rather than disguise—the chosen `Cert_U2` supply path.

## 15. Honest-but-curious Provider versus malicious-Provider extensions

- **Evidence:** III-D requires the Provider to follow SAGA logic but permits metadata/traffic observation. V and VI discuss Provider fault tolerance/scalability; these do not redefine the base threat model as Byzantine. The paper does not prove safety when the Provider violates policy or registry operations.
- **Ambiguity:** "Limited trust" and replication extensions could be overread as malicious-Provider resistance.
- **Decision:** Keep the baseline Provider protocol-following and honest-but-curious. Exclude malicious/Byzantine Provider defenses, PBFT, RAFT, sharding, federation, transparency, and equivocation detection from the base reproduction.
- **Classification:** Paper threat-model boundary and scope decision.
- **Consequence:** No test or ProVerif result may claim malicious-Provider security. Provider-hardening work requires a separately sourced extension.

## 16. Public routability, NAT traversal, and network DoS assumptions

- **Evidence:** III-C assumes globally routable public IP addresses and basic network defenses against DoS and packet flooding. It explicitly avoids NAT traversal/local discovery and assumes registered endpoints are directly reachable.
- **Ambiguity:** Localhost/container networking can demonstrate protocol transport but cannot reproduce Internet reachability or infrastructure defenses.
- **Decision:** Run reproducible local network/mTLS tests using configured endpoints and classify public routing, NAT traversal, local discovery, DDoS protection, and packet-flood mitigation as environmental assumptions outside baseline acceptance.
- **Classification:** Paper environmental assumption and reproduction scope boundary.
- **Consequence:** Local success is not evidence of public deployability or DoS resistance; failures attributable to routing infrastructure are reported separately from protocol failures.

## 17. Paper formal claims versus required engineering security tests

- **Evidence:** IV-F and Appendix D formally verify three security properties under a Dolev-Yao attacker: Token secrecy, Agent-Provider authentication, and Agent-Agent authentication. Appendix D separately runs reachability queries as model executability/sanity checks, not as a fourth security property. Appendix E evaluates A1-A8. The approved design additionally requires crypto/serialization, persistence, concurrency, TLS, logging, and twenty security tests. IV-E Step 8 explicitly checks `PAC_B` binding, expiration, and `Q_max`, but does not explicitly state a separate future-issued/not-before rejection.
- **Ambiguity:** Required tests can be mistaken for formal proof, while engineering validity rules can be misattributed to the paper.
- **Decision:** Label every result as paper assumption, one of the three ProVerif security proofs, Appendix D reachability sanity checking, Appendix E attacker evaluation, or reproduction engineering test. Keep ProVerif security claims to Token secrecy and the two authentication properties. Implement/test Step 8's binding, expiration, and quota checks as paper behavior; classify `[issued_at, expires_at)` and an independent future-issued rejection as reproduction engineering rules, not explicit paper claims.
- **Classification:** Evidence taxonomy and formal-claim boundary.
- **Consequence:** Passing twenty attacks or concurrency tests cannot expand ProVerif claims, and successful reachability queries cannot be reported as a security property. Reports must separately enumerate the three security properties, reachability sanity checks, A1-A8 results, and engineering hardening results.

## 18. Hardware-specific performance numbers versus directional acceptance

- **Evidence:** VI reports timings/throughput from specified hardware, network distributions, models, storage, and deployment configurations. The approved design requires reproducible trends, environment capture, and distribution statistics rather than cross-machine equality.
- **Ambiguity:** Absolute paper numbers are not portable across CPU, OS, network, storage, Python, libraries, or test scale.
- **Decision:** Accept directional reproduction: larger `q_max` lowers amortized per-request authorization overhead; longer lifetime lowers reauthorization frequency; scale/concurrency trends must be repeatable and explained. Record CPU, memory, OS, Python/dependency versions, configuration, warmups, sample count, concurrency, mean, median, P95, P99, and standard deviation; use same-environment historical relative thresholds for regression.
- **Classification:** Reproduction performance acceptance decision.
- **Consequence:** Paper values remain comparison points, never cross-hardware hard gates. Deviations require an evidence-based explanation and raw CSV/JSON, not threshold manipulation.
