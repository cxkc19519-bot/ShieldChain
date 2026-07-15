# SAGA Paper Analysis

This document treats the protocol text in Sections III-IV of the local SAGA paper as normative. Appendix Figures 7-9 are supporting evidence; where Figure 8 conflicts with IV-C Step 7, the main-text formula governs. Engineering choices are identified as such and trace back to [the feature-source matrix](feature-source-matrix.md).

## 1. Problem Addressed by SAGA

SAGA addresses three linked problems in agentic systems: agent discovery, secure direct agent-to-agent communication, and user-controlled remote access. Existing secure-channel, registry, and delegation systems do not jointly give a human user control over an Agent's registration, incoming contacts, and deactivation. SAGA introduces a Provider-maintained registry and user-defined Agent Contact Policies, while keeping post-setup Agent communication direct and bounding access through cryptographic Access Control Tokens (ACTs). (II-B-C; III-B)

## 2. Participants and Responsibilities

| Participant | Responsibility |
|---|---|
| User `U` | Chooses a persistent identity and password; owns Agents; generates and signs Agent metadata and OTKs; defines and updates Contact Policies; refreshes OTKs; rotates Agent keys; deactivates only owned Agents. |
| Agent `A` (receiving) | Holds its private TLS, access-control, and one-time secret keys; authenticates the initiator; derives `SDHK`; deletes the used SOTK; creates, encrypts, stores, and validates ACT state; enforces expiry and quota. |
| Agent `B` (initiating) | Authenticates to the Provider and receiving Agent; verifies returned registration material; derives `SDHK`; holds the ACT ciphertext; attaches it to later direct requests. |
| Provider | Maintains `D_U` and `D_A`; authenticates Users; checks uniqueness and signatures; enforces Contact Policies and per-pair OTK budgets; distributes one signed OTK per successful request; signs registered Agent information. |
| External CA | Issues certificates binding User and Agent identifiers to their public TLS/signature keys and supplies the Provider certificate/public key. |
| External identity service `S` | Performs persistent identity and human verification during User registration. |

The protocol is asymmetric: access control protects the receiving Agent according to its User's policy. (III-B; IV-B-E)

## 3. System Goals

SAGA's stated goals are: User-managed Agent lifecycle; access controlled by User policy; limited trust in third parties and Agents; scalability; limiting each Agent to its own participation; a tunable vulnerability window; and preserved task utility across Agent and LLM implementations. The architecture therefore moves discovery and first-contact authorization through the Provider but keeps subsequent Agent traffic direct. (III-A-B)

## 4. System Assumptions

- The Provider has robust User authentication and delegates human verification to a trusted external identity service; User credentials are not compromised.
- Attackers may register Agents under their own identities but cannot impersonate benign Users.
- Agents and Providers have globally routable public IP addresses.
- Signatures, certificates, DH, encryption, hashes, and KDFs are sound; secret keys remain confidential.
- Agent-Agent and Agent-Provider communication uses TLS, assumed to provide confidentiality, integrity, authenticity, and network-record replay protection.
- The network supplies basic DoS and packet-flooding defenses.
- Registries are stored securely and resist adversarial control or tampering. (III-C-D)

These are assumptions, not properties proved by the protocol or reproduced by local substitutes.

## 5. Threat Model

The Provider follows SAGA logic but may be honest-but-curious, observing metadata and traffic patterns. The paper considers: malicious registered Agents that deviate from the protocol (`C1`); compromised legitimate Agents (`C2`); unregistered self-replicating children that receive parent credentials (`C3`); adversarial credential or Token sharing (`C4`); Sybil identities (`C5`); and a Dolev-Yao-style network attacker that can observe, intercept, modify, replay, reorder, and synthesize messages without breaking cryptography (`C6`). It does not claim security against an actively malicious Provider, compromised registries, stolen benign-User credentials, broken primitives, TLS compromise, or infrastructure-level DoS. (III-C-D; IV-F; Appendix D-E)

## 6. Cryptographic Primitives

The protocol defines an EUF-CMA-secure signature scheme `KeyGen`, `Sign_SK(m)`, and `Verify_PK(m, sigma)`; certificates `GenCert_X(m) = <m, Sign_SK_X(m)>`; collision-resistant `H`; Diffie-Hellman with `DH(x, g^y) = DH(y, g^x)`; HKDF with SHA-256; TLS; and symmetric encryption `Enc`. It cites ECDSA and Ed25519 as acceptable signature examples but does not normatively select one. The evaluation uses Curve25519/X25519, X.509, and SHA-256, but these implementation observations do not override the abstract protocol.

Ed25519, X25519, HKDF parameters, ChaCha20-Poly1305, AAD, deterministic JSON, Base64URL, integer time units, and password KDF parameters are reproduction engineering decisions recorded in [the matrix](feature-source-matrix.md), not additional paper fields.

## 7. Key and Certificate Inventory

| Item | Owner | Private material | Public material | Storage location | Creation | Use | Rotation | Deletion |
|---|---|---|---|---|---|---|---|---|
| User signing credential | User `U` | `SK_U` | `PK_U`, `Cert_U = GenCert_SK_CA(<uid_U, PK_U>)` | `SK_U` with User; `Cert_U` in `D_U` and sent to verifiers | IV-B Steps 1-2 | Signs Agent metadata and every public OTK | Long-term identity key; the paper's evaluation/implementation discussion gives 30-90 days only as a non-normative example, not a protocol parameter; see [the matrix](feature-source-matrix.md) | Paper does not specify destruction; retire securely under key-management best practice |
| Provider signing credential | Provider | `SK_Prov` | `PK_Prov`, Provider certificate | `SK_Prov` at Provider; public identity obtained via CA | Provisioned before IV-B Step 3 | TLS identity and `sigma_A^Prov` | Paper gives only best-practice guidance, no protocol schedule | Paper does not specify; destroy retired private material securely |
| Agent TLS credential | Agent `A` / provisioning User | `SK_A` | `PK_A`, `Cert_A = GenCert_SK_CA(<aid_A, PK_A>)` | `SK_A` locally at Agent; `Cert_A` in `D_A` and exchanged | IV-C Step 2 | Agent-Agent mTLS and identity verification | User should periodically rotate Agent TLS keys (IV-D) | Paper does not specify; destroy retired private key after safe rollover |
| Agent access-control credential | Agent `A` / provisioning User | `SAC_A` | `PAC_A` | `SAC_A` locally at Agent; `PAC_A` in `D_A` and exchanged | IV-C Step 2 | Long-term DH contribution and ACT initiator binding | IV-D gives normative best-practice rotation guidance only; weekly or biweekly appears solely as a non-normative evaluation/implementation example, not a protocol parameter; see [the matrix](feature-source-matrix.md) | Paper does not specify; destroy retired `SAC_A` after dependent sessions/Tokens end |
| Each one-time credential | Receiving Agent `A` / provisioning User | Every `SOTK_A^i` | Every `OTK_A^i` plus `sigma_OTKi^U` | `SOTK_A^i` and mapping local to `A`; signed public OTK in `D_A` until issued | IV-C Step 2; replenished under IV-D | One receiving-side DH contribution per OTK | Short-term; refresh pool and replace each consumed OTK | Provider consumes public OTK on issue; `A` deletes `OTK_A^i -> SOTK_A^i` after successful DH/KDF (Fig. 9; IV-E Step 6 context) |
| Derived shared key | Agents `A` and `B` | `SDHK` | None | Ephemeral local state at both Agents; never in a registry or protocol message | `SDHK = KDF(DH_A) = KDF(DH_B)` in IV-E Step 6 | Encrypt/decrypt the ACT | New OTK derivation produces a fresh shared key | Paper does not state an explicit erase point; discard with dependent Token/session under least-retention practice |
| ACT plaintext nonce | Receiving Agent `A` | Random `N` inside encrypted ACT plaintext | None while encryption holds | In `A`'s Token state and within ciphertext held by `B` | `N $<- R` in IV-E Step 7 | One of exactly five ACT plaintext fields | Fresh for each Token | Discard with Token at completion/expiry/quota exhaustion |
| ACT encryption nonce | Receiving Agent `A` | AEAD nonce value is not specified by the paper's abstract `Enc` | May accompany ciphertext in an AEAD wire format | `A` during encryption; ciphertext package held by `B` | Reproduction generates a fresh nonce per ACT encryption | Ensures nonce-safe ACT AEAD encryption | Never reuse with the same key | Discard with ciphertext/Token; exact format and handling are engineering choices in [the matrix](feature-source-matrix.md) |

## 8. Key Ownership, Storage, Rotation, and Destruction

The inventory above is the lifecycle baseline. Three invariants are normative: private Agent material `(SK_A, SAC_A, {SOTK_A^1, ..., SOTK_A^N})` stays local to the Agent; the Provider stores only public Agent/OTK material and signatures; and a receiving Agent removes the used `OTK_A^i -> SOTK_A^i` mapping before issuing the Token (Fig. 9). The paper explicitly recommends periodic rotation of TLS and access-control keys. Its evaluation classifies OTKs as short-term, access-control keys as medium-term, and identity keys as long-term, but the example weekly/biweekly and 30-90-day schedules are evaluation/implementation guidance only. They are not fixed protocol parameters; concrete schedules remain on the engineering side of [the matrix](feature-source-matrix.md). The paper does not define rollover messages, overlap windows, certificate revocation, crash-safe erasure, or an `SDHK` deletion protocol. Those gaps must not be presented as paper guarantees.

ACT has two nonce concepts that must remain distinct: `N` is a normative field inside the five-field plaintext; the nonce required by the selected AEAD is an implementation-only encryption parameter and is not a sixth ACT plaintext field.

## 9. Registry Data Structures

The User Registry update is:

```text
D_U[uid_U] = <H(passwd), Cert_U>
```

The Agent metadata and registry entry are:

```text
M_A = {ED_A, Cert_A, PAC_A, OTK_A^i, i in [1, N]}
D_A[aid_A] = <uid_U, M_A, CP_A, sigma_A^U, sigma_OTKi^U>
```

The Provider also maintains the per-direction pair counter:

```text
Counter_OTK[aid_A][aid_B]
```

where `A` is receiving and `B` initiating. Public OTK availability, policy, and counter state jointly govern issuance. (IV-B Step 6; IV-C Step 7; IV-D.2)

## 10. User Registration

1. User chooses `uid_U` (for example, an email address) and secret `passwd`.
2. User generates `(PK_U, SK_U)` and obtains:

   ```text
   Cert_U = GenCert_SK_CA(<uid_U, PK_U>)
   ```

3. User obtains and verifies the Provider certificate and `PK_Prov`, then establishes TLS.
4. User sends `(uid_U, passwd)` and `Cert_U`.
5. Provider uses external service `S` to verify identity/human status and checks that the account does not exist.
6. Provider writes `D_U[uid_U] = <H(passwd), Cert_U>` and confirms. (IV-B Steps 1-6; Fig. 7)

The reproduction replaces the external service and password-storage detail with classified engineering adapters; it does not claim to reproduce OpenID Connect.

## 11. Agent Registration

The User constructs:

```text
aid_A = uid_U:name_A
ED_A = <device_A, IP_A, port_A>
Cert_A = GenCert_SK_CA(<aid_A, PK_A>)
(PAC_A, SAC_A)
(OTK_A^1, SOTK_A^1), ..., (OTK_A^N, SOTK_A^N)
sigma_OTKi^U = Sign_SK_U(<aid_A, OTK_A^i>)
sigma_A^U = Sign_SK_U(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>)
```

The User supplies `CP_A`, authenticates to the Provider over TLS with `<uid_U, passwd>`, and submits `(aid_A, ED_A, CP_A)`, `Cert_A`, `PAC_A`, `{OTK_A^1, ..., OTK_A^N}`, `sigma_A^U`, and every `sigma_OTKi^U`. The Provider checks global uniqueness of `aid_A` and `ED_A`, verifies `Cert_A`, then performs:

```text
Verify_PK_U(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>, sigma_A^U)
Verify_PK_U(<aid_A, OTK_A^i>, sigma_OTKi^U)
```

After storing `M_A` and `D_A[aid_A]`, the normative IV-C Step 7 formula is:

```text
sigma_A^Prov = Sign_SK_Prov(<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>)
```

Appendix Figure 8 instead displays `Sign_SK_Prov(<Cert_U, ED_A, PAC_A, sigma_A^U>)`. The reproduction follows the main-text formula and preserves the conflict in the message ledger; the figure cannot override the main-text formula.

## 12. Agent Management

Agent management comprises Contact Policy definition/enforcement, OTK replenishment, policy updates, key rotation, and deactivation. Users may add or remove policy rules and push the modified `CP_A` to the Provider. A deny rule has budget `B(.) = -1`. A User may deactivate only an Agent that they own, completely disabling new incoming contact; Users cannot deactivate other Users' Agents. Users may refresh OTKs at any time and should periodically rotate Agent TLS and access-control keys. (IV-D)

The paper does not specify retroactive invalidation of already-issued ACTs or exact counter migration after a policy update. The deterministic reproduction behavior is classified in [the matrix](feature-source-matrix.md).

## 13. Agent Contact Policy

For receiving Agent `A`, initiating Agent `B`, matching rules `R` in `CP_A`, most-specific rule `r*`, and its budget `B(r*)`:

```text
Budget_OTK(aid_A, aid_B) =
    -1      if R = empty
    B(r*)   if R != empty
```

Rules pattern-match Agent identifiers, and the most specific matching rule wins. The `-1` no-match result distinguishes policy denial/no match from an expired positive quota. A policy may also explicitly assign `-1` to block an Agent. The paper does not fully order all wildcard classes or define equal-specificity conflict resolution; any deterministic ordering beyond “most specific” is an engineering decision. (IV-D.1; Listing 1)

## 14. One-Time Key Allocation

On the first contact from `B` to `A`, the Provider initializes:

```text
Counter_OTK[aid_A][aid_B] = Budget_OTK(aid_A, aid_B)
```

For each permitted request it checks policy membership, checks `Counter_OTK[aid_A][aid_B] > 0`, selects exactly one available signed `OTK_A^i`, returns it with receiving-Agent metadata, and performs:

```text
Counter_OTK[aid_A][aid_B] -= 1
```

Failure is distinguishable between overall OTK-pool exhaustion and depletion of `B`'s quota. The paper chooses one OTK per request to limit the compromise window. Atomicity and precise update order are reproduction hardening, not formulas supplied by the paper. (IV-D.2; IV-E Step 2; Fig. 9)

## 15. Inter-Agent Communication

Let `B` initiate contact with receiving Agent `A`.

1. `B` establishes TLS with the Provider.
2. `B` requests contact using `aid_B` and `aid_A`. After policy/quota checks, the Provider returns:

   ```text
   Cert_U1, (aid_A, ED_A), (Cert_A, PAC_A),
   OTK_A^i, sigma_OTKi^U1, sigma_A^U1
   ```

   and decrements `Counter_OTK[aid_A][aid_B]`.
3. `B` verifies `Cert_U1` and:

   ```text
   Verify_PK_U1(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>, sigma_A^U1)
   Verify_PK_U1(<aid_A, OTK_A^i>, sigma_OTKi^U1)
   ```

4. `B` establishes TLS with `A`; both verify `Cert_A` and `Cert_B`.
5. `B` sends:

   ```text
   <aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, OTK_A^i, sigma_B^Prov
   ```

6. `A` verifies `Cert_U2`, the Provider signature, and that the OTK mapping exists:

   ```text
   Verify_PK_Prov(<aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, sigma_B^Prov)
   OTK_A^i -> SOTK_A^i exists in local storage
   ```

   The two sides derive:

   ```text
   DH_A = DH(SOTK_A^i, PAC_B)
   DH_B = DH(SAC_B, OTK_A^i)
   SDHK = KDF(DH_A) = KDF(DH_B)
   ```

   In the reproduction's selected primitive: `X25519(SAC_B, OTK_A^i) = X25519(SOTK_A^i, PAC_B)`.
7. `A` deletes `OTK_A^i -> SOTK_A^i`, creates and encrypts the ACT, stores Token state, and sends ciphertext to `B`.
8. `B` attaches the Token to subsequent direct requests. `A` verifies binding, time, and quota; both discard it when the task completes. (IV-E Steps 1-8; Fig. 9)

## 16. Access Control Token

The paper's ACT is exactly the following five-field plaintext tuple encrypted under the derived shared key:

```text
N $<- R
token = Enc_SDHK(<N, T_issued, T_expire, Q_max, PAC_B>)
```

`N` is random; `T_issued` records issuance; `T_expire` supplies the explicit expiration bound; `Q_max` bounds the number of requests; and `PAC_B` binds the Token to the initiating Agent. Step 8 explicitly checks that the Token was issued for `B`, has not expired, and has not exceeded its request limit. The paper does not prescribe a separate “future-issued” or not-before check against `T_issued`. `A` creates, encrypts, and stores Token state; `B` stores the ciphertext and attaches it to later requests; `A` decrypts/verifies subsequent use. Reuse by the same `B` is valid while the Token is unexpired and below `Q_max`, including after TLS reconnection. Both discard the Token when the task completes. (IV-E Steps 7-8 and “Token reuse”; Fig. 9)

No `version`, Token ID, Agent ID, task ID, context hash, tool, operation, parameter, or resource field belongs in this tuple. Outer versioning, encoding, AEAD nonce/AAD, time units, persistent quota counting, and concurrency semantics are implementation-only choices linked in [the matrix](feature-source-matrix.md). Although the prose calls the ACT task-scoped, the tuple has no task identifier; this limitation is not repaired by changing the baseline tuple.

## 17. Required Signature Verification by Entity

| Verifier | Required verification | Evidence/use |
|---|---|---|
| User `U` | Provider certificate and `PK_Prov` before TLS | IV-B Step 3; Fig. 7 |
| Provider | User credentials and persistent identity; `Cert_A`; `Verify_PK_U(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>, sigma_A^U)`; every `Verify_PK_U(<aid_A, OTK_A^i>, sigma_OTKi^U)` | IV-B Step 5; IV-C Steps 4 and 6; Fig. 8 |
| Initiating Agent `B` | `Cert_U1`; receiving Agent certificate/key binding; `sigma_A^U1`; `sigma_OTKi^U1`; peer `Cert_A` during TLS | IV-E Steps 3-4; Fig. 9 |
| Receiving Agent `A` | Initiating User certificate `Cert_U2`; `Verify_PK_Prov(<aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, sigma_B^Prov)`; peer `Cert_B` during TLS; local OTK-to-SOTK existence | IV-E Steps 4-6; Fig. 9 |

The protocol message ledger records the exact signer/key/tuple mapping and the Figure 8 inconsistency.

## 18. Formally Proved Security Properties

The paper models Agent registration and Agent communication in ProVerif under the symbolic Dolev-Yao model. It reports proofs of: secrecy of the SAGA Token; authentication of Agent-Provider communication; and authentication of Agent-Agent communication. It also issues reachability queries. The attacker may observe, intercept, modify, replay, reorder, and synthesize arbitrary network messages, subject to symbolic cryptographic assumptions. (IV-F; Appendix D)

These are protocol-model results, not proofs of implementation correctness, policy semantics, database transactions, or all runtime properties.

## 19. Security Properties Not Covered by the Paper

The paper does not prove or fully specify: safety against an actively malicious Provider; compromised registry storage; credential theft from benign Users/Agents; PKI/CA compromise; TLS or primitive failure; public-endpoint/NAT discovery; DoS resistance; Sybil prevention beyond persistent human identities; secure deletion; crash recovery; atomic OTK, pair-counter, or `Q_max` updates; deterministic serialization; application-request deduplication; active revocation of issued ACTs; privacy of Provider-visible metadata/traffic; policy-rule ambiguity resolution; counter migration on policy updates; or task binding despite the task-scoped prose.

The eight implemented attack cases in Appendix E demonstrate selected detection paths under the assumptions; they do not enlarge the formal proof boundary.

## 20. Reproduction Scope and Exclusions

The base reproduction covers IV-B through IV-E: User registration, Agent registration, registries, Contact Policies, OTK allocation, mTLS communication, DH/KDF derivation, the exact five-field ACT, verification, legal reuse, expiry/quota enforcement, policy updates, and Agent deactivation. It will use mature libraries and deterministic engineering choices documented in [the matrix](feature-source-matrix.md), without treating those choices as paper protocol.

Excluded from the baseline are RAFT/Paxos/PBFT, sharding, federation, A2A integration, active Token revocation, prompt-injection defenses, risk-adaptive policy, and Agent-to-Tool authorization. The authors' code is a non-normative cross-check only. Any future task/tool/resource Token must be a separate extension and must not alter the paper ACT tuple.
