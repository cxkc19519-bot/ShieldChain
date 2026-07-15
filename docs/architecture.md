# SAGA Reproduction Architecture

## Goals and Non-Goals

This architecture defines a modular, testable reproduction of the base SAGA protocol in Sections IV-B through IV-E. It covers User and Agent registration, Contact Policy evaluation, one-time-key (OTK) allocation, direct Agent communication, ACT establishment and bounded reuse, policy updates, Agent deactivation, real X.509 transport, and reproducible verification artifacts.

The first milestone is a pure protocol core with in-memory adapters; SQLite and real FastAPI/mTLS services complete the reproduction. The core is not a mock protocol: it uses mature implementations of signatures, certificates, X25519, HKDF, AEAD, password hashing, and constant-time comparison.

Non-goals are malicious/Byzantine Provider resistance, compromised-registry recovery, external proof-of-personhood, public routing/NAT traversal, infrastructure DoS defense, application-semantic request deduplication, active ACT revocation, RAFT/PBFT, sharding, federation, A2A integration, prompt-injection detection, risk-adaptive authorization, and Agent-to-Tool authorization. The baseline does not add task, tool, operation, parameter, resource, or delegation fields to the ACT.

## Source-Provenance Boundary

The source order is: explicit paper formulas and steps; paper figures and notation; implementation/evaluation prose; approved reproduction decisions; then non-normative reference-code observations. Conflicts are recorded rather than silently resolved. Every executable behavior must be classified in `docs/feature-source-matrix.md` as paper design, reproduction engineering, or a deferred extension.

The paper ACT plaintext remains exactly five fields:

```text
<N, T_issued, T_expire, Q_max, PAC_B>
```

The implementation names are `nonce`, `issued_at`, `expires_at`, `q_max`, and `initiating_agent_access_control_public_key`. Protocol `version`, the AEAD nonce, and encoding metadata are outer-envelope engineering fields, not ACT plaintext. IV-E Step 8 explicitly checks initiating-Agent binding, expiration, and quota; it does not specify an independent future-issued/not-before rejection. The reproduction's half-open interval and future-issued rejection are therefore engineering rules, never attributed to Step 8.

The paper requires receiving Agent `A` to verify `Cert_U2` in IV-E Step 6, but Step 5/Figure 9 does not transport it. This transport gap remains visible. A later concrete certificate lookup or supplemental envelope must be labeled an engineering supplement and must not be inserted into the normative Step 5 tuple.

## Package and Dependency Diagram

Only inward project dependencies are permitted:

```text
adapters -> protocols -> domain
adapters -> ports <- protocols
protocols -> crypto -> domain
verification -> public protocol interfaces
```

| Package | Responsibility | Public interface responsibility | May not import |
|---|---|---|---|
| `domain` | Immutable identifiers, endpoints, policies, OTK/ACT values, lifecycle states, commands/results, and stable errors | Validated value objects and framework-neutral result/error types | Any other `saga` package; FastAPI/Pydantic transport models; SQL/ORM; concrete crypto libraries |
| `crypto` | Canonical encoding and mature-library wrappers for Ed25519, X.509, X25519, HKDF-SHA256, ChaCha20-Poly1305, scrypt, SHA-256, and constant-time comparison | Typed primitive operations that accept/return domain values or bytes and fail closed | `protocols`, `ports`, `adapters`, FastAPI, persistence, policy logic |
| `ports` | Protocol-owned abstractions for state, time, randomness, identity checks, password records, trust, and atomic transitions | Minimal protocols/ABCs whose methods express required atomic semantics | `adapters`, FastAPI, SQLite/ORM, concrete crypto libraries; it must not implement policy |
| `protocols` | User/Agent registration, contact resolution, policy selection, OTK issuance, ACT establishment/use, update, and deactivation state machines | Use-case commands/results and public service interfaces; all authorization decisions live here | `adapters`, FastAPI/Pydantic HTTP models, SQLite/ORM, filesystem/environment/config loading |
| `adapters` | In-memory/SQLite port implementations, FastAPI routes, TLS/mTLS endpoints, CA/certificate/config loading, clocks, RNG, and identity substitutes | Translate external inputs to protocol commands, implement ports, map stable outcomes outward | Verification internals; routes cannot import persistence implementations directly or encode protocol policy |
| `verification` | Unit/protocol/security/network/concurrency/performance harnesses, ProVerif models, result schemas, and paper comparison | Exercise only public protocol interfaces and deployed network endpoints | Adapter internals, private protocol helpers, production secret/config state; it cannot become a runtime dependency |

The HTTP layer cannot decide policy. Persistence cannot decide authorization. Routes validate transport shape, establish authenticated transport identity, invoke a use case, and map its stable result. Stores execute the atomic state transition requested by the protocol but do not choose whether an identity, policy, Token, or operation is authorized.

## Domain Models

Core immutable models include `UserId`, `AgentId`, `EndpointDescriptor`, certificate/key references, `UserRegistration`, `AgentRegistration`, `ContactPolicy`, `PolicyRule`, `PairBudget`, `PublicOtk`, `SecretOtk`, `OtkState`, `ActPlaintext`, `ActEnvelope`, and `ActUseState`. `AgentId` has the paper-compatible `uid_U:name_A` form; an endpoint has device, IP/address, and port components.

`ContactPolicy` selects one most-specific match using the engineering order exact Agent ID > User-domain wildcard > Agent-type wildcard > global wildcard. Equal-specificity overlap is invalid at registration/update. `budget=-1`, no match, exhausted pair budget, and exhausted OTK pool remain distinct domain outcomes.

OTK states distinguish available public material, Provider-issued/consumed public material, and receiving-side SOTK availability/consumption. ACT state is authoritative at the receiver; the initiator stores only the opaque ciphertext. Successful ACT use increments persistent usage, while failed validation consumes no quota.

Security-sensitive numeric fields are integers. Time is Unix milliseconds and injected through `Clock`. Binary fields use strict unpadded Base64URL at the transport boundary. Unknown/duplicate fields, non-canonical encodings, and floating-point security fields are rejected.

## Cryptographic Boundary

The cryptographic package delegates all primitives to `cryptography` or an equivalently reviewed mature library; it never implements a primitive itself. The reproduction profile is:

- Ed25519 for User and Provider signatures;
- X.509 certificates issued by an independent test CA for User, Provider, and Agent bindings;
- X25519 for long-term Agent access-control keys and OTK/SOTK pairs;
- HKDF-SHA256 with `salt=None` and `info=b"SAGA-ACT-DERIVE/v1"`;
- ChaCha20-Poly1305 with a fresh encryption nonce and `aad=b"SAGA-ACT/v1"`;
- scrypt with `N=2^15, r=8, p=1, dkLen=32` and a fresh 16-byte salt;
- SHA-256 where the paper requires a hash; deterministic UTF-8 JSON for signed/encrypted tuples.

The exact signed tuples are centralized and version-tested. In particular, the Provider signs the IV-C Step 7 main-text tuple `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>`, not the conflicting Figure 8 layout. User signatures cover `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>` and each `<aid_A, OTK_A^i>`.

Secret types are non-serializable by default. Private keys, passwords, salts plus derived verifiers, SOTKs, `SDHK`, ACT plaintext, and full ciphertext are never exposed through public results or logs. AEAD and canonical-decoding failures collapse to stable fail-closed domain errors rather than forming verification oracles.

## Protocol State Machines

Each use case is an explicit transition with no hidden framework state:

```text
User:       absent -> identity_verified -> registered
Agent:      absent -> registration_verified -> active -> deactivated
Public OTK: available -> issued (terminal)
Secret OTK: available -> consumed/deleted (terminal)
ACT:        established -> usable -> exhausted | expired | discarded
```

Registration transitions commit only after all credentials, certificates, uniqueness conditions, and signatures verify. Contact resolution evaluates active state and current policy, initializes/caps the pair counter, consumes exactly one budget unit and one OTK, then returns one typed response. ACT establishment accepts an unused local SOTK, verifies initiating registration material, derives `SDHK`, consumes the SOTK, and creates/stores the five-field Token. ACT use maps the mTLS peer to its registered `PAC_B`, decrypts, checks binding/time/quota, and atomically increments on success.

Same-Agent ACT reuse below `q_max` and before expiry, including across a new TLS session, is legal. Wrong-Agent transfer, expired use, exhausted use, and TLS-record replay are different cases. No request ID exists, so semantic duplicate detection is outside the baseline.

## Port Interfaces

Ports are narrow and express transaction intent rather than storage mechanics:

- `UserRegistry`: create-if-absent and fetch User certificate/password record.
- `AgentRegistry`: create-if-unique, fetch active/owned registration, update policy, append signed OTKs, and deactivate owned Agent.
- `ContactResolutionStore`: one atomic operation for current policy/active checks, pair-counter initialization or capping, positive-budget decrement, and exactly-one public OTK consumption.
- `ReceivingOtkStore`: atomically claim an `OTK -> SOTK` mapping for one ACT establishment; a claimed mapping can never be restored by retry.
- `ActStateStore`: create receiver-owned state, atomic validate-and-increment, fetch/discard, and crash-safe recovery semantics.
- `IdentityVerifier`: persistent-identity/human-verification decision; local adapters are substitutes for a paper assumption, not OpenID Connect reproduction.
- `PasswordHasher`, `CertificateVerifier`, and `PeerIdentityResolver`: secure credential operations and mapping of authenticated transport identity to registered identity.
- `Clock`, `SecureRandom`, and `TransactionRunner`: deterministic test seams and production-safe providers.

Port methods return stable domain results/errors. They never return a partially mutated aggregate and never expose SQL exceptions, raw certificate-library exceptions, or cryptographic-library errors.

## In-Memory and SQLite Adapters

The in-memory adapter provides deterministic, lock-protected implementations for unit and protocol tests. It must have the same uniqueness, ordering, atomicity, and failure semantics as SQLite; it is not allowed to weaken concurrency behavior because it is “only for tests.”

SQLite uses schema constraints for unique `uid`, `aid`, endpoint, and OTK identity; transactions use a write-locking strategy sufficient to linearize counter and consumption transitions. Transaction retry is bounded and maps lock exhaustion to `ConcurrentConflict`. Restart tests reopen the database and prove that issued public OTKs, consumed SOTKs, pair budgets, Agent deactivation, ACT state, and usage counts do not roll back.

Both adapters implement protocol-requested transitions. Persistence cannot decide authorization: it may enforce structural constraints and compare-and-update preconditions, but policy matching, ownership rules, Agent eligibility, and ACT validity are protocol decisions.

## FastAPI and mTLS Adapters

FastAPI routes parse versioned transport envelopes, resolve authenticated identity, invoke one protocol use case, and map stable errors to coarse HTTP responses. The HTTP layer cannot decide policy and cannot skip a protocol verification because a request arrived over TLS.

User-to-Provider registration/management uses server-authenticated TLS followed by User account/external-identity authentication inside the protected channel. It is not User-certificate mTLS. Agent-to-Agent uses real mutual TLS and both peers validate Agent certificates. The completed network reproduction also authenticates Agent-to-Provider connections with the approved X.509/mTLS deployment profile, while preserving the paper classification of IV-E Step 1 as TLS.

TLS adapters enforce trust anchors, certificate validity, expected Agent/Provider identity, timeouts, bounded request sizes, interrupted-session cleanup, and reconnect behavior. A TLS handshake failure never reaches protocol code. TLS record replay is tested at the transport boundary; it is not implemented as an ACT field or application deduplication rule.

## User Registration Data Flow

1. User chooses `uid_U` and password, generates `(PK_U, SK_U)`, and obtains `Cert_U` binding `<uid_U, PK_U>`.
2. User verifies the Provider certificate and opens server-authenticated TLS (not User mTLS).
3. The route validates the envelope and calls `RegisterUser` with `uid_U`, password, and `Cert_U`.
4. The protocol verifies certificate binding, invokes `IdentityVerifier`, rejects an existing User, and requests scrypt hashing with fresh salt.
5. `UserRegistry.create_if_absent` atomically stores only the password record and `Cert_U`.
6. A typed confirmation is returned; secrets are cleared from request-scoped state and excluded from logs.

## Agent Registration Data Flow

1. The authenticated owning User constructs `aid_A`, `ED_A`, `Cert_A`, `(PAC_A, SAC_A)`, OTK/SOTK pairs, `CP_A`, `sigma_A^U`, and each `sigma_OTKi^U`.
2. Private `SK_A`, `SAC_A`, and SOTKs are provisioned only to Agent `A`; only public material reaches the Provider.
3. Over server-authenticated User-Provider TLS, account credentials authenticate the User and the route calls `RegisterAgent`.
4. The protocol checks ownership context, global `aid_A`/endpoint uniqueness, Agent certificate binding, policy validity, the exact User metadata signature, and every exact OTK signature.
5. One transaction stores the complete Agent record, policy, signatures, and OTK pool; no subset is visible on failure.
6. The Provider signs `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>` and returns the attestation. Signature generation failure aborts the registration transaction or leaves no active Agent.

## Contact Resolution and OTK Data Flow

1. Initiating `B` authenticates to the Provider and requests contact with receiving `A` using both Agent IDs.
2. The protocol loads registered identities and delegates one atomic transition to `ContactResolutionStore`.
3. Inside that transition, the requested protocol decision is applied to current active state and the most-specific current policy; the pair counter is initialized or capped by `min(old_remaining, new_budget)` and must be positive.
4. Exactly one signed available public OTK is selected; the pair budget is decremented and the OTK is marked issued in the same commit.
5. Only after commit does the Provider return `Cert_U1`, `aid_A`, `ED_A`, `Cert_A`, `PAC_A`, one `OTK_A^i`, `sigma_OTKi^U1`, and `sigma_A^U1`.
6. `B` verifies the CA bindings and both User signatures before contacting `A`.

No match, explicit deny, inactive Agent, pair-budget exhaustion, and OTK-pool exhaustion are distinct internal results. Policy update applies on the next request; a larger budget or OTK refill never restores already consumed pair quota.

## ACT Establishment and Use Data Flow

1. `B` and `A` complete mTLS and verify Agent certificates.
2. `B` sends the normative Step 5 tuple `<aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, OTK_A^i, sigma_B^Prov`.
3. `A` performs the Step 6 `Cert_U2` verification requirement and Provider-attestation verification. Because the paper omits the `Cert_U2` transport source, the concrete supply path remains an explicitly classified engineering supplement.
4. `B` derives `SDHK` from `X25519(SAC_B, OTK_A^i)`; `A` derives it from `X25519(SOTK_A^i, PAC_B)` and fixed HKDF parameters.
5. `A` atomically claims/deletes the SOTK mapping before creating Token state. Failure requires a fresh OTK; distributed rollback is not invented.
6. `A` creates exactly `<N, T_issued, T_expire, Q_max, PAC_B>`, encrypts it with fresh AEAD nonce/AAD, stores authoritative receiver state, and sends only the envelope/ciphertext to `B`.
7. On later mTLS requests, `A` maps the peer certificate to registered `PAC_B`, decrypts, checks semantic key equality, applies `[issued_at, expires_at)`, and atomically checks `< q_max` then increments.
8. Expiry, exhaustion, or local task completion discards Token state as specified; continued contact starts with a fresh OTK. Policy change or deactivation blocks new discovery/OTK issuance but does not retroactively revoke an issued ACT.

## Atomicity and Transaction Boundaries

The following operations cannot partially commit:

- User create-if-absent and complete Agent registration;
- policy replacement/validation, OTK append, and Agent deactivation;
- policy/active-state read, pair-counter initialization/capping/check/decrement, and one public OTK select-and-consume;
- SOTK claim/delete plus receiver ACT-state creation, with an explicit fail-closed recovery rule if encryption/storage fails;
- ACT `< q_max` validation and successful-use increment;
- task-completion discard and terminal-state transitions.

Provider and receiving Agent transactions are separate trust/state domains. The architecture does not claim distributed atomic rollback between public OTK issuance and SOTK consumption. Once a public OTK is issued it is never returned to the pool; a failed later handshake starts over with a new OTK. Linearization tests cover both in-memory and SQLite adapters, including `q_max=1`, simultaneous last-budget use, and simultaneous last-OTK allocation.

## Failure Semantics

Stable categories are: `InvalidInput`, `AuthenticationFailed`, `InvalidCertificate`, `InvalidSignature`, `DuplicateRegistration`, `PolicyDenied`, `PolicyNoMatch`, `PairBudgetExhausted`, `OtkPoolExhausted`, `OtkConsumed`, `AgentInactive`, `TokenIdentityMismatch`, `TokenNotYetValid`, `TokenExpired`, `TokenExhausted`, `InvalidTokenCiphertext`, and `ConcurrentConflict`.

All failures are fail closed. Validation occurs before mutation except where one atomic compare-and-update performs both. Failed signature, certificate, binding, time, or ciphertext checks do not consume ACT quota. External HTTP responses are deliberately coarser than internal errors where detail would create a credential, certificate, signature, OTK, or Token oracle. Timeouts/interruption abort uncommitted work; committed one-time consumption is never reversed. Unknown exceptions become a generic failure, are correlated internally, and never expose a stack trace or secret.

## Secret-Safe Observability

Structured events contain event name, public User/Agent IDs where appropriate, coarse result category, duration, adapter kind, correlation ID, and transaction/retry count. Security events distinguish policy denial, OTK issuance, ACT establishment, legal ACT use, expiry, exhaustion, identity mismatch, and transport failure without disclosing verification internals.

Logs, metrics, traces, exceptions, and benchmark artifacts must never contain passwords, password verifiers/salts, private keys, SOTKs, `SDHK`, complete ACT plaintext, complete ACT ciphertext, AEAD keys/nonces, or raw authorization headers. A log-capture security test injects recognizable canary secrets and scans all outputs. Logging failure cannot change authorization or transaction outcome.

## Configuration and Dependency Injection

The composition root is the only place that reads environment/files, selects adapters, loads trust anchors and keys, sets database paths, or constructs FastAPI applications. Protocol constructors receive ports, crypto services, and immutable configuration explicitly. Tests inject a fake `Clock`, deterministic non-production random/vector sources where appropriate, in-memory stores, and controlled identity/certificate verifiers; production paths inject OS CSPRNG, real clock, SQLite, and X.509/mTLS adapters.

Security constants are named, versioned configuration with safe defaults. Private keys and passwords are loaded through secret-bearing adapters and are never stored in ordinary config files. Invalid or incomplete configuration fails startup before a listening socket is opened.

## Verification Architecture

Verification is layered and isolated from runtime imports:

- unit: canonical bytes and fixed cryptographic vectors;
- protocol: state-machine transitions and IV-B–IV-E coverage through public interfaces;
- integration: memory/SQLite semantic parity, persistence, crash/reopen, and transaction failures;
- security: the 20 required adversarial cases with provenance labels;
- network: real CA, TLS/mTLS, certificate failures, timeout/interruption/reconnect, and TLS-record replay;
- concurrency: OTK, pair budget, SOTK, and `q_max` linearization;
- performance: stable CSV/JSON raw samples and statistical summaries;
- formal: separate ProVerif registration and communication models.

ProVerif claims are limited to Token secrecy, Agent-Provider authentication, and Agent-Agent authentication. Reachability queries are executability sanity checks, not a fourth security property. Runtime tests do not become formal proofs, and ProVerif does not prove policy semantics, database atomicity, TLS/library correctness, availability, or implementation security.

## Deferred Extensions

Deferred work is isolated behind future, unused extension seams: a separate Agent-to-Tool capability-token family, `RiskAssessment`/`RiskPolicyEngine`/`TokenParameterPolicy`, and `RiskDetector.assess(context, user_intent, planned_action)`. Baseline composition does not instantiate these interfaces, does not generate placeholder risk scores, and does not branch authorization on them.

Tool/task/resource authorization is completely deferred. It must use a separate branch and Token family after the base gate; it cannot add fields to, wrap claims around, or reinterpret the five-field paper ACT. Active revocation, prompt-injection detection, risk-adaptive lifetime/quota, delegation, RAFT/PBFT, sharding, federation, A2A, and malicious-Provider defenses likewise remain outside runtime code and baseline acceptance.
