# SAGA Threat Model

This document separates the paper's assumptions, symbolic proof results, attacker experiments, and reproduction-only engineering tests. The normative sources are Sections III-C, III-D, IV-B-IV-F, Appendix D, and Appendix E of the SAGA paper. A paper assumption is not a proved property; an Appendix E result is not a ProVerif result; and a reproduction test is not evidence that the paper proved the tested property.

## Trusted and Honest-but-Curious Components

- **Provider:** The Provider is trusted to execute SAGA protocol logic correctly: authenticate Users, maintain `D_U` and `D_A`, enforce Contact Policies, allocate OTKs, update pair counters, and sign registered Agent data. Section III-D permits the Provider to be honest-but-curious and observe Agent metadata and traffic patterns, but does not permit it to alter registry state, misissue OTKs, bypass policy, forge protocol history, or otherwise act maliciously.
- **User and Agent registries:** Section III-D assumes registry storage is secure and not under adversarial control or tampering. Registry integrity and availability are therefore trusted premises.
- **External identity service:** Section III-C and IV-B Step 5 trust an external service to verify persistent identity and human status. The service is outside the SAGA protocol proof.
- **Certificate authority:** IV-B Steps 2-3 and IV-C Step 2 rely on a CA for User, Provider, and Agent certificate bindings. The protocol assumes valid certificate issuance and verification. The paper's protocol prose describes an external CA, while VI-A describes an internal CA deployed with the Provider; this deployment difference does not change the trusted-CA premise.
- **Users:** Benign-User credentials are assumed uncompromised (III-C). An attacker may create Agents under its own identity but may not register an Agent under a benign User's identity.

The User-Provider channel in IV-B Step 3 and IV-C Step 4 is server-authenticated TLS followed by account or external-service authentication inside that channel. The paper does not specify User-certificate mTLS. Agent-Agent communication in IV-E Step 4 is mutual TLS.

## System Assumptions

| Assumption | Exact paper location | Boundary imposed on claims |
|---|---|---|
| Robust User authentication; uncompromised User credentials; human-only Agent registration through a trusted identity service | III-C; IV-B Step 5 | SAGA does not prove identity-provider correctness, proof-of-personhood, or safety after benign-User credential theft. |
| Attackers may register Agents only under their own identities | III-C, Agent Identity Control | Impersonating a benign User at registration is excluded rather than defeated by the protocol. |
| Globally routable public endpoints for Agents and Providers | III-C, Public IP Addressing | NAT traversal, local discovery, address reachability, and public endpoint provisioning are outside the protocol. |
| Secure signatures, certificates, DH, encryption, hashing, and KDFs; confidential secret keys | III-C, Cryptographic Soundness; IV-A | Primitive breaks, private-key extraction, weak randomness, and CA compromise are outside the model. C2-C4 deliberately admit compromise or sharing in the specified Agent scenarios, but do not turn cryptographic forgery into an allowed operation. |
| TLS confidentiality, integrity, authenticity, and network-record replay protection | III-C, Secure Channels; IV-B Step 3; IV-C Step 4; IV-E Steps 1 and 4 | TLS compromise and on-channel record-layer replay that defeats TLS are outside the runtime attacker evaluation. Legal ACT reuse after a TLS reconnect remains paper behavior (IV-E, Token reuse). |
| Basic infrastructure protection against DoS and packet flooding | III-C, Network Protections | SAGA does not prove or experimentally establish network DoS resistance. |
| Secure, untampered registries | III-D | Registry corruption, rollback, and malicious administrative writes are outside the base threat model. |

## Adversary Capabilities C1-C6

| Capability | Capability admitted by the paper | Where it is accepted, limited, or rejected |
|---|---|---|
| **C1 - registered adversarial Agent** | An adversary can create and register an Agent under its own identity, deviate from the protocol, and use social engineering to persuade a benign User to allow it. | Defined in III-D. IV-D.1 and IV-E Step 2 apply the receiving Agent's Contact Policy before OTK issuance; IV-E Step 8 and Token reuse bound an issued ACT by expiration and `Q_max`. Appendix E A6 demonstrates policy denial, while A8 demonstrates that a valid ACT is accepted but bounded. Social-engineering success itself is not prevented. |
| **C2 - compromised legitimate Agent** | A legitimate Agent registered with the Provider may be compromised through websites, tools, or other external resources. | Defined in III-D. IV-D.2 limits a contact-resolution response to one OTK; IV-E Step 8 and Token reuse bound an already issued ACT by expiration and `Q_max`. Appendix E A8 demonstrates accepted-but-bounded use of a valid ACT; the protocol does not claim to prevent the compromise itself. |
| **C3 - unregistered self-replicated child** | A parent Agent can create an unregistered child and share TLS keys, access-control keys, and existing ACTs with it. | Defined in III-D. IV-B Step 5 requires human verification before independent User/Agent registration, as evaluated by Appendix E A7. Appendix E A5 and IV-E Step 8 reject a Token when the presented initiator does not match its `PAC` binding, while A8 accepts a valid matching ACT until its limits. **Inference:** if a child uses all shared parent material successfully, the protocol can observe it as the parent's cryptographic identity and constrain it only through the same policy/ACT limits; the paper does not state that the protocol detects or removes the child. |
| **C4 - public-key, access-control-key, and Token sharing** | III-D says an adversarial Agent may share its “TLS public keys, access control keys, and access control tokens” with another adversary-controlled Agent. The security meaning of sharing TLS public keys alone is incomplete in the paper; this document leaves that wording as written rather than substituting different key material. | Defined in III-D. IV-E Step 6 verifies the Provider-signed initiating-Agent metadata and the OTK mapping; IV-E Step 8 checks the authenticated initiator's `PAC` binding, expiration, and quota. Appendix E A5 demonstrates rejection when the Token is bound to a different Agent, A6 demonstrates policy denial before OTK issuance, and A8 demonstrates accepted-but-bounded use when the presented Token is valid. |
| **C5 - Sybil identities** | An adversary may try to create Agents under multiple identities. | Accepted as an attempted capability in III-D. IV-B Step 5 and IV-F rely on unique registration plus trusted human verification to reject autonomous new identities. This is assumption-backed mitigation, not a cryptographic Sybil proof. Appendix E's A7 directly evaluates self-replication registration under C3; Table IV does not map an A1-A8 case to C5. |
| **C6 - network-level Dolev-Yao attacker** | The attacker can overhear, intercept, modify, replay, reorder, and synthesize arbitrary network messages, subject to the symbolic hardness of modeled cryptography. | Defined in III-D and analyzed in IV-F/Appendix D. ProVerif limits C6 through modeled secrecy and authentication correspondences. At runtime, III-C separately assumes TLS defeats network tampering, eavesdropping, and record replay. Appendix E describes message-level manipulation in its evaluation scope but Table IV's A1-A8 capability column does not assign a row to C6. |

## Evaluated Attack Models A1-A8

Appendix E reports implemented attacker evaluations. These are concrete detection/acceptance observations, not formal proofs.

| Model | Required capabilities in Appendix E | Attempt and exact protocol outcome |
|---|---|---|
| **A1** | C1, C2 | `M` contacts `A` without valid TLS credentials. The receiving Agent rejects the mutual-TLS handshake at IV-E Step 4. |
| **A2** | C1, C2 | `M` completes TLS but presents neither a valid OTK nor a prior ACT. `A` terminates at IV-E Step 6 because no valid access-control credential is present. |
| **A3** | C1, C2 | `M` presents an expired or quota-exhausted ACT. `A` rejects it at IV-E Step 8. The paper calls this Token replay, but the evaluated conditions are expiration and quota exhaustion, not detection of every semantically duplicate application request. |
| **A4** | C1, C2 | `M` combines a benign Agent's public data/Provider signature with `M`'s information. Provider-signature verification fails at IV-E Step 6 because the signed registered tuple does not match. |
| **A5** | C1, C2, C3, C4 | `M` presents an otherwise valid ACT issued to another Agent. At IV-E Step 8, `A` rejects the mismatch between the mTLS-authenticated initiator's registered `PAC` and the ACT's `PAC_B` binding. |
| **A6** | C1, C2, C3, C4 | `M` requests contact despite not being authorized by `A`'s Contact Policy. The Provider denies OTK issuance at IV-E Step 2. |
| **A7** | C3 | `M` tries to register copies of itself or other Agents. Human verification during User registration rejects autonomous registration at IV-B Step 5. This result depends on the trusted external identity assumption. |
| **A8** | C1, C2, C3, C4 | `M` contacts `A` with a valid ACT. The protocol accepts the connection under IV-E Token reuse; expiration and `Q_max` bound the accepted abuse window, and a later policy block prevents new OTK issuance. This is an accepted-and-limited attack state, not detection at first use. |

## Dolev-Yao Network Attacker

The formal attacker is C6. IV-F and Appendix D use the symbolic Dolev-Yao model: the attacker controls the public network and may observe, intercept, modify, replay, reorder, and synthesize messages, but cannot violate the equations and cryptographic hardness abstractions in the model. Appendix D models DH, signatures, symmetric encryption, hashing, and KDFs and constructs separate Agent-registration and Agent-communication models.

This formal attacker must not be conflated with either a malicious Provider or a runtime attacker that has broken TLS. The Provider is a protocol-following participant in the model, and III-C treats TLS security as an assumption. Symbolic constructors also do not prove that a selected library, serialization, nonce lifecycle, certificate configuration, database transaction, or secret erasure is correct.

## Formally Verified Properties

The paper reports ProVerif security results for only the following scope (IV-F; Appendix D):

1. **SAGA Token secrecy:** an attacker query tests whether the Dolev-Yao attacker can obtain the modeled Token term.
2. **Agent-Provider authentication:** injective event correspondences cover Agents authenticating Provider messages and the Provider authenticating Agents in the modeled registration/Provider interactions.
3. **Agent-Agent authentication:** event correspondences cover the two Agents' modeled communication.

These are symbolic protocol-model statements. They do not prove Contact Policy semantics, `Counter_OTK` or `q_max` atomicity, availability, secure deletion, malicious-Provider safety, TLS/library correctness, implementation memory safety, or the absence of implementation vulnerabilities.

Appendix D also runs reachability queries to check that the modeled events can occur. Reachability is a model executability/sanity check; it is not a fourth formally verified security property.

## Experimentally Evaluated Properties

Appendix E experimentally evaluates A1-A8: mutual-TLS rejection, missing OTK/ACT rejection, expired/exhausted ACT rejection, Provider-signature mismatch rejection, wrong-Agent ACT transfer rejection, Contact Policy denial, human-verification rejection of autonomous registration, and bounded acceptance of a valid ACT held by a malicious/compromised Agent.

Those cases show that the implementation used by the authors reached the listed detection or limiting points under the paper assumptions. They neither enumerate all behaviors admitted by C1-C6 nor establish formal completeness. In particular, A8 demonstrates an accepted vulnerability window, and A3 does not demonstrate general application-request deduplication.

## Properties Required by the Reproduction but Not Proved by the Paper

The reproduction requires engineering security tests for properties needed to implement the paper deterministically but not proved by it:

- deterministic serialization, strict Base64URL decoding, fixed integer time encoding, signature-input tamper rejection, HKDF domain separation, and AEAD nonce/ciphertext/AAD tamper rejection;
- real X.509 TLS/mTLS configuration, certificate mismatch/expiry rejection, timeout and interrupted-session handling, plus legal reuse of the same ACT after TLS reconnection as explicitly allowed by IV-E Token reuse;
- one linearizable Provider transaction for policy/active-state read, persistent pair-budget check/decrement, and exactly-one public OTK allocation;
- one fail-closed receiving-Agent transition for SOTK consumption and ACT creation, plus crash/persistence checks;
- persistent, atomic `< q_max` check-and-increment so `q_max=1` permits at most one concurrent success;
- IV-E Step 8's explicit checks: the authenticated initiator's registered `PAC` equals the ACT binding, current time is before expiration, and successful use count is below `q_max`;
- the reproduction's half-open interval `[issued_at, expires_at)` and separate future-issued/not-before rejection are engineering rules. IV-E Step 8 explicitly requires binding, expiration, and quota checks, but does not explicitly specify an independent future-issued check;
- stable fail-closed errors and secret-safe logging;
- deterministic Contact Policy tie rejection and policy-update counter migration;
- natural expiry/quota exhaustion for existing ACTs after policy update or deactivation, without a base-protocol revocation list.

Passing these tests provides engineering evidence about this reproduction. It does not expand the paper's ProVerif claims.

## Explicitly Out-of-Scope Threats

- an actively malicious or Byzantine Provider, Provider-key theft, malicious OTK issuance, policy bypass by the Provider, or registry equivocation;
- compromise, rollback, or unauthorized mutation of `D_U`, `D_A`, counters, or other trusted persistence below the protocol interface;
- compromise of the CA or external identity service, theft of benign-User credentials, or bypass of the assumed human-verification service;
- cryptographic primitive breaks, weak platform randomness, private-key extraction beyond C2-C4's specified credential possession/sharing cases, or TLS compromise;
- NAT traversal, local discovery, correctness of public routing, infrastructure DDoS/packet-flooding resistance, and general service availability;
- prevention, detection, remediation, or behavioral safety of a valid Agent after compromise; SAGA only limits capabilities and exposure under C2;
- application-semantic replay/deduplication, idempotency, and task binding. The base ACT has no request ID, idempotency key, or `task_id`;
- active revocation of issued ACTs, prompt-injection defenses, risk-adaptive authorization, Agent-to-Tool authorization, PBFT, RAFT, sharding, federation, and A2A integration in the base reproduction.

## Claim-Language Rules

Every report, test name, benchmark, and future verification artifact must label evidence as one of: **paper assumption**, **formal ProVerif result**, **Appendix E attacker evaluation**, or **reproduction engineering test**. Mixed evidence must be separated sentence by sentence.

The following statements are forbidden and must be replaced with bounded language:

| Forbidden overstatement | Required bounded wording |
|---|---|
| “ProVerif proves the Contact Policy implementation is correct.” | “ProVerif proves the listed secrecy/authentication correspondences for the symbolic registration and communication models; policy implementation is covered by engineering tests.” |
| “SAGA prevents compromise of a valid Agent.” | “SAGA accepts C2 compromise as possible and bounds some subsequent use through one-OTK issuance, ACT expiration, quota, and future policy denial.” |
| “SAGA detects all application-level replay.” | “TLS is assumed to mitigate network-record replay; SAGA rejects wrong-Agent, expired, and exhausted ACT use, while valid ACT reuse is intentional and semantic request deduplication is out of scope.” |
| “SAGA is secure against a malicious Provider.” | “The Provider follows protocol logic and may be honest-but-curious; actively malicious Provider behavior is out of scope.” |
| “Passing attack tests is a formal proof.” | “Passing attack tests is experimental or engineering evidence for the tested cases; formal claims are limited to the ProVerif queries.” |

No claim may silently promote an assumption into a guarantee, an A1-A8 observation into a universal defense, or an engineering decision into a paper-defined field or property.
