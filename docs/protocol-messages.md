# SAGA Protocol Message Ledger

The ledger follows the main-text formulas in Sections IV-B-IV-E. Figures 7-9 are supporting protocol diagrams. `A` is the receiving Agent, `B` the initiating Agent, `U1` owns `A`, and `U2` owns `B`.

## User Registration (IV-B Steps 1-6; Figure 7)

| Step | Sender | Receiver | Message content | Cryptographic operation | Receiver verification | State transition | Paper evidence |
|---|---|---|---|---|---|---|---|
| IV-B.1 | User `U` (local) | User `U` | Choose `uid_U`, `passwd` | Secure generation/storage of passphrase is assumed | N/A | User account material prepared | IV-B Step 1; Fig. 7 |
| IV-B.2a | User `U` (local) | User `U` | `(PK_U, SK_U)` | `KeyGen()` | N/A | User signing key pair created | IV-B Step 2; Fig. 7 |
| IV-B.2b | CA | User `U` | `Cert_U = GenCert_SK_CA(<uid_U, PK_U>)` | CA signs `<uid_U, PK_U>` | User obtains CA-issued binding | User certificate available for registration | IV-B Step 2; Fig. 7 |
| IV-B.3a | CA / Provider | User `U` | Provider certificate, `PK_Prov` | Certificate issuance/validation | User verifies Provider certificate and public key | Provider trust anchor established | IV-B Step 3; Fig. 7 |
| IV-B.3b | User `U` | Provider | TLS handshake | TLS authentication/key establishment | Each endpoint performs TLS verification; paper explicitly states User verifies Provider identity | Confidential authenticated channel established | IV-B Step 3; Fig. 7 |
| IV-B.4 | User `U` | Provider | `(uid_U, passwd)`, `Cert_U` | Protected by TLS | Parse certificate and account data | Registration request pending | IV-B Step 4; Fig. 7 |
| IV-B.5 | External service `S` | Provider | Persistent identity/human-verification result | External authentication mechanism | Provider checks successful identity verification and account non-existence | Request accepted or rejected | IV-B Step 5; III-C; Fig. 7 |
| IV-B.6a | Provider (local) | `D_U` | `D_U[uid_U] = <H(passwd), Cert_U>` | `H(passwd)` in paper formula | N/A | User Registry entry created | IV-B Step 6; Fig. 7 |
| IV-B.6b | Provider | User `U` | Confirmation | TLS protection | User receives confirmation | User may register Agents | IV-B Step 6; Fig. 7 |

## Agent Registration (IV-C Steps 1-7; Figure 8)

| Step | Sender | Receiver | Message content | Cryptographic operation | Receiver verification | State transition | Paper evidence |
|---|---|---|---|---|---|---|---|
| IV-C.1 | User `U` (local) | User `U` | `aid_A = uid_U:name_A`; `ED_A = <device_A, IP_A, port_A>` | None | N/A | Candidate Agent identity/endpoint created | IV-C Step 1; Fig. 8 |
| IV-C.2a | User `U` / CA | Agent `A` | `(PK_A, SK_A)`; `Cert_A = GenCert_SK_CA(<aid_A, PK_A>)` | TLS key generation and CA signature | Certificate binding will be checked by Provider and peer Agents | Agent TLS credential created | IV-C Step 2; Fig. 8 |
| IV-C.2b | User `U` | Agent `A` | `(PAC_A, SAC_A)` | Access-control key generation | N/A | Long-term public/private access-control pair created | IV-C Step 2; Fig. 8 |
| IV-C.2c | User `U` | Agent `A` | `(OTK_A^1, SOTK_A^1), ..., (OTK_A^N, SOTK_A^N)` | One-time DH key generation | N/A | OTK/SOTK pool created | IV-C Step 2; Fig. 8 |
| IV-C.2d | User `U` | Provider and future initiators | `sigma_OTKi^U = Sign_SK_U(<aid_A, OTK_A^i>)` for each `i` | User signs exact two-field tuple | Provider and initiator verify with `PK_U` | Each public OTK is attributable to User/Agent | IV-C Steps 2, 6; IV-E Step 3; main text; Fig. 9. Fig. 8 visually omits `aid_A` from this signature |
| IV-C.2e | User `U` | Provider and future initiators | `sigma_A^U = Sign_SK_U(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>)` | User signs exact five-field tuple | Provider and initiator verify with `PK_U` | Agent metadata bound to User and Provider | IV-C Steps 2, 6; IV-E Step 3; Fig. 8-9 |
| IV-C.3 | User `U` (local) | User `U` | Contact policy `CP_A` | None | N/A | Policy prepared for registration | IV-C Step 3; Fig. 8 |
| IV-C.4a | User `U` | Provider | TLS handshake | TLS | Provider/User authenticate channel as specified | Registration channel established | IV-C Step 4; Fig. 8 |
| IV-C.4b | User `U` | Provider | `<uid_U, passwd>` | TLS-protected authentication | Provider verifies credentials against `D_U` | User authorized or rejected | IV-C Step 4; Fig. 8 |
| IV-C.5a | User `U` | Provider | `(aid_A, ED_A, CP_A)`, `Cert_A`, `PAC_A`, `{OTK_A^1, ..., OTK_A^N}`, `sigma_A^U`, and every `sigma_OTKi^U` | Previously created CA/User signatures | Provider parses complete submission | Registration transaction pending | IV-C Step 5 main text; Fig. 8 |
| IV-C.5b | User `U` (local provisioning) | Agent `A` | `(SK_A, SAC_A, {SOTK_A^1, ..., SOTK_A^N})` | Private-key transfer/storage | Agent retains private counterparts locally | Agent private state installed; never sent to Provider | IV-C Step 5 main text |
| IV-C.6 | Provider (local) | Provider | `aid_A`, `ED_A`, `Cert_A`, `sigma_A^U`, every `sigma_OTKi^U` | `Verify_PK_U(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>, sigma_A^U)`; `Verify_PK_U(<aid_A, OTK_A^i>, sigma_OTKi^U)` | Check global uniqueness of `aid_A`, `ED_A`; verify certificate and all signatures | Fail closed or proceed | IV-C Step 6; Fig. 8 |
| IV-C.7a | Provider (local) | `D_A` | `M_A = {ED_A, Cert_A, PAC_A, OTK_A^i, i in [1,N]}`; `D_A[aid_A] = <uid_U, M_A, CP_A, sigma_A^U, sigma_OTKi^U>` | None beyond verified inputs | N/A | Agent Registry entry created | IV-C Step 7; Fig. 8 |
| IV-C.7b | Provider | User `U` | `sigma_A^Prov = Sign_SK_Prov(<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>)` | Provider signs normative five-field main-text tuple | User stores Provider confirmation for initiating communication | Agent becomes registered; Provider signature retained | IV-C Step 7 main text; Figure 8 conflicts as documented below |

## Contact Resolution and OTK Allocation (IV-D; IV-E Steps 1-3)

| Step | Sender | Receiver | Message content | Cryptographic operation | Receiver verification | State transition | Paper evidence |
|---|---|---|---|---|---|---|---|
| IV-E.1 | Initiating Agent `B` | Provider | TLS handshake | TLS authentication/key establishment | Standard TLS certificate verification | Authenticated channel established | IV-E Step 1; Fig. 9 |
| IV-E.2a | Agent `B` | Provider | Request permission to contact: `aid_B`, `aid_A` | TLS protection | Provider identifies initiating and receiving entries | Contact-resolution transaction starts | IV-E Step 2 main text; Fig. 9 shows “Request to contact aid_A” |
| IV-D.1 / IV-E.2b | Provider (local) | Provider | `Budget_OTK(aid_A, aid_B)` using most-specific rule in `CP_A` | Policy evaluation | Require a matching/permitting policy result | Deny or continue | IV-D.1; Listing 1; IV-E Step 2; Fig. 9 |
| IV-D.2 / IV-E.2c | Provider (local) | Provider | `Counter_OTK[aid_A][aid_B]` | On first contact initialize to `Budget_OTK(aid_A, aid_B)`; require `> 0` | Check pair quota and overall OTK availability | Deny on quota/pool exhaustion or reserve one OTK | IV-D.2; IV-E Step 2; Fig. 9 |
| IV-E.2d | Provider | Agent `B` | `Cert_U1, (aid_A, ED_A), (Cert_A, PAC_A), OTK_A^i, sigma_OTKi^U1, sigma_A^U1` | Returns existing CA/User-signed material under TLS | `B` must perform Step 3 verifications | Exactly one public OTK issued; `Counter_OTK[aid_A][aid_B] -= 1` | IV-E Step 2; Fig. 9 |
| IV-E.3a | Agent `B` (local) | Agent `B` | `Cert_U1`, including `PK_U1`; `Cert_A` | Certificate validation | Verify CA bindings and extract public keys | Receiving identity accepted or request aborted | IV-E Step 3; Fig. 9 |
| IV-E.3b | Agent `B` (local) | Agent `B` | `sigma_A^U1` | `Verify_PK_U1(<aid_A, ED_A, PK_A, PAC_A, PK_Prov>, sigma_A^U1)` | Exact tuple must match returned metadata | Agent metadata accepted or aborted | IV-E Step 3; Fig. 9 |
| IV-E.3c | Agent `B` (local) | Agent `B` | `sigma_OTKi^U1` | `Verify_PK_U1(<aid_A, OTK_A^i>, sigma_OTKi^U1)` | Exact OTK/Agent binding must verify | OTK accepted or aborted | IV-E Step 3; Fig. 9; main-text typesetting contains a harmless trailing comma |

## Agent mTLS, DH, ACT Issuance, and ACT Use (IV-E Steps 4-8; Figure 9)

| Step | Sender | Receiver | Message content | Cryptographic operation | Receiver verification | State transition | Paper evidence |
|---|---|---|---|---|---|---|---|
| IV-E.4 | Agent `B` | Agent `A` | Agent-Agent TLS handshake using `Cert_B`, `Cert_A` | Mutual TLS | Both Agents verify the other's certificate | Direct authenticated channel established | IV-E Step 4; Fig. 9 |
| IV-E.5 | Agent `B` | Agent `A` | `<aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, OTK_A^i, sigma_B^Prov` | Message protected by TLS; signatures created at registration | `A` receives the registration attestation and selected OTK | Token request pending | IV-E Step 5; exact message shown in Fig. 9 |
| IV-E.6a | Agent `A` (local) | Agent `A` | `Cert_U2`, `sigma_B^Prov`, B's registration tuple | `Verify_PK_Prov(<aid_B, Cert_B, ED_B, PAC_B, sigma_B^U2>, sigma_B^Prov)` | Verify U2 certificate and Provider signature; mTLS already verifies `Cert_B` | B's registered identity accepted or request aborted | IV-E Step 6; Fig. 9 |
| IV-E.6b | Agent `A` (local) | Agent `A` | `OTK_A^i` | Lookup `OTK_A^i -> SOTK_A^i` | Mapping must exist and be unused | OTK accepted or request aborted | Fig. 9; IV-E Step 6 says “If OTK is valid” |
| IV-E.6c | Agent `B` (local) | Agent `B` | `SAC_B`, `OTK_A^i` | `DH_B = DH(SAC_B, OTK_A^i)`; `SDHK = KDF(DH_B)` | N/A | Initiator derives shared key | IV-E Step 6; Fig. 9 |
| IV-E.6d | Agent `A` (local) | Agent `A` | `SOTK_A^i`, `PAC_B` | `DH_A = DH(SOTK_A^i, PAC_B)`; `SDHK = KDF(DH_A)` | Equality follows DH relation | Receiver derives same shared key | IV-E Step 6; Fig. 9 |
| IV-E.6e | Agent `A` (local) | Agent `A` | `OTK_A^i -> SOTK_A^i` | Secure state deletion (abstractly) | N/A | Used secret OTK mapping deleted | Fig. 9, immediately after KDF |
| IV-E.7a | Agent `A` (local) | Agent `A` | `<N, T_issued, T_expire, Q_max, PAC_B>` | `N $<- R`; `token = Enc_SDHK(<N, T_issued, T_expire, Q_max, PAC_B>)` | N/A | Five-field ACT created/encrypted and receiver state stored | IV-E Step 7; Fig. 9 |
| IV-E.7b | Agent `A` | Agent `B` | `token` ciphertext | TLS transport plus `Enc_SDHK` | `B` stores opaque ciphertext; paper does not require B to validate plaintext | Initiator becomes Token holder | IV-E Step 7; Fig. 9 |
| IV-E.8a | Agent `B` | Agent `A` | Subsequent request with attached `token` | TLS; `A` decrypts/validates Token under `SDHK` | Verify Token was issued for B (`PAC_B`), is unexpired, and is below `Q_max` | Valid request accepted and usage advances; invalid request rejected | IV-E Step 8; “Token reuse”; Fig. 9 |
| IV-E.8b | Agents `A` and `B` (local) | Local state | Completed-task Token state/ciphertext | None | Task completion decision | Both parties discard Token | IV-E Step 8 |

## Policy Update and Agent Deactivation (IV-D)

| Step | Sender | Receiver | Message content | Cryptographic operation | Receiver verification | State transition | Paper evidence |
|---|---|---|---|---|---|---|---|
| IV-D update 1 | User `U` | Provider | Modified `CP_A`, including added/removed rules or a specific `B(.) = -1` deny rule | Authenticated Provider interface/TLS is implied by registered-User management | Provider must authenticate User and ownership of `A` | `CP_A` replaced/updated for future contact resolution | IV-D “Policy Updates and Revocation” |
| IV-D update 2 | User `U` | Provider | Fresh signed OTK batch for owned Agent | User signatures on OTKs follow `sigma_OTKi^U = Sign_SK_U(<aid_A, OTK_A^i>)` | Provider verifies ownership/signatures as registration semantics require | Public OTK pool replenished; pair-counter reset semantics are not specified | IV-D.2 and key management |
| IV-D deactivate | User `U` | Provider | Request to deactivate owned `aid_A` | Authenticated Provider interface/TLS is implied | Provider verifies that `U` owns `A`; requests against other Users' Agents must fail | New incoming contact/discovery disabled | IV-D “Policy Updates and Revocation” |

The paper does not define a concrete wire tuple, signature, response, transaction order, effect on initialized pair counters, or retroactive ACT invalidation for these management actions. Reproduction choices must remain classified in [the matrix](feature-source-matrix.md).

## Signature Ledger

| Signer | Exact signed tuple | Verification key | Verifier | Usage step |
|---|---|---|---|---|
| External CA | `<uid_U, PK_U>` in `Cert_U = GenCert_SK_CA(<uid_U, PK_U>)` | CA public key | User, Provider, and peer Agent as applicable | IV-B Step 2; IV-E Steps 3 and 6 |
| External CA | `<aid_A, PK_A>` in `Cert_A = GenCert_SK_CA(<aid_A, PK_A>)` | CA public key | Provider and peer Agents | IV-C Steps 2 and 6; IV-E Steps 3-4 |
| User `U` | `<aid_A, ED_A, PK_A, PAC_A, PK_Prov>` in `sigma_A^U` | `PK_U` from `Cert_U` | Provider; initiating Agent | IV-C Steps 2 and 6; IV-E Step 3 |
| User `U` | `<aid_A, OTK_A^i>` in `sigma_OTKi^U` | `PK_U` from `Cert_U` | Provider; initiating Agent | IV-C Steps 2 and 6; IV-E Step 3 |
| Provider | `<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>` in `sigma_A^Prov` | `PK_Prov` | Receiving Agent when `A` later initiates as `B`; User stores confirmation | IV-C Step 7; IV-E Steps 5-6 |

`sigma_A^U` includes `PK_Prov`, binding registration to the named Provider. `sigma_A^Prov` embeds the User signature, so the receiver verifies a Provider attestation over both Agent registration data and its User attribution.

## DH Ledger

| Party | Private input | Peer/public input | Paper computation | Reproduction instantiation | Result |
|---|---|---|---|---|---|
| Initiating `B` | `SAC_B` | `OTK_A^i` | `DH_B = DH(SAC_B, OTK_A^i)` | `X25519(SAC_B, OTK_A^i)` | `SDHK = KDF(DH_B)` |
| Receiving `A` | `SOTK_A^i` | `PAC_B` | `DH_A = DH(SOTK_A^i, PAC_B)` | `X25519(SOTK_A^i, PAC_B)` | `SDHK = KDF(DH_A)` |

Required equality: `X25519(SAC_B, OTK_A^i) = X25519(SOTK_A^i, PAC_B)`, hence `KDF(DH_B) = KDF(DH_A) = SDHK`. X25519 is the approved reproduction instantiation; the IV-E formula is expressed abstractly as `DH`.

## Token Ownership Ledger

| State/action | Owner | Exact responsibility | Evidence |
|---|---|---|---|
| ACT plaintext creation | Receiving Agent `A` | Chooses `N`, `T_issued`, `T_expire`, `Q_max`, and binds `PAC_B` | IV-E Step 7; Fig. 9 |
| Encryption | Receiving Agent `A` | Computes `token = Enc_SDHK(<N, T_issued, T_expire, Q_max, PAC_B>)` | IV-E Step 7; Fig. 9 |
| Authoritative Token/use state | Receiving Agent `A` | Stores Token state, decrypts/verifies later presentation, enforces identity, expiry, and quota | IV-E Steps 7-8; Fig. 9 |
| Ciphertext possession | Initiating Agent `B` | Stores the opaque `token` returned by A and attaches it to subsequent requests | IV-E Steps 7-8; “Token reuse” |
| Discard | Both `A` and `B` | Discard Token when the task completes | IV-E Step 8 |

The Provider neither creates nor stores the ACT. `B` is a ciphertext holder, not the authoritative verifier. `A` creates/encrypts/stores state and verifies subsequent use.

## Normative inconsistency: IV-C Step 7 versus Figure 8

IV-C Step 7 gives the Provider signature as:

```text
sigma_A^Prov = Sign_SK_Prov(<aid_A, Cert_A, ED_A, PAC_A, sigma_A^U>)
```

Appendix Figure 8 visibly gives:

```text
sigma_A^Prov = Sign_SK_Prov(<Cert_U, ED_A, PAC_A, sigma_A^U>)
```

Figure 8 therefore substitutes `Cert_U` for the main text's leading `aid_A, Cert_A` fields. In addition, Figure 8 displays `sigma_OTKi^U = Sign_SK_U(OTK_A^i)`, while IV-C Step 2 and IV-E Step 3 use `<aid_A, OTK_A^i>`. Under the approved source order, explicit main-text formulas govern. The reproduction uses the IV-C Step 7 Provider tuple and the IV-C Step 2 OTK tuple, retains this ambiguity record, and does not let the authors' implementation override the paper.

A separate transport omission remains unresolved in the paper: IV-E Step 6 says that `A` verifies `U2`'s certificate, but the Step 5 prose and Figure 9 request tuple do not explicitly carry `Cert_U2`. This ledger records the required verification without silently adding `Cert_U2` to the normative Figure 9 tuple; the implementation plan must classify any certificate-retrieval mechanism as an engineering decision unless stronger paper evidence is found.
