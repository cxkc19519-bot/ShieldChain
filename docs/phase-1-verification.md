# SAGA Phase 1 Verification

## 1. Completed work
- Scope: canonical encoding, four paper tuples, Ed25519, X25519, HKDF, AEAD, scrypt, X.509 validation.
- Phase boundary: library/vector behavior only.
- Public surfaces are frozen as the exact `saga.domain` and `saga.crypto` tuples tested in `tests/unit/test_public_api.py`; password persistence remains available only from `saga.crypto.passwords`.
- This implementer executed no Git command. Git diff/status evidence, the independent whole-branch review, and the restricted commit remain controller-owned gates.

## 2. Files created/modified
| Path | Action | Responsibility |
|---|---|---|
| `src/saga/domain/__init__.py` | modified | Freeze the five-name domain convenience surface. |
| `src/saga/crypto/__init__.py` | modified | Freeze the 37-name cryptographic convenience surface without password exports. |
| `tests/unit/test_public_api.py` | created | Enforce exact domain, crypto, and password-submodule exports. |
| `tests/unit/test_phase_one_scope.py` | created | Reject runtime and protocol-layer packages during Phase 1. |
| `docs/feature-source-matrix.md` | modified | Record seven Task 10 Phase 1 engineering supplements while preserving the other columns. |
| `docs/phase-1-verification.md` | created | Preserve the ten-part Phase 1 implementation evidence and acceptance boundary. |

## 3. Paper/source-matrix mapping
| Mechanism | Paper location | Engineering supplement | Test evidence |
|---|---|---|---|
| Canonical four-tuple encoding | IV-C Steps 2, 6-7; IV-E Step 7 | Deterministic UTF-8 JSON, closed schemas, fixed field order | `tests/unit/test_protocol_tuples.py::test_all_canonical_tuple_vectors_are_consumed` |
| Ed25519 signatures | III signatures; IV-B-C | Mature-library Ed25519 wrapper; raw 32-byte public keys | `tests/unit/test_signatures.py::test_all_signature_vectors_are_consumed` |
| X25519 agreement | IV-E Step 6; Fig. 9 | X25519 with raw 32-byte PAC/OTK public values | `tests/unit/test_key_agreement.py::test_all_x25519_vectors_are_consumed` |
| SDHK derivation | III KDF background; IV-E Step 6; Fig. 9 | Fixed-domain HKDF-SHA256 with 32-byte output | `tests/unit/test_kdf.py::test_all_hkdf_vectors_are_consumed` |
| ACT authenticated encryption | IV-E Step 7; Fig. 9 | ChaCha20-Poly1305, fixed AAD, closed versioned envelope | `tests/unit/test_aead.py::test_all_aead_vectors_are_consumed` |
| Password record | IV-B Steps 5-6; IV-D key management; Fig. 7 | Versioned redacted scrypt record on a separate persistence surface | `tests/unit/test_passwords.py::test_all_scrypt_vectors_are_consumed` |
| Certificate validation | IV-B Step 2; IV-C Steps 1-2, 5-6; IV-E Steps 3-6 | Single-root URI-SAN profile with strict BC/KU/EKU, SPKI binding, and half-open validity | `tests/unit/test_certificates.py::test_all_identity_profiles_validate` |
| Public API and phase boundary | Phase 1 release gate | Exact export tuples and no runtime/protocol packages | `tests/unit/test_public_api.py`; `tests/unit/test_phase_one_scope.py` |

## 4. Engineering decisions used
| Decision | Exact value | Classification |
|---|---|---|
| Canonical encoding | Deterministic JSON, UTF-8, fixed field order, closed schemas, no floating-point security fields | 复现工程补充 |
| Signature algorithm | Ed25519; raw public key length 32 bytes | 复现工程补充 |
| Key agreement | X25519; raw PAC/OTK public key length 32 bytes | 复现工程补充 |
| KDF | HKDF-SHA256, `salt=None`, `info=b"SAGA-ACT-DERIVE/v1"`, output length 32 bytes | 复现工程补充 |
| AEAD | ChaCha20-Poly1305 with `aad=b"SAGA-ACT/v1"` | 复现工程补充 |
| ACT envelope | Version and 12-byte AEAD nonce remain outside the exact five-field plaintext | 复现工程补充 |
| Password record | scrypt `N=2^15`, `r=8`, `p=1`, `dkLen=32`, fresh 16-byte salt | 复现工程补充 |
| Certificate profile | One Ed25519 trust anchor; URI SAN identity; exact BC/KU/EKU; SPKI binding; half-open validity | 复现工程补充 |
| Binary and time encoding | Strict unpadded Base64URL and nonnegative integer Unix milliseconds | 复现工程补充 |

## 5. Commands executed
| Command | UTC timestamp | Exit code |
|---|---|---:|
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py tests/unit/test_phase_one_scope.py -q` before exports | observed after test writes at 2026-07-16T10:24:51Z and before implementation writes at 2026-07-16T10:25:28Z | 1 |
| `.\.venv\Scripts\ruff.exe format src tests` | 2026-07-16T10:26:26Z | 0 |
| `.\.venv\Scripts\python.exe -m pytest tests/unit -q` | 2026-07-16T10:26:42Z | 0 |
| `.\.venv\Scripts\python.exe -m mypy src` | 2026-07-16T10:26:41Z | 0 |
| `.\.venv\Scripts\ruff.exe check src tests` | 2026-07-16T10:26:42Z | 0 |
| `.\.venv\Scripts\ruff.exe format --check src tests` | 2026-07-16T10:26:41Z | 0 |
| `.\.venv\Scripts\python.exe -m pip check` | 2026-07-16T10:26:41Z | 0 |
| `rg -ni --hidden 'BEGIN[[:space:]].*PRIVATE KEY\|PRIVATE KEY-----\|never-log-me\|correct horse' src tests/vectors` | 2026-07-16T10:28:09Z | 1, expected no-match result |
| `rg -ni --hidden '"(password\|private_key\|secret\|seed)"[[:space:]]*:' tests/vectors` | 2026-07-16T10:28:09Z | 1, expected no-match result |
| Six-path `Compare-Object` followed by `.\.venv\Scripts\python.exe -m pytest tests/unit -q` | 2026-07-16T10:27:37Z | 0 |
| `rg -n "Ed25519\|X25519\|HKDF\|ChaCha20Poly1305\|Scrypt\|x509" src/saga/crypto` | 2026-07-16T10:27:07Z | 0 |
| `rg -n "def .*sha\|def .*curve\|def .*poly1305\|modular\|scalar" src/saga/crypto` | 2026-07-16T10:27:07Z | 0, two benign wrapper-name matches audited below |
| `.\.venv\Scripts\python.exe -m pip freeze --all --exclude-editable` | 2026-07-16T10:27:07Z | 0 |
| Normalized freeze creation and case-sensitive raw comparison with `requirements.lock` | 2026-07-16T10:27:50Z | 0 |
| `rg -ni "(^-e\|file:\|[A-Z]:\\\|SAGA，A Security)" requirements.lock` | 2026-07-16T10:27:07Z | 1, expected no-match result |
| Exact Task 9/10 matrix-row and four-column-header audit against the two task briefs | 2026-07-16T10:29:30Z | 0 |
| `.\.venv\Scripts\python.exe -m pytest tests/unit/test_public_api.py tests/unit/test_phase_one_scope.py -q` after exports | 2026-07-16T10:29:46Z | 0 |

## 6. Test results with exact counts and exit codes
| Gate | Passed | Failed | Skipped | Exit code |
|---|---:|---:|---:|---:|
| TDD RED focused pytest | 2 | 2 | 0 | 1 |
| TDD GREEN focused pytest | 4 | 0 | 0 | 0 |
| Complete unit pytest | 260 | 0 | 0 | 0 |
| Fresh vector-set/loader pytest | 260 | 0 | 0 | 0 |
| mypy | 11 source files | 0 | n/a | 0 |
| Ruff check | all checks | 0 | n/a | 0 |
| Ruff format | 2 reformatted, 23 unchanged | 0 | n/a | 0 |
| Ruff format check | 25 formatted files | 0 | n/a | 0 |
| pip check | no broken requirements | 0 | n/a | 0 |

The six-vector collection gate observed 6 expected paths, 6 actual paths, and 0 differences. Loader ownership is executable, not visual: canonical, Ed25519, X25519, HKDF, AEAD, and scrypt owning tests each assert exact document/record keys and `seen == expected_names`; all are included in both 260-test passes.

Both secret scans observed 0 matches. The primitive ownership scan resolves Ed25519, X25519, HKDF, ChaCha20-Poly1305, scrypt, and X.509 calls to `cryptography`. The custom-primitive regex produced exactly two benign matches, `derive_sdhk(shared_secret)` and `derive_shared_secret(...)`, because `.*sha` also matches the word `shared`; inspection confirms both are wrappers over `cryptography`, not SHA/curve/Poly1305 implementations. No modular arithmetic or scalar implementation was found.

The dependency audit observed 18 freeze lines and 18 lock lines with a case-sensitive raw equality result of true. The editable/path scan observed 0 matches. The ignored mechanical scratch is `.superpowers/sdd/phase1-freeze.normalized.txt` and is outside the commit set.

The matrix audit compared all seven Task 10 replacement rows byte-for-byte with `task-10-brief.md`, all three Task 9 certificate rows byte-for-byte with `task-9-brief.md`, confirmed one exact four-column header, and counted exactly ten Phase 1 supplement rows.

## 7. Unresolved paper limitations
- ACT has no task field; no request-level replay detection is claimed.
- ACT reuse is intentionally legal until expiry or `q_max` exhaustion; Phase 1 does not define request IDs, idempotency keys, or semantic deduplication.
- The Phase 1 certificate boundary validates the closed single-root profile; it does not implement general PKIX path building, revocation, or multi-anchor trust.
- Phase 1 contains library/vector behavior only, so no registry, Contact Policy, OTK lifecycle, ACT lifecycle, transport, or persistence behavior is claimed.

## 8. Known differences from the paper
- Concrete algorithms, canonical encoding, certificate profile, AAD and KDF domain are engineering supplements.
- Raw Ed25519/X25519 key encodings, strict Base64URL, integer Unix milliseconds, the closed outer ACT envelope, and the scrypt record parameters are also engineering supplements.
- Certificate/TLS-key members of canonical tuples remain opaque bytes; DER parsing and profile validation occur only at the separate certificate boundary.

## 9. Phase 2 plan boundary
- Authorized next action after acceptance: plan User and Agent registration.
- Not authorized: Contact Policy, OTK state, ACT lifecycle, mTLS service, attacks, ProVerif, performance, baseline tag, or innovation branch.

## 10. User acceptance question
Do you accept Phase 1 evidence and authorize Phase 2 planning?
