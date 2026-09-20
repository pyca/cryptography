# Reviewing the OpenSSL bridge integration

Review the final implementation by dependency boundary, with each boundary's
callers and tests beside it. The original import commit is too broad to be a
useful review unit, and reviewing its later fixes separately makes reviewers
reconstruct code that has already been replaced.

The reference integration is `f6db46397a8f38caa521d77d5f16a3e69fdec2b2`.
Its [CI run](https://github.com/pyca/cryptography/actions/runs/35423202758)
passed all 69 jobs and the aggregate 100% coverage gate. This is evidence for
that revision; subsequent changes need their own full CI result.

## Review order

Paths below are relative to the repository root unless linked. These are review
units of one integrated change, **not claims that intermediate commits build**.

| Unit | Implementation and callers | Review question and evidence |
| --- | --- | --- |
| 1. Native build and linkage | `openssl-bridge-sys/{build.rs,wrapper.h,shim.c}` under `src/rust/`; workspace manifests; build scripts and `cryptography-cffi` | Do generated declarations, configuration flags, target C types, and CFFI all describe the same installed library? Read [native link identity](SAFETY.md#native-link-identity) with the platform, fork, minimal-feature, and MSRV CI jobs. |
| 2. Ownership and shared contracts | [lib.rs](src/lib.rs), [error.rs](src/error.rs), [secret.rs](src/secret.rs), [encoding.rs](src/encoding.rs), [number.rs](src/number.rs), [runtime.rs](src/runtime.rs) | Who owns each allocation, what gets erased, and how are native status/length results interpreted? Read inline unit tests plus `tests/initialization.rs` and `tests/validation.rs`. Keep error-queue compatibility separate from operation success. |
| 3. Symmetric operations | `hash`, `mac`, `kdf`, `argon2`, `cipher`, `gcm`, `aead`, `poly1305`, `rand`; matching `src/rust/src/backend/` adapters and `cryptography-crypto` | Are bounds and operation order checked before FFI, and do failures preserve poisoning and output cleanup? Pair bridge tests with cryptography's primitive tests, Fernet, key wrapping, and password-based encryption callers. |
| 4. Typed keys and serialization | `rsa`, `ec`, `dh`, `dsa`, `curve25519`, `curve448`, `pq`, `mldsa`, `mlkem`; `cryptography-key-parsing`; matching Python key adapters | Does parsing preserve existing accepted encodings without accidentally granting permission to use malformed keys? Review each algorithm vertically through parsing, validation, operations, serialization, and its negative/known-answer tests. Include Wycheproof and the bridge PQ vectors. |
| 5. Native compatibility containers | [containers.rs](src/containers.rs), [legacy_key.rs](src/legacy_key.rs), [pkcs7.rs](src/pkcs7.rs), [x509.rs](src/x509.rs); `src/rust/src/{pkcs12.rs,pkcs7.rs,pyopenssl.rs}` | Keep decoding separate from trust and key validation. Check private export cleanup, trailing-data behavior, trust-store updates, legacy passwords, and their Rust/Python regressions. |
| 6. TLS and pyOpenSSL | [tls.rs](src/tls.rs), `src/tls/` children; `src/rust/src/pyopenssl/tls.rs`; Python stubs; `.github/patches/pyopenssl.patch` | Follow context construction, callbacks, connection state, and transport ownership in that order. Read [TLS invariants](SAFETY.md#tls-callbacks-and-pyopenssl), `tests/tls.rs`, `tests/hazmat/bindings/test_pyopenssl.py`, and the patched downstream suite together. |
| 7. Integration acceptance | `.github/workflows/ci.yml`, downstream scripts, `noxfile.py`, `.github/bin/merge_rust_coverage.py`, `tests/test_rust_coverage.py` | Confirm the same backends, downstream consumers, and coverage producers remain required. Review every exclusion's stated native invariant; 100% of measured code is not proof that excluded paths were executed. |

Keep tests with their implementation unit; do not defer their review to a final
"tests" patch. Likewise, Python exception translation and negative tests belong
beside the Rust operations whose errors they translate. The shared `buf.rs` and
`error.rs` changes in `src/rust/src/` affect several units and deserve an explicit
cross-cutting pass ([buffer contract](SAFETY.md#python-buffer-boundary)).

## Why not an additive migration stack?

`openssl-bridge-sys` and the original `openssl-sys` both declare
`links = "openssl"`. Cargo cannot resolve both in the same dependency graph.
Simply adding the new crate to the existing workspace and switching callers one
at a time therefore does not produce a buildable stack. Renaming the link key
would also remove the guard that keeps CFFI and Rust on a single native ABI.

Keep the dependency replacement, build metadata, typed-key parsing, and callers
as an atomic cutover. Use the units above to divide review responsibility. The
coverage-parser fix and its tests can be considered separately, but splitting
the actual backend switch requires additional migration machinery and fresh
validation; the existing green result cannot be attached to invented slices.

The pyOpenSSL migration is a distinct review unit, but its coverage job must stay
attached to the integrated head. Only `pyopenssl-bridge` instruments this typed
adapter and contributes its Rust profiles to the aggregate gate. The unmodified
`pyopenssl` and `pyopenssl-release` jobs verify retained CFFI compatibility.
Moving the companion patch to a pyOpenSSL PR later requires keeping the downstream
job pointed at that exact migration revision, not dropping the job or its profiles.

## Simplifications made here

- `secret::Secret<N>` owns fixed-size secret bytes alongside `SecretBytes`.
  Curve448, ML-DSA, and ML-KEM no longer depend on the Curve25519 module for a
  storage type. Both owners and cipher/RSA scratch cleanup use `secret::erase`.
  The fixed sizes, drop behavior, and absence of implicit `Clone`/`Debug` remain.
- Native DER encoding now lives in a private `encoding` module rather than the
  public X.509 compatibility module. Callers choose public or secret output;
  the allocator callback is private, so callers no longer carry its exact-size
  safety obligation. The length/cursor regression test moved with the helper.
- PKCS#12 certificate export returns its public DER allocation directly. Private
  key exports still use erased storage; public certificate bytes no longer pass
  through a secret buffer followed by a second allocation and copy.

These changes do not alter the native shim, backend selection, Python behavior,
operation state machines, test vectors, test skips, or coverage exclusions.

## API distinctions to retain

| Tempting reduction | Why it would make the contract harder to review |
| --- | --- |
| One generic native key with an algorithm id | Reintroduces independent key/type assertions at every call. Algorithm-specific roles and borrowed serialization views make mismatches explicit in Rust. |
| Merge DSA/DH material and operational key types | Legacy malformed encodings may round-trip, but signing/agreement requires validation. Material has no cryptographic methods; that boundary is intentional. |
| One AEAD interface for streaming and one-shot decryption | `aead::Key::open_into` withholds plaintext until authentication. `UnverifiedGcmDecrypt` exposes unauthenticated streaming output for existing Python semantics. The difference belongs in the type and method names. |
| One RSA padding enum for all operations | Signing, verification, and encryption have different admissible parameters. Keep those domains separate, including verification-only salt policies. |
| Replace all BIO owners with one shared wrapper | X.509/TLS's writable memory BIOs are erased on drop. PKCS#7 also uses borrowed-input BIOs; applying the writable-buffer destructor would violate ownership assumptions. |
| Generate every algorithm wrapper with macros | Backend support, native ownership, and failure ordering differ. Sharing a small bounded helper is easier to audit than hiding those differences behind a generic framework. |

`rsa::Plaintext` could eventually share storage with `SecretBytes`, but that is
less valuable than the changes above: it would need an explicit truncation and
erasure contract. Keep that separate from the module moves. Likewise, raw TLS
option masks and legacy X.509 helpers are compatibility requirements until the
companion pyOpenSSL API changes; removing them only moves complexity to callers.

## Acceptance after any split or simplification

Run `nox -e local` with the pinned Wycheproof and x509-limbo corpora. A local
system-OpenSSL pass is only one part of acceptance. Require a new full CI run on
the final commit, retaining:

- OpenSSL versions, FIPS, minimal-feature and both no-legacy configurations;
  LibreSSL 4.2.1/4.3.2, pinned BoringSSL, and AWS-LC 5.9.0.
- Rust/MSRV and platform jobs, including free-threaded Python and downstream
  compatibility jobs.
- Bridge unit/integration/documentation tests, cryptography's existing suites,
  unmodified pyOpenSSL, released pyOpenSSL, and patched pyOpenSSL.
- The aggregate 100% gate, downstream Rust profile upload, existing exclusion
  boundaries, and malformed-exclusion rejection tests.

Do not lower the threshold, add exclusions, or drop downstream coverage to make
an intermediate review slice appear independently green.
