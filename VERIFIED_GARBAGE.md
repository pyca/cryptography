# cryptography on verified-garbage

This branch (`vg-backend`) adds [verified-garbage](https://github.com/pyca/verified-garbage)
(VG) as an alternative crypto backend for cryptography. A VG build does not link
or depend on OpenSSL at all. OpenSSL remains the default backend, and an
OpenSSL build behaves exactly as before.

## Building and testing

* Build with `--no-default-features --features verified-garbage`.
* `nox -e local-verified-garbage` runs the full local check (format, lint,
  type-check, Python and Rust tests) on a VG build.
* `nox -e rust-verified-garbage` formats, lints and tests only the Rust code of
  a VG build.
* `nox -e local` now lints both builds.
* The Python-facing Rust module is still called `_rust.openssl` on VG builds,
  so no Python import paths changed.
* VG is a path dependency on `../verified-garbage`, so the build only works
  next to a checkout of that repository. A real release would use a git or
  crates.io dependency.

## Results

Full test suite, with Wycheproof (`--wycheproof-root`), on x86-64 with OpenSSL
3.0.13:

| Build | Passed | Skipped | Failed |
|---|---|---|---|
| verified-garbage | 4647 | 86 | 0 |
| OpenSSL | 4241 | 491 | 0 |
| OpenSSL, without Wycheproof (the baseline command) | 4109 | 630 | 0 |

The last row is the pre-branch baseline (4102 passed, 630 skipped) plus 7 new
regression tests.

The built VG extension links only libc and libgcc, and exports or imports no
OpenSSL symbols.

VG runs about 400 more tests than OpenSSL 3.0.13 does, because it implements
algorithms that version of OpenSSL lacks: ML-KEM, ML-DSA, Argon2, XOFHash,
AES-GCM-SIV, HPKE with ML-KEM, and the IDEA modes.

## Gaps in verified-garbage

Each of these raises `UnsupportedAlgorithm` on VG builds, and the tests that
need it are skipped on VG builds only (through `backend.*_supported()`
predicates).

* **EC**
  * No point decompression, so compressed (`02`/`03`) public keys are
    rejected.
  * No binary `sect*` curves.
  * VG pairs one hash with each curve for ECDSA (P-256 also has SHA-384).
    Other hashes work by re-encoding the digest into a native-hash value with
    the same `bits2int` integer (`ecdsa_input` in
    `src/rust/src/backend/vg/ec.rs`). This was checked by hand for every
    supported curve size, but deserves review.
  * Deterministic ECDSA is reported unsupported on VG, because exact RFC 6979
    is only possible for the native pairs.
  * VG's ECDSA signatures are always deterministic, never randomized.
* **RSA**
  * Only 512–8192-bit moduli and public exponents below 2^33 can be used for
    operations. Keys outside that range still load, but `verify`, `encrypt`
    and `recover_data_from_signature` raise `UnsupportedAlgorithm`.
  * Key generation sizes must be multiples of 128 bits.
  * `unsafe_skip_rsa_key_validation` cannot skip VG's own load-time checks.
  * PSS requires MGF1 over the signature's own hash, and has no SHA-3.
  * OAEP's MGF1 must use SHA-1 or the same hash as OAEP.
  * PKCS#1 v1.5 decryption always uses implicit rejection: bad padding returns
    a pseudo-random message instead of an error.
* **DSA**
  * No parameter generation.
  * Only four (p, q) sizes: 1024/160, 2048/224, 2048/256 and 3072/256 bits.
    This also blocks loading some test certificates and keys that use
    2048/160.
* **DH**
  * No primality check on p or q (OpenSSL tests them).
  * VG refuses a private key whose y is not g^x mod p, and a y of 1.
* **HMAC and PBKDF2**: only MD5, SHA-1 and SHA-2, so no SHA-3, BLAKE2 or
  SM3. This also limits HKDF, KBKDF and PKCS#12 MACs.
* **CMAC**: only AES and 3DES.
* **AES-GCM-SIV**: no 192-bit keys.
* **SM4-GCM**: not implemented.
* **AES-GCM**: decryption with tag lengths of 5–7 or 9–11 bytes is refused.
* **Single DES**: not implemented. Old encrypted PKCS#8 keys that use it are
  decrypted as 3DES with three equal keys, which is the same thing
  mathematically.
* **Platforms**: VG's RSA-OAEP and finite-field DH exist only on x86-64 and
  AArch64, so a VG build of cryptography works only there.

## Gaps on the cryptography side

* **No OpenSSL bindings**: `cryptography.hazmat.bindings.openssl.binding`
  raises `ImportError` on VG builds. pyOpenSSL and anything else that uses
  those bindings won't work.
* **DER only**: BER-encoded PKCS#12 and PKCS#7 files cannot be loaded,
  because the Rust ASN.1 parser that replaces OpenSSL's reads only DER.
* **PKCS#12 MACs**: PBMAC1 (RFC 9579) is not supported.
* **Test-only PKCS#7 verifier**: `test_support.pkcs7_verify` has a
  reimplemented VG version that checks less than OpenSSL's. It doesn't check
  validity periods or the S/MIME purpose, and builds only one level of chain.
* **Zeroization**: VG's routine for wiping secrets isn't public, so
  temporary seeds in cryptography's code are wiped on a best-effort basis.
* **Rust version**: the VG build needs Rust 1.88; cryptography's minimum is
  1.83.

## Open decisions

1. **DSA and DH keys loaded from PKCS#8** carry no public value y, and VG
   can't compute g^x mod p. It is currently computed with Python's `pow`,
   which is not constant time in the secret x, and VG then checks the result.
   (Upstream already calls `pow` the same way when validating DSA private
   numbers.) The alternative is refusing these keys on VG, which means no
   PKCS#8 DSA or DH private keys load at all.
2. **ML-DSA `sign_mu` / `verify_mu`** call VG functions that are hidden from
   its documentation (`sign_internal` / `verify_internal`, described as being
   for known-answer tests). Either VG makes them a supported API, or
   cryptography disables these two methods on VG builds.

## Bugs found that also affect the OpenSSL build

Fixed on this branch:

* An overflow panic in the scrypt memory error message for huge `n` and `r`.
* A panic in PKCS#12 serialization for unsupported `hmac_hash` choices; it
  now raises `UnsupportedAlgorithm`.

Not fixed (outside the VG code; worth reporting upstream):

* A deeply nested PBES2 key (about 10000 levels of `AlgorithmIdentifier`)
  crashes the interpreter with a stack overflow on both builds and on the
  released 50.0.2. The cause is unbounded recursion in the ASN.1 parsing.
* On the OpenSSL build, two inputs panic: a legacy PEM `DEK-Info` header with
  an 8-byte AES IV, and PBKDF2 iteration counts of 2^32 or more in encrypted
  PKCS#8 keys.

Three panics specific to VG were also found and fixed: AES-SIV with a list of
associated data, DH parameter serialization, and a stack overflow from deeply
nested PKCS#12 bags.
