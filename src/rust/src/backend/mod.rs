// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Minimum input size before hash/HMAC/cipher operations detach from the
// interpreter (release the GIL) so other threads can run. Detaching and
// re-attaching has a fixed cost, so it is a net loss for small inputs.
// CPython's hashlib uses the same approach with a 2048-byte cutoff.
pub(crate) const GIL_DETACH_THRESHOLD: usize = 2048;

/// Runs `f` with the GIL released if `len` is at least
/// `GIL_DETACH_THRESHOLD`, and attached otherwise. `f` must not touch any
/// Python objects.
pub(crate) fn run_with_gil_detached<T, F>(py: pyo3::Python<'_>, len: usize, f: F) -> T
where
    T: pyo3::marker::Ungil,
    F: pyo3::marker::Ungil + FnOnce() -> T,
{
    if len >= GIL_DETACH_THRESHOLD {
        py.detach(f)
    } else {
        f()
    }
}

#[cfg(feature = "openssl")]
pub(crate) mod aead;
#[cfg(feature = "openssl")]
pub(crate) mod cipher_registry;
#[cfg(feature = "verified-garbage")]
#[path = "vg/cipher_registry.rs"]
pub(crate) mod cipher_registry;
pub(crate) mod ciphers;
#[cfg(feature = "openssl")]
pub(crate) mod cmac;
#[cfg(feature = "openssl")]
pub(crate) mod dh;
#[cfg(feature = "verified-garbage")]
#[path = "vg/dh.rs"]
pub(crate) mod dh;
#[cfg(feature = "openssl")]
pub(crate) mod dsa;
#[cfg(feature = "verified-garbage")]
#[path = "vg/dsa.rs"]
pub(crate) mod dsa;
#[cfg(feature = "openssl")]
pub(crate) mod ec;
#[cfg(feature = "verified-garbage")]
#[path = "vg/ec.rs"]
pub(crate) mod ec;
#[cfg(feature = "openssl")]
pub(crate) mod ed25519;
#[cfg(feature = "verified-garbage")]
#[path = "vg/ed25519.rs"]
pub(crate) mod ed25519;
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
#[cfg(feature = "openssl")]
pub(crate) mod ed448;
#[cfg(feature = "verified-garbage")]
#[path = "vg/ed448.rs"]
pub(crate) mod ed448;
pub(crate) mod hashes;
pub(crate) mod hmac;
#[cfg(feature = "openssl")]
pub(crate) mod hpke;
#[cfg(feature = "openssl")]
pub(crate) mod kdf;
pub(crate) mod keys;
#[cfg(feature = "openssl")]
pub(crate) mod keywrap;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
#[cfg(feature = "openssl")]
pub(crate) mod mldsa;
#[cfg(feature = "verified-garbage")]
#[path = "vg/mldsa.rs"]
pub(crate) mod mldsa;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
#[cfg(feature = "openssl")]
pub(crate) mod mlkem;
#[cfg(feature = "verified-garbage")]
#[path = "vg/mlkem.rs"]
pub(crate) mod mlkem;
#[cfg(feature = "openssl")]
pub(crate) mod poly1305;
#[cfg(feature = "openssl")]
pub(crate) mod rand;
#[cfg(feature = "openssl")]
pub(crate) mod rsa;
#[cfg(feature = "verified-garbage")]
#[path = "vg/rsa.rs"]
pub(crate) mod rsa;
pub(crate) mod utils;
#[cfg(all(test, feature = "verified-garbage"))]
#[path = "vg/test_vectors.rs"]
mod vg_test_vectors;
#[cfg(feature = "openssl")]
pub(crate) mod x25519;
#[cfg(feature = "verified-garbage")]
#[path = "vg/x25519.rs"]
pub(crate) mod x25519;
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
#[cfg(feature = "openssl")]
pub(crate) mod x448;
#[cfg(feature = "verified-garbage")]
#[path = "vg/x448.rs"]
pub(crate) mod x448;
