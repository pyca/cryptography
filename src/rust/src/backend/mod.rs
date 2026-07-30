// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Minimum input size before hash/HMAC/cipher operations detach from the
// interpreter (release the GIL) so other threads can run. Detaching and
// re-attaching has a fixed cost, so it is a net loss for small inputs.
// CPython's hashlib uses the same approach with a 2048-byte cutoff.
pub(crate) const GIL_DETACH_THRESHOLD: usize = 2048;

pub(crate) mod aead;
pub(crate) mod cipher_registry;
pub(crate) mod ciphers;
pub(crate) mod cmac;
pub(crate) mod dh;
pub(crate) mod dsa;
pub(crate) mod ec;
pub(crate) mod ed25519;
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
pub(crate) mod ed448;
pub(crate) mod hashes;
pub(crate) mod hmac;
pub(crate) mod hpke;
pub(crate) mod kdf;
pub(crate) mod keys;
pub(crate) mod keywrap;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
pub(crate) mod mldsa;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
pub(crate) mod mlkem;
pub(crate) mod poly1305;
pub(crate) mod rand;
pub(crate) mod rsa;
pub(crate) mod utils;
pub(crate) mod x25519;
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
pub(crate) mod x448;
