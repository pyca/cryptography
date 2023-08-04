// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;

pub trait CryptoOps {
    /// A public key type for this cryptographic backend.
    type Key;

    /// Extracts the public key from the given `Certificate` in
    /// a `Key` format known by the cryptographic backend, or `None`
    /// if the key is malformed.
    fn public_key(&self, cert: &Certificate) -> Option<Self::Key>;

    /// Verifies the signature on `Certificate` using the given
    /// `Key`.
    fn is_signed_by(&self, cert: &Certificate, key: Self::Key) -> bool;
}
