// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;

pub trait CryptoOps {
    /// A public key type for this cryptographic backend.
    type Key;

    /// An error type for this cryptographic backend.
    type Err;

    /// Extracts the public key from the given `Certificate` in
    /// a `Key` format known by the cryptographic backend, or `None`
    /// if the key is malformed.
    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err>;

    /// Verifies the signature on `Certificate` using the given
    /// `Key`.
    fn is_signed_by(&self, cert: &Certificate<'_>, key: Self::Key) -> Result<(), Self::Err>;
}

#[cfg(test)]
pub(crate) mod tests {
    use cryptography_x509::certificate::Certificate;

    use super::CryptoOps;

    pub(crate) struct NullOps {}
    impl CryptoOps for NullOps {
        type Key = ();

        fn public_key(&self, _cert: &Certificate<'_>) -> Option<Self::Key> {
            Some(())
        }

        fn is_signed_by(&self, _cert: &Certificate<'_>, _key: Self::Key) -> bool {
            true
        }
    }

    #[test]
    fn test_nullops() {
        // Arbitrary relatively small cert (v1_cert.pem from cryptography_vectors).
        let v1_cert = "
-----BEGIN CERTIFICATE-----
MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV
BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz
MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM
RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO
/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE
Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ
zl9HYIMxATFyqSiD9jsx
-----END CERTIFICATE-----";

        let cert_der = pem::parse(v1_cert.as_bytes()).unwrap().contents;
        let cert = asn1::parse_single::<Certificate<'_>>(&cert_der).unwrap();

        let ops = NullOps {};
        assert_eq!(ops.public_key(&cert), Some(()));
        assert!(ops.is_signed_by(&cert, ops.public_key(&cert).unwrap()));
    }
}
