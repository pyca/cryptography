// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;

pub struct VerificationCertificate<'a, B: CryptoOps> {
    cert: Certificate<'a>,
    public_key: once_cell::sync::OnceCell<B::Key>,
    extra: B::CertificateExtra,
}

impl<'a, B: CryptoOps> VerificationCertificate<'a, B> {
    pub fn new(cert: Certificate<'a>, extra: B::CertificateExtra) -> Self {
        VerificationCertificate {
            cert,
            extra,
            public_key: once_cell::sync::OnceCell::new(),
        }
    }

    pub fn certificate(&self) -> &Certificate<'a> {
        &self.cert
    }

    pub fn public_key(&self, ops: &B) -> Result<&B::Key, B::Err> {
        self.public_key
            .get_or_try_init(|| ops.public_key(self.certificate()))
    }

    pub fn extra(&self) -> &B::CertificateExtra {
        &self.extra
    }
}

impl<B: CryptoOps> PartialEq for VerificationCertificate<'_, B> {
    fn eq(&self, other: &Self) -> bool {
        self.cert == other.cert
    }
}
impl<B: CryptoOps> Eq for VerificationCertificate<'_, B> {}

pub trait CryptoOps {
    /// A public key type for this cryptographic backend.
    type Key;

    /// An error type for this cryptographic backend.
    type Err;

    /// Extra data that's passed around with the certificate.
    type CertificateExtra;

    /// Extracts the public key from the given `Certificate` in
    /// a `Key` format known by the cryptographic backend, or `None`
    /// if the key is malformed.
    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err>;

    /// Verifies the signature on `Certificate` using the given
    /// `Key`.
    fn verify_signed_by(&self, cert: &Certificate<'_>, key: &Self::Key) -> Result<(), Self::Err>;
}

#[cfg(test)]
pub(crate) mod tests {
    use cryptography_x509::certificate::Certificate;

    pub(crate) fn v1_cert_pem() -> pem::Pem {
        pem::parse(
            "
-----BEGIN CERTIFICATE-----
MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV
BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz
MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM
RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO
/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE
Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ
zl9HYIMxATFyqSiD9jsx
-----END CERTIFICATE-----",
        )
        .unwrap()
    }

    pub(crate) fn cert(cert_pem: &pem::Pem) -> Certificate<'_> {
        asn1::parse_single(cert_pem.contents()).unwrap()
    }
}
