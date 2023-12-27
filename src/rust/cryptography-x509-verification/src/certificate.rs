// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Validation-specific certificate functionality.

use cryptography_x509::certificate::Certificate;

pub(crate) fn cert_is_self_issued(cert: &Certificate<'_>) -> bool {
    cert.issuer() == cert.subject()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::cert_is_self_issued;
    use crate::certificate::Certificate;
    use crate::ops::tests::{cert, v1_cert_pem};
    use crate::ops::CryptoOps;

    #[test]
    fn test_certificate_v1() {
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);

        assert!(!cert_is_self_issued(&cert));
    }

    fn ca_pem() -> pem::Pem {
        // From vectors/cryptography_vectors/x509/custom/ca/ca.pem
        pem::parse(
            "-----BEGIN CERTIFICATE-----
MIIBUTCB96ADAgECAgIDCTAKBggqhkjOPQQDAjAnMQswCQYDVQQGEwJVUzEYMBYG
A1UEAwwPY3J5cHRvZ3JhcGh5IENBMB4XDTE3MDEwMTEyMDEwMFoXDTM4MTIzMTA4
MzAwMFowJzELMAkGA1UEBhMCVVMxGDAWBgNVBAMMD2NyeXB0b2dyYXBoeSBDQTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBj/z7v5Obj13cPuwECLBnUGq0/N2CxS
JE4f4BBGZ7VfFblivTvPDG++Gve0oQ+0uctuhrNQ+WxRv8GC177F+QWjEzARMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANES742XWm64tkGnz8Dn
pG6u2lHkZFQr3oaVvPcemvlbAiEA0WGGzmYx5C9UvfXIK7NEziT4pQtyESE0uRVK
Xw4nMqk=
-----END CERTIFICATE-----",
        )
        .unwrap()
    }

    #[test]
    fn test_certificate_ca() {
        let cert_pem = ca_pem();
        let cert = cert(&cert_pem);

        assert!(cert_is_self_issued(&cert));
    }

    pub(crate) struct PublicKeyErrorOps {}
    impl CryptoOps for PublicKeyErrorOps {
        type Key = ();
        type Err = ();
        type CertificateExtra = ();

        fn public_key(&self, _cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
            // Simulate failing to retrieve a public key.
            Err(())
        }

        fn verify_signed_by(
            &self,
            _cert: &Certificate<'_>,
            _key: &Self::Key,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    #[test]
    fn test_certificate_public_key_error() {
        let cert_pem = ca_pem();
        let cert = cert(&cert_pem);

        assert!(cert_is_self_issued(&cert));
    }

    #[test]
    fn test_certificate_public_key_error_ops() {
        // Just to get coverage on the `PublicKeyErrorOps` helper.
        let cert_pem = ca_pem();
        let cert = cert(&cert_pem);
        let ops = PublicKeyErrorOps {};

        assert!(ops.public_key(&cert).is_err());
        assert!(ops.verify_signed_by(&cert, &()).is_ok());
    }
}
