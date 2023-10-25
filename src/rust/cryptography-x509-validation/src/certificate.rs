// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Validation-specific certificate functionality.

use cryptography_x509::certificate::Certificate;

use crate::ops::CryptoOps;

#[allow(dead_code)]
pub(crate) fn cert_is_self_issued(cert: &Certificate<'_>) -> bool {
    cert.issuer() == cert.subject()
}

#[allow(dead_code)]
pub(crate) fn cert_is_self_signed<B: CryptoOps>(cert: &Certificate<'_>, ops: &B) -> bool {
    match ops.public_key(cert) {
        Ok(pk) => cert_is_self_issued(cert) && ops.verify_signed_by(cert, pk).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::ops::tests::{cert, v1_cert_pem, NullOps};

    use super::{cert_is_self_issued, cert_is_self_signed};

    #[test]
    fn test_certificate_validation_helpers() {
        let cert_pem = v1_cert_pem();
        let cert = cert(&cert_pem);
        let ops = NullOps {};

        assert!(!cert_is_self_issued(&cert));
        assert!(!cert_is_self_signed(&cert, &ops));
    }
}
