// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Validation-specific certificate functionality.

use cryptography_x509::certificate::Certificate;

use crate::ops::CryptoOps;

pub(crate) fn cert_is_self_issued(cert: &Certificate) -> bool {
    cert.issuer() == cert.subject()
}

pub(crate) fn cert_is_self_signed<B: CryptoOps>(cert: &Certificate, ops: &B) -> bool {
    match ops.public_key(cert) {
        Some(pk) => cert_is_self_issued(cert) && ops.is_signed_by(cert, pk),
        None => false,
    }
}
