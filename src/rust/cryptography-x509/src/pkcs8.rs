// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::common::AlgorithmIdentifier;

// RFC 5208, Section 6
#[derive(asn1::Asn1Write, asn1::Asn1Read)]
pub struct EncryptedPrivateKeyInfo<'a> {
    pub encryption_algorithm: AlgorithmIdentifier<'a>,
    pub encrypted_data: &'a [u8],
}
