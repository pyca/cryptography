// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::pkcs7;

// #[derive(asn1::Asn1Write)]
pub struct Pfx<'a> {
    pub version: u8,
    pub auth_safe: pkcs7::ContentInfo<'a>,
    pub mac_data: Option<MacData<'a>>,
}

// #[derive(asn1::Asn1Write)]
pub struct MacData<'a> {
    pub mac: pkcs7::DigestInfo<'a>,
    pub salt: &'a [u8],
    // #[default(1)]
    pub iterations: u64,
}
