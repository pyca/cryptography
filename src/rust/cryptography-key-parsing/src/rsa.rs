// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::KeyParsingResult;

#[derive(asn1::Asn1Read)]
pub struct Pkcs1RsaPublicKey<'a> {
    pub n: asn1::BigUint<'a>,
    e: asn1::BigUint<'a>,
}

pub fn parse_pkcs1_public_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    let k = asn1::parse_single::<Pkcs1RsaPublicKey<'_>>(data)?;

    let n = openssl::bn::BigNum::from_slice(k.n.as_bytes())?;
    let e = openssl::bn::BigNum::from_slice(k.e.as_bytes())?;

    let rsa = openssl::rsa::Rsa::from_public_components(n, e)?;
    Ok(openssl::pkey::PKey::from_rsa(rsa)?)
}
