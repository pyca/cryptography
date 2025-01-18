// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::KeyParsingResult;

#[derive(asn1::Asn1Read)]
pub struct Pkcs1RsaPublicKey<'a> {
    pub n: asn1::BigUint<'a>,
    e: asn1::BigUint<'a>,
}

// RFC 8017, Section A.1.2
#[derive(asn1::Asn1Read)]
pub(crate) struct RsaPrivateKey<'a> {
    pub(crate) version: u8,
    pub(crate) n: asn1::BigUint<'a>,
    pub(crate) e: asn1::BigUint<'a>,
    pub(crate) d: asn1::BigUint<'a>,
    pub(crate) p: asn1::BigUint<'a>,
    pub(crate) q: asn1::BigUint<'a>,
    pub(crate) dmp1: asn1::BigUint<'a>,
    pub(crate) dmq1: asn1::BigUint<'a>,
    pub(crate) iqmp: asn1::BigUint<'a>,
    // We don't support these, so don't bother to parse the inner fields.
    pub(crate) other_prime_infos: Option<asn1::SequenceOf<'a, asn1::Sequence<'a>, 1>>,
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

pub fn parse_pkcs1_private_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let rsa_private_key = asn1::parse_single::<RsaPrivateKey<'_>>(data)?;
    if rsa_private_key.version != 0 || rsa_private_key.other_prime_infos.is_some() {
        return Err(crate::KeyParsingError::InvalidKey);
    }
    let n = openssl::bn::BigNum::from_slice(rsa_private_key.n.as_bytes())?;
    let e = openssl::bn::BigNum::from_slice(rsa_private_key.e.as_bytes())?;
    let d = openssl::bn::BigNum::from_slice(rsa_private_key.d.as_bytes())?;
    let p = openssl::bn::BigNum::from_slice(rsa_private_key.p.as_bytes())?;
    let q = openssl::bn::BigNum::from_slice(rsa_private_key.q.as_bytes())?;
    let dmp1 = openssl::bn::BigNum::from_slice(rsa_private_key.dmp1.as_bytes())?;
    let dmq1 = openssl::bn::BigNum::from_slice(rsa_private_key.dmq1.as_bytes())?;
    let iqmp = openssl::bn::BigNum::from_slice(rsa_private_key.iqmp.as_bytes())?;
    let rsa_key = openssl::rsa::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)?;
    Ok(openssl::pkey::PKey::from_rsa(rsa_key)?)
}
