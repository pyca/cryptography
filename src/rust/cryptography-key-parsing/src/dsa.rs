// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{KeyParsingResult, KeySerializationResult};

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct DsaPrivateKey<'a> {
    version: u8,
    p: asn1::BigUint<'a>,
    q: asn1::BigUint<'a>,
    g: asn1::BigUint<'a>,
    pub_key: asn1::BigUint<'a>,
    priv_key: asn1::BigUint<'a>,
}

pub fn serialize_pkcs1_private_key(
    dsa: &openssl::dsa::DsaRef<openssl::pkey::Private>,
) -> KeySerializationResult<Vec<u8>> {
    let p_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.p())?;
    let q_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.q())?;
    let g_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.g())?;
    let pub_key_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.pub_key())?;
    let priv_key_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.priv_key())?;

    let key = DsaPrivateKey {
        version: 0,
        p: asn1::BigUint::new(&p_bytes).unwrap(),
        q: asn1::BigUint::new(&q_bytes).unwrap(),
        g: asn1::BigUint::new(&g_bytes).unwrap(),
        pub_key: asn1::BigUint::new(&pub_key_bytes).unwrap(),
        priv_key: asn1::BigUint::new(&priv_key_bytes).unwrap(),
    };
    Ok(asn1::write_single(&key)?)
}

pub fn parse_pkcs1_private_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let dsa_private_key = asn1::parse_single::<DsaPrivateKey<'_>>(data)?;
    if dsa_private_key.version != 0 {
        return Err(crate::KeyParsingError::InvalidKey);
    }
    let p = openssl::bn::BigNum::from_slice(dsa_private_key.p.as_bytes())?;
    let q = openssl::bn::BigNum::from_slice(dsa_private_key.q.as_bytes())?;
    let g = openssl::bn::BigNum::from_slice(dsa_private_key.g.as_bytes())?;
    let priv_key = openssl::bn::BigNum::from_slice(dsa_private_key.priv_key.as_bytes())?;
    let pub_key = openssl::bn::BigNum::from_slice(dsa_private_key.pub_key.as_bytes())?;
    let dsa = openssl::dsa::Dsa::from_private_components(p, q, g, priv_key, pub_key)?;
    Ok(openssl::pkey::PKey::from_dsa(dsa)?)
}
