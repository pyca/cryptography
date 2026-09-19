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
    dsa: &openssl_bridge::dsa::PrivateKeyMaterial,
) -> KeySerializationResult<Vec<u8>> {
    let parts = dsa.parameters().components();
    let public = dsa.public_key();
    let p_bytes = crate::utils::integer_bytes(parts.p);
    let q_bytes = crate::utils::integer_bytes(parts.q);
    let g_bytes = crate::utils::integer_bytes(parts.g);
    let pub_key_bytes = crate::utils::integer_bytes(public.public_value());
    let priv_key_bytes = crate::utils::integer_bytes(dsa.scalar());
    Ok(asn1::write_single(&DsaPrivateKey {
        version: 0,
        p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
        q: asn1::BigUint::new(q_bytes.as_ref()).unwrap(),
        g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
        pub_key: asn1::BigUint::new(pub_key_bytes.as_ref()).unwrap(),
        priv_key: asn1::BigUint::new(priv_key_bytes.as_ref()).unwrap(),
    })?)
}
pub fn parse_pkcs1_private_key(
    data: &[u8],
) -> KeyParsingResult<openssl_bridge::dsa::PrivateKeyMaterial> {
    let key = asn1::parse_single::<DsaPrivateKey<'_>>(data)?;
    if key.version != 0 {
        return Err(crate::KeyParsingError::InvalidKey);
    }
    let params =
        openssl_bridge::dsa::ParameterMaterial::from_components(openssl_bridge::dsa::Components {
            p: key.p.as_bytes(),
            q: key.q.as_bytes(),
            g: key.g.as_bytes(),
        })?;
    Ok(openssl_bridge::dsa::PrivateKeyMaterial::from_components(
        params,
        key.priv_key.as_bytes(),
        key.pub_key.as_bytes(),
    )?)
}
