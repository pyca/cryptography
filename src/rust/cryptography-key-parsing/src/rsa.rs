// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::Pkcs1RsaPublicKey;

use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

// RFC 8017, Section A.1.2
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
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

/// Bounded encodings from an RSA private-key container. Operations require the
/// independent RSA constructor with the caller's explicit validation policy.
pub struct RsaPrivateMaterial {
    parts: [openssl_bridge::secret::SecretBytes; 8],
}
impl RsaPrivateMaterial {
    pub fn components(&self) -> openssl_bridge::rsa::PrivateComponents<'_> {
        let [n, e, d, p, q, dmp1, dmq1, iqmp] = &self.parts;
        openssl_bridge::rsa::PrivateComponents {
            n: n.as_ref(),
            e: e.as_ref(),
            d: d.as_ref(),
            p: p.as_ref(),
            q: q.as_ref(),
            dmp1: dmp1.as_ref(),
            dmq1: dmq1.as_ref(),
            iqmp: iqmp.as_ref(),
        }
    }
}
pub fn parse_pkcs1_public_key(data: &[u8]) -> KeyParsingResult<openssl_bridge::rsa::PublicKey> {
    let key = asn1::parse_single::<Pkcs1RsaPublicKey<'_>>(data)?;
    Ok(openssl_bridge::rsa::PublicKey::from_components(
        key.n.as_bytes(),
        key.e.as_bytes(),
    )?)
}
pub fn serialize_pkcs1_public_key(
    key: &openssl_bridge::rsa::PublicKey,
) -> KeySerializationResult<Vec<u8>> {
    let parts = key.export_components()?;
    let n = crate::utils::integer_bytes(&parts.n);
    let e = crate::utils::integer_bytes(&parts.e);
    Ok(asn1::write_single(&Pkcs1RsaPublicKey {
        n: asn1::BigUint::new(n.as_ref()).unwrap(),
        e: asn1::BigUint::new(e.as_ref()).unwrap(),
    })?)
}
pub fn serialize_pkcs1_private_key(
    parts: openssl_bridge::rsa::PrivateComponents<'_>,
) -> KeySerializationResult<Vec<u8>> {
    let n = crate::utils::integer_bytes(parts.n);
    let e = crate::utils::integer_bytes(parts.e);
    let d = crate::utils::integer_bytes(parts.d);
    let p = crate::utils::integer_bytes(parts.p);
    let q = crate::utils::integer_bytes(parts.q);
    let dmp1 = crate::utils::integer_bytes(parts.dmp1);
    let dmq1 = crate::utils::integer_bytes(parts.dmq1);
    let iqmp = crate::utils::integer_bytes(parts.iqmp);
    Ok(asn1::write_single(&RsaPrivateKey {
        version: 0,
        n: asn1::BigUint::new(n.as_ref()).unwrap(),
        e: asn1::BigUint::new(e.as_ref()).unwrap(),
        d: asn1::BigUint::new(d.as_ref()).unwrap(),
        p: asn1::BigUint::new(p.as_ref()).unwrap(),
        q: asn1::BigUint::new(q.as_ref()).unwrap(),
        dmp1: asn1::BigUint::new(dmp1.as_ref()).unwrap(),
        dmq1: asn1::BigUint::new(dmq1.as_ref()).unwrap(),
        iqmp: asn1::BigUint::new(iqmp.as_ref()).unwrap(),
        other_prime_infos: None,
    })?)
}
pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<RsaPrivateMaterial> {
    let key = asn1::parse_single::<RsaPrivateKey<'_>>(data)?;
    if key.version != 0 || key.other_prime_infos.is_some() {
        return Err(KeyParsingError::InvalidKey);
    }
    let parts = [
        key.n, key.e, key.d, key.p, key.q, key.dmp1, key.dmq1, key.iqmp,
    ];
    // Match the independent RSA operation layer's native bit-length bound, while
    // deferring mathematical checks until the validation policy is selected.
    if parts
        .iter()
        .any(|n| n.as_bytes().len() > (i32::MAX as usize) / 8)
    {
        return Err(KeyParsingError::InvalidKey);
    }
    Ok(RsaPrivateMaterial {
        parts: parts.map(|n| n.as_bytes().to_vec().into()),
    })
}
