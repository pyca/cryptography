// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! OpenSSL's traditional DSA private key format, as raw components.

use crate::raw::{DsaParameters, DsaPrivateKey};
use crate::vg_util::{big_uint, der_uint, uint};
use crate::{KeyParsingResult, KeySerializationResult};

/// Serializes `key`, whose `y` must be present (the format includes it).
pub fn serialize_pkcs1_private_key(key: &DsaPrivateKey) -> KeySerializationResult<Vec<u8>> {
    let p = der_uint(&key.params.p);
    let q = der_uint(&key.params.q);
    let g = der_uint(&key.params.g);
    let y = der_uint(key.y.as_ref().expect("DSA private key without y"));
    let x = der_uint(&key.x);
    Ok(asn1::write_single(&crate::common::DsaPrivateKey {
        version: 0,
        p: big_uint(&p),
        q: big_uint(&q),
        g: big_uint(&g),
        pub_key: big_uint(&y),
        priv_key: big_uint(&x),
    })?)
}

/// Parses a key, with its `y`, which the backend must check is `g^x mod p`.
pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<DsaPrivateKey> {
    let k = crate::common::parse_dsa_private_key(data)?;
    Ok(DsaPrivateKey {
        params: DsaParameters {
            p: uint(k.p),
            q: uint(k.q),
            g: uint(k.g),
        },
        x: uint(k.priv_key),
        y: Some(uint(k.pub_key)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vg_util::pem_vector;
    use crate::KeyParsingError;

    #[test]
    fn test_vectors() {
        let der = pem_vector!("Traditional_OpenSSL_Serialization/dsa.1024.pem");
        let key = parse_pkcs1_private_key(&der).ok().unwrap();
        assert_eq!(key.params.p.len(), 128);
        assert_eq!(key.params.q.len(), 20);
        assert!(key.y.is_some());
        // OpenSSL's encoding is the same as ours.
        assert_eq!(serialize_pkcs1_private_key(&key).ok().unwrap(), der);

        let der = pem_vector!("Traditional_OpenSSL_Serialization/dsa.2048.pem");
        let key = parse_pkcs1_private_key(&der).ok().unwrap();
        assert_eq!(serialize_pkcs1_private_key(&key).ok().unwrap(), der);

        let der = pem_vector!("Traditional_OpenSSL_Serialization/dsa-wrong-version.pem");
        assert!(matches!(
            parse_pkcs1_private_key(&der),
            Err(KeyParsingError::InvalidKey)
        ));
    }

    #[test]
    #[should_panic(expected = "DSA private key without y")]
    fn test_serialize_without_y() {
        let key = DsaPrivateKey {
            params: DsaParameters {
                p: vec![23],
                q: vec![11],
                g: vec![4],
            },
            x: vec![3],
            y: None,
        };
        let _ = serialize_pkcs1_private_key(&key);
    }
}
