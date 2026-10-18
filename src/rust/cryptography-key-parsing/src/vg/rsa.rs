// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! PKCS #1 RSA keys, as raw components.

use cryptography_x509::common::Pkcs1RsaPublicKey;

use crate::raw::{RsaPrivateKey, RsaPublicKey};
use crate::vg_util::{big_uint, der_uint, uint};
use crate::{KeyParsingResult, KeySerializationResult};

pub fn parse_pkcs1_public_key(data: &[u8]) -> KeyParsingResult<RsaPublicKey> {
    let k = asn1::parse_single::<Pkcs1RsaPublicKey<'_>>(data)?;
    Ok(RsaPublicKey {
        n: uint(k.n),
        e: uint(k.e),
    })
}

pub fn serialize_pkcs1_public_key(key: &RsaPublicKey) -> KeySerializationResult<Vec<u8>> {
    let n = der_uint(&key.n);
    let e = der_uint(&key.e);
    Ok(asn1::write_single(&Pkcs1RsaPublicKey {
        n: big_uint(&n),
        e: big_uint(&e),
    })?)
}

pub fn serialize_pkcs1_private_key(key: &RsaPrivateKey) -> KeySerializationResult<Vec<u8>> {
    let n = der_uint(&key.n);
    let e = der_uint(&key.e);
    let d = der_uint(&key.d);
    let p = der_uint(&key.p);
    let q = der_uint(&key.q);
    let dmp1 = der_uint(&key.dmp1);
    let dmq1 = der_uint(&key.dmq1);
    let iqmp = der_uint(&key.iqmp);
    Ok(asn1::write_single(&crate::common::RsaPrivateKey {
        version: 0,
        n: big_uint(&n),
        e: big_uint(&e),
        d: big_uint(&d),
        p: big_uint(&p),
        q: big_uint(&q),
        dmp1: big_uint(&dmp1),
        dmq1: big_uint(&dmq1),
        iqmp: big_uint(&iqmp),
        other_prime_infos: None,
    })?)
}

pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<RsaPrivateKey> {
    let k = crate::common::parse_rsa_private_key(data)?;
    Ok(RsaPrivateKey {
        n: uint(k.n),
        e: uint(k.e),
        d: uint(k.d),
        p: uint(k.p),
        q: uint(k.q),
        dmp1: uint(k.dmp1),
        dmq1: uint(k.dmq1),
        iqmp: uint(k.iqmp),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vg_util::{pem_vector, vector};
    use crate::KeyParsingError;

    #[test]
    fn test_private_key_vectors() {
        let der = pem_vector!("Traditional_OpenSSL_Serialization/testrsa.pem");
        let key = parse_pkcs1_private_key(&der).ok().unwrap();
        assert_eq!(key.e, [1, 0, 1]);
        assert_ne!(key.n[0], 0);
        // OpenSSL's encoding is the same as ours.
        assert_eq!(serialize_pkcs1_private_key(&key).ok().unwrap(), der);
        let der2 = vector!("DER_Serialization/testrsa.der");
        assert_eq!(parse_pkcs1_private_key(der2).ok().unwrap(), key);

        let der = pem_vector!("Traditional_OpenSSL_Serialization/rsa-wrong-version.pem");
        assert!(matches!(
            parse_pkcs1_private_key(&der),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse_pkcs1_private_key(b"\x30\x00"),
            Err(KeyParsingError::Parse(_))
        ));
    }

    #[test]
    fn test_multi_prime_rejected() {
        let one = [1u8];
        // A key with otherPrimeInfos (built by hand: version 1, eight
        // integers and a non-empty SEQUENCE OF).
        let mut body = Vec::new();
        body.extend_from_slice(&asn1::write_single(&1u8).unwrap());
        for _ in 0..8 {
            body.extend_from_slice(&asn1::write_single(&big_uint(&one)).unwrap());
        }
        body.extend_from_slice(&[0x30, 0x02, 0x30, 0x00]);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        assert!(matches!(
            parse_pkcs1_private_key(&der),
            Err(KeyParsingError::InvalidKey)
        ));
        // The same with version 0 is rejected too.
        der[4] = 0;
        assert!(matches!(
            parse_pkcs1_private_key(&der),
            Err(KeyParsingError::InvalidKey)
        ));
    }

    #[test]
    fn test_public_key_round_trip() {
        let key = RsaPublicKey {
            n: vec![0xc0, 1, 2, 3],
            e: vec![1, 0, 1],
        };
        let der = serialize_pkcs1_public_key(&key).ok().unwrap();
        // n's high bit is set: it is encoded with a leading zero.
        assert_eq!(
            der,
            [0x30, 0x0c, 0x02, 0x05, 0, 0xc0, 1, 2, 3, 0x02, 0x03, 1, 0, 1]
        );
        assert_eq!(parse_pkcs1_public_key(&der).ok().unwrap(), key);
        assert!(matches!(
            parse_pkcs1_public_key(&der[1..]),
            Err(KeyParsingError::Parse(_))
        ));
    }
}
