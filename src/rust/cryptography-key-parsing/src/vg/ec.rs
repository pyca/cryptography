// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! SEC 1 / RFC 5915 EC private keys, as raw components.

use cryptography_x509::common::EcParameters;

use crate::raw::EcPrivateKey;
use crate::vg_util::{curve_order_len, ec_params_to_curve, strip_zeros};
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

/// Serializes `key`, whose `public_point` must be present (uncompressed).
/// The private value is written at the byte length of the curve's order.
///
/// # Panics
///
/// If the curve is not supported, the public point is missing, or the
/// private value is longer than the curve's order.
pub fn serialize_pkcs1_private_key(
    key: &EcPrivateKey,
    include_curve: bool,
) -> KeySerializationResult<Vec<u8>> {
    let order_len = curve_order_len(&key.curve).expect("Unknown curve");
    let parameters = include_curve.then(|| EcParameters::NamedCurve(key.curve.clone()));

    let value = strip_zeros(&key.private_value);
    assert!(value.len() <= order_len, "EC private key too long");
    let mut private_key = vec![0; order_len - value.len()];
    private_key.extend_from_slice(value);

    let public_point = key
        .public_point
        .as_ref()
        .expect("EC private key without public point");

    Ok(asn1::write_single(&crate::common::EcPrivateKey {
        version: 1,
        private_key: &private_key,
        parameters,
        public_key: Some(asn1::BitString::new(public_point, 0).unwrap()),
    })?)
}

/// Parses a key; its curve is `ec_params` (from a PKCS #8 wrapper) or its
/// own, which must agree when both are present. The private value must be
/// as long as the curve's order. The public point, if present, is returned
/// as encoded, for the backend to check.
pub fn parse_pkcs1_private_key(
    data: &[u8],
    ec_params: Option<EcParameters<'_>>,
) -> KeyParsingResult<EcPrivateKey> {
    let (k, params) = crate::common::parse_ec_private_key(data, ec_params)?;
    let curve = ec_params_to_curve(&params)?;

    if Some(k.private_key.len()) != curve_order_len(&curve) {
        return Err(KeyParsingError::TruncatedEcPrivateKey);
    }

    let public_point = match k.public_key {
        Some(point) => {
            // The publicKey BIT STRING holds an octet-aligned EC point, so a
            // non-zero unused-bits count is a malformed encoding.
            if point.padding_bits() != 0 {
                return Err(KeyParsingError::InvalidKey);
            }
            Some(point.as_bytes().to_vec())
        }
        None => None,
    };

    Ok(EcPrivateKey {
        curve,
        private_value: k.private_key.to_vec(),
        public_point,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography_x509::oid;

    #[test]
    fn test_round_trip() {
        let key = EcPrivateKey {
            curve: oid::EC_SECP256R1,
            private_value: vec![1; 32],
            public_point: Some([&[4u8][..], &[2; 64]].concat()),
        };
        for include_curve in [true, false] {
            let der = serialize_pkcs1_private_key(&key, include_curve)
                .ok()
                .unwrap();
            let params = (!include_curve).then_some(EcParameters::NamedCurve(oid::EC_SECP256R1));
            let parsed = parse_pkcs1_private_key(&der, params).ok().unwrap();
            assert_eq!(parsed, key);
        }
        // Short private values are padded to the order's length.
        let short = EcPrivateKey {
            private_value: vec![0, 0, 1],
            ..key.clone()
        };
        let der = serialize_pkcs1_private_key(&short, true).ok().unwrap();
        let parsed = parse_pkcs1_private_key(&der, None).ok().unwrap();
        let mut expected = vec![0; 31];
        expected.push(1);
        assert_eq!(parsed.private_value, expected);
    }

    #[test]
    fn test_parse_errors() {
        let key = EcPrivateKey {
            curve: oid::EC_SECP384R1,
            private_value: vec![1; 48],
            public_point: Some(vec![4; 97]),
        };
        // No curve anywhere.
        let der = serialize_pkcs1_private_key(&key, false).ok().unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::InvalidKey)
        ));
        // Inconsistent curves.
        let der = serialize_pkcs1_private_key(&key, true).ok().unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, Some(EcParameters::NamedCurve(oid::EC_SECP256R1))),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse_pkcs1_private_key(&der[..0], None),
            Err(KeyParsingError::Parse(_))
        ));
        let truncated = crate::common::EcPrivateKey {
            version: 1,
            private_key: &[1; 47],
            parameters: Some(EcParameters::NamedCurve(oid::EC_SECP384R1)),
            public_key: None,
        };
        let der = asn1::write_single(&truncated).unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::TruncatedEcPrivateKey)
        ));
        let unknown = crate::common::EcPrivateKey {
            version: 1,
            private_key: &[1; 32],
            parameters: Some(EcParameters::NamedCurve(oid::X25519_OID)),
            public_key: None,
        };
        let der = asn1::write_single(&unknown).unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::UnsupportedEllipticCurve(_))
        ));
        let bad_version = crate::common::EcPrivateKey {
            version: 2,
            private_key: &[1; 32],
            parameters: Some(EcParameters::NamedCurve(oid::EC_SECP256R1)),
            public_key: None,
        };
        let der = asn1::write_single(&bad_version).unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::InvalidKey)
        ));
        let padded = crate::common::EcPrivateKey {
            version: 1,
            private_key: &[1; 32],
            parameters: Some(EcParameters::NamedCurve(oid::EC_SECP256R1)),
            public_key: Some(asn1::BitString::new(&[4, 0], 1).unwrap()),
        };
        let der = asn1::write_single(&padded).unwrap();
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::InvalidKey)
        ));
    }

    #[test]
    fn test_parse_vectors() {
        let der = crate::vg_util::pem_vector!("PEM_Serialization/ec_private_key.pem");
        let key = parse_pkcs1_private_key(&der, None).ok().unwrap();
        assert_eq!(key.curve, oid::EC_SECP256R1);
        assert_eq!(key.private_value.len(), 32);
        assert_eq!(key.public_point.as_ref().unwrap().len(), 65);
        // OpenSSL's encoding is the same as ours.
        assert_eq!(serialize_pkcs1_private_key(&key, true).ok().unwrap(), der);

        // The private value's high bit is set: no leading zero is added.
        let der = crate::vg_util::pem_vector!("EC/high-bit-set.pem");
        let key = parse_pkcs1_private_key(&der, None).ok().unwrap();
        assert_eq!(serialize_pkcs1_private_key(&key, true).ok().unwrap(), der);

        let der = crate::vg_util::vector!("EC/truncated-private-key.der");
        assert!(matches!(
            parse_pkcs1_private_key(der, None),
            Err(KeyParsingError::TruncatedEcPrivateKey)
        ));
        let der = crate::vg_util::pem_vector!("EC/secp128r1_private_key.pem");
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::UnsupportedEllipticCurve(_))
        ));
        let der = crate::vg_util::pem_vector!("EC/ec-missing-curve.pem");
        assert!(matches!(
            parse_pkcs1_private_key(&der, None),
            Err(KeyParsingError::InvalidKey)
        ));
    }
}
