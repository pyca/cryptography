// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Encoding helpers for the verified-garbage key parsing modules.

use cryptography_x509::common::EcParameters;

use crate::{KeyParsingError, KeyParsingResult, KeySerializationError, KeySerializationResult};

/// An unsigned big-endian integer without leading zeros (a raw key
/// component) from its DER encoding (which may have a leading zero byte).
pub(crate) fn uint(v: asn1::BigUint<'_>) -> Vec<u8> {
    strip_zeros(v.as_bytes()).to_vec()
}

/// `v` without its leading zero bytes.
pub(crate) fn strip_zeros(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    &v[start..]
}

/// The DER encoding of an unsigned big-endian integer (with or without
/// leading zeros): minimal, with a zero byte prepended when the high bit is
/// set, as `asn1::BigUint::new` requires.
pub(crate) fn der_uint(v: &[u8]) -> Vec<u8> {
    let v = strip_zeros(v);
    let mut out = Vec::with_capacity(v.len() + 1);
    if v.first().is_none_or(|&b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(v);
    out
}

/// An `asn1::BigUint` over bytes `der_uint` produced.
pub(crate) fn big_uint(der: &[u8]) -> asn1::BigUint<'_> {
    asn1::BigUint::new(der).unwrap()
}

/// The byte length of the group order (and so of private scalars, RFC 5915)
/// of each named curve supported: the curves cryptography supports with
/// OpenSSL, all of which verified-garbage implements.
pub(crate) fn curve_order_len(curve: &asn1::ObjectIdentifier) -> Option<usize> {
    use cryptography_x509::oid;
    Some(match *curve {
        oid::EC_SECP192R1 => 24,
        oid::EC_SECP224R1 => 28,
        oid::EC_SECP256R1 | oid::EC_SECP256K1 | oid::EC_BRAINPOOLP256R1 => 32,
        oid::EC_SECP384R1 | oid::EC_BRAINPOOLP384R1 => 48,
        oid::EC_BRAINPOOLP512R1 => 64,
        oid::EC_SECP521R1 => 66,
        _ => return None,
    })
}

/// The supported named curve that EC parameters denote.
pub(crate) fn ec_params_to_curve(
    params: &EcParameters<'_>,
) -> KeyParsingResult<asn1::ObjectIdentifier> {
    let curve = crate::common::ec_params_to_curve_oid(params)?;
    if curve_order_len(&curve).is_none() {
        return Err(KeyParsingError::UnsupportedEllipticCurve(curve));
    }
    Ok(curve)
}

/// The byte length of a field element of each supported curve.
pub(crate) fn curve_field_len(curve: &asn1::ObjectIdentifier) -> Option<usize> {
    // Every supported curve's field and order have the same byte length.
    curve_order_len(curve)
}

/// Whether two SEC 1 encodings (§2.3.3: compressed, uncompressed or hybrid)
/// of points on a curve whose field elements are `field_len` bytes long
/// denote the same point. It compares what both encodings carry: the x
/// coordinate, the parity of y, and y when both include it. Encodings that
/// are malformed (wrong length or prefix) are never equal.
pub(crate) fn ec_points_eq(a: &[u8], b: &[u8], field_len: usize) -> bool {
    // (x, parity of y, y if present), or `None` for the point at infinity.
    #[allow(clippy::type_complexity)]
    fn decode(p: &[u8], field_len: usize) -> Result<Option<(&[u8], u8, Option<&[u8]>)>, ()> {
        match p.first() {
            Some(0x00) if p.len() == 1 => Ok(None),
            Some(&prefix @ (0x02 | 0x03)) if p.len() == 1 + field_len => {
                Ok(Some((&p[1..], prefix & 1, None)))
            }
            Some(&prefix @ (0x04 | 0x06 | 0x07)) if p.len() == 1 + 2 * field_len => {
                let (x, y) = p[1..].split_at(field_len);
                let parity = y[field_len - 1] & 1;
                if prefix != 0x04 && prefix & 1 != parity {
                    return Err(());
                }
                Ok(Some((x, parity, Some(y))))
            }
            _ => Err(()),
        }
    }
    match (decode(a, field_len), decode(b, field_len)) {
        (Ok(None), Ok(None)) => true,
        (Ok(Some((xa, pa, ya))), Ok(Some((xb, pb, yb)))) => {
            xa == xb
                && pa == pb
                && match (ya, yb) {
                    (Some(ya), Some(yb)) => ya == yb,
                    _ => true,
                }
        }
        _ => false,
    }
}

/// Fills `buf` with random bytes from the operating system.
pub(crate) fn rand_bytes(buf: &mut [u8]) -> KeySerializationResult<()> {
    getrandom::fill(buf).map_err(|_| KeySerializationError::VerifiedGarbage("getrandom"))
}

/// The contents of a file under `vectors/cryptography_vectors/asymmetric/`.
#[cfg(test)]
macro_rules! vector {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../vectors/cryptography_vectors/asymmetric/",
            $path
        ))
        .as_slice()
    };
}
#[cfg(test)]
pub(crate) use vector;

/// The contents of a PEM file under `vectors/cryptography_vectors/asymmetric/`.
#[cfg(test)]
macro_rules! pem_vector {
    ($path:literal) => {
        pem::parse($crate::vg_util::vector!($path))
            .unwrap()
            .into_contents()
    };
}
#[cfg(test)]
pub(crate) use pem_vector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_uint() {
        assert_eq!(der_uint(&[]), vec![0]);
        assert_eq!(der_uint(&[0, 0]), vec![0]);
        assert_eq!(der_uint(&[0, 1]), vec![1]);
        assert_eq!(der_uint(&[0x80]), vec![0, 0x80]);
        assert_eq!(der_uint(&[0, 0, 0x80, 1]), vec![0, 0x80, 1]);
        for v in [&[0u8][..], &[0x7f], &[0x80, 0], &[1, 2, 3]] {
            let der = der_uint(v);
            assert_eq!(strip_zeros(big_uint(&der).as_bytes()), strip_zeros(v));
        }
    }

    #[test]
    fn test_ec_points_eq() {
        let x = [1u8, 2];
        let y_even = [3u8, 4];
        let y_odd = [3u8, 5];
        let u = [&[4u8][..], &x, &y_even].concat();
        let u_odd = [&[4u8][..], &x, &y_odd].concat();
        let c_even = [&[2u8][..], &x].concat();
        let c_odd = [&[3u8][..], &x].concat();
        let h_even = [&[6u8][..], &x, &y_even].concat();
        let h_bad = [&[7u8][..], &x, &y_even].concat();
        assert!(ec_points_eq(&u, &u, 2));
        assert!(ec_points_eq(&u, &c_even, 2));
        assert!(ec_points_eq(&c_even, &u, 2));
        assert!(ec_points_eq(&u, &h_even, 2));
        assert!(!ec_points_eq(&u, &c_odd, 2));
        assert!(!ec_points_eq(&u, &u_odd, 2));
        assert!(!ec_points_eq(&u, &h_bad, 2));
        assert!(!ec_points_eq(&u, &u[..4], 2));
        assert!(!ec_points_eq(&[], &[], 2));
        assert!(ec_points_eq(&[0], &[0], 2));
        assert!(!ec_points_eq(&[0], &u, 2));
        let other_x = [&[2u8][..], &[1, 3]].concat();
        assert!(!ec_points_eq(&c_even, &other_x, 2));
    }

    #[test]
    fn test_curves() {
        use cryptography_x509::oid;
        assert_eq!(curve_order_len(&oid::EC_SECP521R1), Some(66));
        assert_eq!(curve_field_len(&oid::EC_SECP256R1), Some(32));
        assert_eq!(curve_order_len(&oid::X25519_OID), None);
        assert!(matches!(
            ec_params_to_curve(&EcParameters::NamedCurve(oid::X25519_OID)),
            Err(KeyParsingError::UnsupportedEllipticCurve(_))
        ));
        assert!(matches!(
            ec_params_to_curve(&EcParameters::NamedCurve(oid::EC_SECP384R1)),
            Ok(oid::EC_SECP384R1)
        ));
    }

    #[test]
    fn test_rand_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(rand_bytes(&mut a).is_ok());
        assert!(rand_bytes(&mut b).is_ok());
        assert_ne!(a, b);
    }
}
