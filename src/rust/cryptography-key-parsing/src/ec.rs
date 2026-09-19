// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::EcParameters;
use cryptography_x509::ec_constants;

use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

// From RFC 5915 Section 3
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct EcPrivateKey<'a> {
    pub(crate) version: u8,
    pub(crate) private_key: &'a [u8],
    #[explicit(0)]
    pub(crate) parameters: Option<EcParameters<'a>>,
    #[explicit(1)]
    pub(crate) public_key: Option<asn1::BitString<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl_bridge::ec::{Curve, PointEncoding, PrivateKey};

    #[test]
    fn sec1_rejects_a_valid_public_point_for_a_different_private_scalar() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        for public_scalar in [1, 2] {
            let public = PrivateKey::from_scalar(Curve::P256, &[public_scalar])
                .unwrap()
                .public_key()
                .unwrap()
                .to_encoded(PointEncoding::Uncompressed)
                .unwrap();
            let encoded = asn1::write_single(&EcPrivateKey {
                version: 1,
                private_key: &scalar,
                parameters: Some(EcParameters::NamedCurve(
                    cryptography_x509::oid::EC_SECP256R1,
                )),
                public_key: Some(asn1::BitString::new(&public, 0).unwrap()),
            })
            .unwrap();
            let result = parse_pkcs1_private_key(&encoded, None);
            if public_scalar == 1 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(KeyParsingError::InvalidKey)));
            }
        }
    }
}

pub(crate) fn group_to_curve_oid(curve: openssl_bridge::ec::Curve) -> asn1::ObjectIdentifier {
    match curve {
        openssl_bridge::ec::Curve::P192 => cryptography_x509::oid::EC_SECP192R1,
        openssl_bridge::ec::Curve::P224 => cryptography_x509::oid::EC_SECP224R1,
        openssl_bridge::ec::Curve::P256 => cryptography_x509::oid::EC_SECP256R1,
        openssl_bridge::ec::Curve::P384 => cryptography_x509::oid::EC_SECP384R1,
        openssl_bridge::ec::Curve::P521 => cryptography_x509::oid::EC_SECP521R1,
        openssl_bridge::ec::Curve::Secp256k1 => cryptography_x509::oid::EC_SECP256K1,
        openssl_bridge::ec::Curve::BrainpoolP256r1 => cryptography_x509::oid::EC_BRAINPOOLP256R1,
        openssl_bridge::ec::Curve::BrainpoolP384r1 => cryptography_x509::oid::EC_BRAINPOOLP384R1,
        openssl_bridge::ec::Curve::BrainpoolP512r1 => cryptography_x509::oid::EC_BRAINPOOLP512R1,
    }
}
pub(crate) fn ec_params_to_group(
    params: &EcParameters<'_>,
) -> KeyParsingResult<openssl_bridge::ec::Curve> {
    match params {
        EcParameters::NamedCurve(curve_oid) => {
            let curve_nid = match curve_oid {
                &cryptography_x509::oid::EC_SECP192R1 => openssl_bridge::ec::Curve::P192,
                &cryptography_x509::oid::EC_SECP224R1 => openssl_bridge::ec::Curve::P224,
                &cryptography_x509::oid::EC_SECP256R1 => openssl_bridge::ec::Curve::P256,
                &cryptography_x509::oid::EC_SECP384R1 => openssl_bridge::ec::Curve::P384,
                &cryptography_x509::oid::EC_SECP521R1 => openssl_bridge::ec::Curve::P521,

                &cryptography_x509::oid::EC_SECP256K1 => openssl_bridge::ec::Curve::Secp256k1,

                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP256R1 => {
                    openssl_bridge::ec::Curve::BrainpoolP256r1
                }
                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP384R1 => {
                    openssl_bridge::ec::Curve::BrainpoolP384r1
                }
                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP512R1 => {
                    openssl_bridge::ec::Curve::BrainpoolP512r1
                }

                _ => return Err(KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone())),
            };

            if !curve_nid.is_available() {
                return Err(KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone()));
            }
            Ok(curve_nid)
        }
        EcParameters::SpecifiedCurve(params) => {
            // We do not support arbitrary explicit curves. Instead we map values
            // to named curves. This currently supports only P256, P384,
            // and P521. No binary curves are supported. Everything must
            // match, except the seed may be omitted on NIST curves since OpenSSL
            // has supported a -no_seed option for over 20 years and I don't want to
            // figure out whether anyone uses that or not. No one should be using
            // explicit curve encoding anyway. Curves were meant to be named!
            let (curve_nid, oid) = match params {
                &ec_constants::P256_DOMAIN | &ec_constants::P256_DOMAIN_NO_SEED => (
                    openssl_bridge::ec::Curve::P256,
                    cryptography_x509::oid::EC_SECP256R1,
                ),
                &ec_constants::P384_DOMAIN | &ec_constants::P384_DOMAIN_NO_SEED => (
                    openssl_bridge::ec::Curve::P384,
                    cryptography_x509::oid::EC_SECP384R1,
                ),
                &ec_constants::P521_DOMAIN | &ec_constants::P521_DOMAIN_NO_SEED => (
                    openssl_bridge::ec::Curve::P521,
                    cryptography_x509::oid::EC_SECP521R1,
                ),
                _ => return Err(KeyParsingError::ExplicitCurveUnsupported),
            };
            if !curve_nid.is_available() {
                // NO-COVERAGE-START
                // Supported backends all include these three NIST curves; this guard
                // needs native initialization or allocation failure.
                return Err(KeyParsingError::UnsupportedEllipticCurve(oid));
                // NO-COVERAGE-END
            }
            Ok(curve_nid)
        }
        EcParameters::ImplicitCurve(_) => Err(KeyParsingError::ExplicitCurveUnsupported),
    }
}

pub fn serialize_pkcs1_private_key(
    ec: &openssl_bridge::ec::PrivateKey,
    include_curve: bool,
) -> KeySerializationResult<Vec<u8>> {
    let parameters =
        include_curve.then(|| EcParameters::NamedCurve(group_to_curve_oid(ec.curve())));
    let scalar = ec.scalar()?;
    let mut private_key_bytes: openssl_bridge::secret::SecretBytes =
        vec![0; ec.curve().field_size()].into();
    let offset = private_key_bytes.as_ref().len() - scalar.as_ref().len();
    private_key_bytes.as_mut()[offset..].copy_from_slice(scalar.as_ref());
    let public_key_bytes = ec
        .public_key()?
        .to_encoded(openssl_bridge::ec::PointEncoding::Uncompressed)?;
    let key = EcPrivateKey {
        version: 1,
        private_key: private_key_bytes.as_ref(),
        parameters,
        public_key: Some(asn1::BitString::new(&public_key_bytes, 0).unwrap()),
    };
    Ok(asn1::write_single(&key)?)
}

pub fn parse_pkcs1_private_key(
    data: &[u8],
    ec_params: Option<EcParameters<'_>>,
) -> KeyParsingResult<openssl_bridge::ec::PrivateKey> {
    let ec_private_key = asn1::parse_single::<EcPrivateKey<'_>>(data)?;
    if ec_private_key.version != 1 {
        return Err(crate::KeyParsingError::InvalidKey);
    }

    let group = match (ec_params, ec_private_key.parameters) {
        (Some(outer_params), Some(inner_params)) => {
            if outer_params != inner_params {
                return Err(crate::KeyParsingError::InvalidKey);
            }
            ec_params_to_group(&outer_params)?
        }
        (Some(outer_params), None) => ec_params_to_group(&outer_params)?,
        (None, Some(inner_params)) => ec_params_to_group(&inner_params)?,
        (None, None) => return Err(crate::KeyParsingError::InvalidKey),
    };

    if ec_private_key.private_key.len() != group.field_size() {
        return Err(crate::KeyParsingError::TruncatedEcPrivateKey);
    }

    let key = openssl_bridge::ec::PrivateKey::from_scalar(group, ec_private_key.private_key)
        .map_err(|_| KeyParsingError::InvalidKey)?;
    if let Some(encoded) = ec_private_key.public_key {
        if encoded.padding_bits() != 0 {
            return Err(KeyParsingError::InvalidKey);
        }
        let public = openssl_bridge::ec::PublicKey::from_encoded(group, encoded.as_bytes())
            .map_err(|_| KeyParsingError::InvalidKey)?;
        let form = openssl_bridge::ec::PointEncoding::Uncompressed;
        if public.to_encoded(form)? != key.public_key()?.to_encoded(form)? {
            return Err(KeyParsingError::InvalidKey);
        }
    }
    Ok(key)
}
