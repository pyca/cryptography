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

pub(crate) fn group_to_curve_oid(
    group: &openssl::ec::EcGroupRef,
) -> Option<asn1::ObjectIdentifier> {
    let nid = group.curve_name()?;
    match nid {
        openssl::nid::Nid::X9_62_PRIME192V1 => Some(cryptography_x509::oid::EC_SECP192R1),
        openssl::nid::Nid::SECP224R1 => Some(cryptography_x509::oid::EC_SECP224R1),
        openssl::nid::Nid::X9_62_PRIME256V1 => Some(cryptography_x509::oid::EC_SECP256R1),
        openssl::nid::Nid::SECP384R1 => Some(cryptography_x509::oid::EC_SECP384R1),
        openssl::nid::Nid::SECP521R1 => Some(cryptography_x509::oid::EC_SECP521R1),
        openssl::nid::Nid::SECP256K1 => Some(cryptography_x509::oid::EC_SECP256K1),
        openssl::nid::Nid::SECT233R1 => Some(cryptography_x509::oid::EC_SECT233R1),
        openssl::nid::Nid::SECT283R1 => Some(cryptography_x509::oid::EC_SECT283R1),
        openssl::nid::Nid::SECT409R1 => Some(cryptography_x509::oid::EC_SECT409R1),
        openssl::nid::Nid::SECT571R1 => Some(cryptography_x509::oid::EC_SECT571R1),
        openssl::nid::Nid::SECT163R2 => Some(cryptography_x509::oid::EC_SECT163R2),
        openssl::nid::Nid::SECT163K1 => Some(cryptography_x509::oid::EC_SECT163K1),
        openssl::nid::Nid::SECT233K1 => Some(cryptography_x509::oid::EC_SECT233K1),
        openssl::nid::Nid::SECT283K1 => Some(cryptography_x509::oid::EC_SECT283K1),
        openssl::nid::Nid::SECT409K1 => Some(cryptography_x509::oid::EC_SECT409K1),
        openssl::nid::Nid::SECT571K1 => Some(cryptography_x509::oid::EC_SECT571K1),
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        openssl::nid::Nid::BRAINPOOL_P256R1 => Some(cryptography_x509::oid::EC_BRAINPOOLP256R1),
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        openssl::nid::Nid::BRAINPOOL_P384R1 => Some(cryptography_x509::oid::EC_BRAINPOOLP384R1),
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        openssl::nid::Nid::BRAINPOOL_P512R1 => Some(cryptography_x509::oid::EC_BRAINPOOLP512R1),
        _ => None,
    }
}

pub(crate) fn ec_params_to_group(
    params: &EcParameters<'_>,
) -> KeyParsingResult<openssl::ec::EcGroup> {
    match params {
        EcParameters::NamedCurve(curve_oid) => {
            let curve_nid = match curve_oid {
                &cryptography_x509::oid::EC_SECP192R1 => openssl::nid::Nid::X9_62_PRIME192V1,
                &cryptography_x509::oid::EC_SECP224R1 => openssl::nid::Nid::SECP224R1,
                &cryptography_x509::oid::EC_SECP256R1 => openssl::nid::Nid::X9_62_PRIME256V1,
                &cryptography_x509::oid::EC_SECP384R1 => openssl::nid::Nid::SECP384R1,
                &cryptography_x509::oid::EC_SECP521R1 => openssl::nid::Nid::SECP521R1,

                &cryptography_x509::oid::EC_SECP256K1 => openssl::nid::Nid::SECP256K1,

                &cryptography_x509::oid::EC_SECT233R1 => openssl::nid::Nid::SECT233R1,
                &cryptography_x509::oid::EC_SECT283R1 => openssl::nid::Nid::SECT283R1,
                &cryptography_x509::oid::EC_SECT409R1 => openssl::nid::Nid::SECT409R1,
                &cryptography_x509::oid::EC_SECT571R1 => openssl::nid::Nid::SECT571R1,

                &cryptography_x509::oid::EC_SECT163R2 => openssl::nid::Nid::SECT163R2,

                &cryptography_x509::oid::EC_SECT163K1 => openssl::nid::Nid::SECT163K1,
                &cryptography_x509::oid::EC_SECT233K1 => openssl::nid::Nid::SECT233K1,
                &cryptography_x509::oid::EC_SECT283K1 => openssl::nid::Nid::SECT283K1,
                &cryptography_x509::oid::EC_SECT409K1 => openssl::nid::Nid::SECT409K1,
                &cryptography_x509::oid::EC_SECT571K1 => openssl::nid::Nid::SECT571K1,

                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP256R1 => openssl::nid::Nid::BRAINPOOL_P256R1,
                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP384R1 => openssl::nid::Nid::BRAINPOOL_P384R1,
                #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
                &cryptography_x509::oid::EC_BRAINPOOLP512R1 => openssl::nid::Nid::BRAINPOOL_P512R1,

                _ => return Err(KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone())),
            };

            Ok(openssl::ec::EcGroup::from_curve_name(curve_nid)
                .map_err(|_| KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone()))?)
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
                    openssl::nid::Nid::X9_62_PRIME256V1,
                    cryptography_x509::oid::EC_SECP256R1,
                ),
                &ec_constants::P384_DOMAIN | &ec_constants::P384_DOMAIN_NO_SEED => (
                    openssl::nid::Nid::SECP384R1,
                    cryptography_x509::oid::EC_SECP384R1,
                ),
                &ec_constants::P521_DOMAIN | &ec_constants::P521_DOMAIN_NO_SEED => (
                    openssl::nid::Nid::SECP521R1,
                    cryptography_x509::oid::EC_SECP521R1,
                ),
                _ => return Err(KeyParsingError::ExplicitCurveUnsupported),
            };
            Ok(openssl::ec::EcGroup::from_curve_name(curve_nid)
                .map_err(|_| KeyParsingError::UnsupportedEllipticCurve(oid))?)
        }
        EcParameters::ImplicitCurve(_) => Err(KeyParsingError::ExplicitCurveUnsupported),
    }
}

pub fn serialize_pkcs1_private_key(
    ec: &openssl::ec::EcKeyRef<openssl::pkey::Private>,
    include_curve: bool,
) -> KeySerializationResult<Vec<u8>> {
    let parameters = if include_curve {
        let curve_oid = group_to_curve_oid(ec.group()).expect("Unknown curve");
        Some(EcParameters::NamedCurve(curve_oid))
    } else {
        None
    };

    let private_key_bytes = ec.private_key().to_vec();

    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let public_key_bytes = ec.public_key().to_bytes(
        ec.group(),
        openssl::ec::PointConversionForm::UNCOMPRESSED,
        &mut bn_ctx,
    )?;

    let key = EcPrivateKey {
        version: 1,
        private_key: &private_key_bytes,
        parameters,
        public_key: Some(asn1::BitString::new(&public_key_bytes, 0).unwrap()),
    };
    Ok(asn1::write_single(&key)?)
}

pub fn parse_pkcs1_private_key(
    data: &[u8],
    ec_params: Option<EcParameters<'_>>,
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
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

    let private_number = openssl::bn::BigNum::from_slice(ec_private_key.private_key)?;
    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let public_point = if let Some(point_bytes) = ec_private_key.public_key {
        openssl::ec::EcPoint::from_bytes(&group, point_bytes.as_bytes(), &mut bn_ctx)
            .map_err(|_| crate::KeyParsingError::InvalidKey)?
    } else {
        let mut public_point = openssl::ec::EcPoint::new(&group)?;
        public_point
            .mul_generator(&group, &private_number, &bn_ctx)
            .map_err(|_| crate::KeyParsingError::InvalidKey)?;
        public_point
    };

    let ec_key =
        openssl::ec::EcKey::from_private_components(&group, &private_number, &public_point)
            .map_err(|_| KeyParsingError::InvalidKey)?;
    ec_key
        .check_key()
        .map_err(|_| KeyParsingError::InvalidKey)?;
    Ok(openssl::pkey::PKey::from_ec_key(ec_key)?)
}
