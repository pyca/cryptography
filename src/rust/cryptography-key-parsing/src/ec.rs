// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::EcParameters;

use crate::common::EcPrivateKey;
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

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
    let curve_oid = crate::common::ec_params_to_curve_oid(params)?;
    let curve_nid = match &curve_oid {
        &cryptography_x509::oid::EC_SECP192R1 => openssl::nid::Nid::X9_62_PRIME192V1,
        &cryptography_x509::oid::EC_SECP224R1 => openssl::nid::Nid::SECP224R1,
        &cryptography_x509::oid::EC_SECP256R1 => openssl::nid::Nid::X9_62_PRIME256V1,
        &cryptography_x509::oid::EC_SECP384R1 => openssl::nid::Nid::SECP384R1,
        &cryptography_x509::oid::EC_SECP521R1 => openssl::nid::Nid::SECP521R1,

        &cryptography_x509::oid::EC_SECP256K1 => openssl::nid::Nid::SECP256K1,

        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        &cryptography_x509::oid::EC_BRAINPOOLP256R1 => openssl::nid::Nid::BRAINPOOL_P256R1,
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        &cryptography_x509::oid::EC_BRAINPOOLP384R1 => openssl::nid::Nid::BRAINPOOL_P384R1,
        #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
        &cryptography_x509::oid::EC_BRAINPOOLP512R1 => openssl::nid::Nid::BRAINPOOL_P512R1,

        _ => return Err(KeyParsingError::UnsupportedEllipticCurve(curve_oid)),
    };

    openssl::ec::EcGroup::from_curve_name(curve_nid)
        .map_err(|_| KeyParsingError::UnsupportedEllipticCurve(curve_oid))
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

    let private_key_bytes = ec
        .private_key()
        .to_vec_padded(ec.group().order_bits().div_ceil(8).try_into().unwrap())?;

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
    let (ec_private_key, params) = crate::common::parse_ec_private_key(data, ec_params)?;
    let group = ec_params_to_group(&params)?;

    if ec_private_key.private_key.len() != group.order_bits().div_ceil(8).try_into().unwrap() {
        return Err(crate::KeyParsingError::TruncatedEcPrivateKey);
    }

    let private_number = openssl::bn::BigNum::from_slice(ec_private_key.private_key)?;
    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let public_point = if let Some(point_bytes) = ec_private_key.public_key {
        // The publicKey BIT STRING holds an octet-aligned EC point, so a
        // non-zero unused-bits count is a malformed encoding.
        if point_bytes.padding_bits() != 0 {
            return Err(crate::KeyParsingError::InvalidKey);
        }
        openssl::ec::EcPoint::from_bytes(&group, point_bytes.as_bytes(), &mut bn_ctx)
            .map_err(|_| crate::KeyParsingError::InvalidKey)?
    } else {
        let mut public_point = openssl::ec::EcPoint::new(&group)?;
        public_point
            .mul_generator2(&group, &private_number, &mut bn_ctx)
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
