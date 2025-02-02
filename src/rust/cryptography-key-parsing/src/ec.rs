// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::EcParameters;

use crate::{KeyParsingError, KeyParsingResult};

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

                #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
                &cryptography_x509::oid::EC_BRAINPOOLP256R1 => openssl::nid::Nid::BRAINPOOL_P256R1,
                #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
                &cryptography_x509::oid::EC_BRAINPOOLP384R1 => openssl::nid::Nid::BRAINPOOL_P384R1,
                #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
                &cryptography_x509::oid::EC_BRAINPOOLP512R1 => openssl::nid::Nid::BRAINPOOL_P512R1,

                _ => return Err(KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone())),
            };

            Ok(openssl::ec::EcGroup::from_curve_name(curve_nid)
                .map_err(|_| KeyParsingError::UnsupportedEllipticCurve(curve_oid.clone()))?)
        }
        EcParameters::ImplicitCurve(_) | EcParameters::SpecifiedCurve(_) => {
            Err(KeyParsingError::ExplicitCurveUnsupported)
        }
    }
}
