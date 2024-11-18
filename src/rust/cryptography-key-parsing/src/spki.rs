// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{AlgorithmParameters, SubjectPublicKeyInfo};

use crate::{KeyParsingError, KeyParsingResult};

pub fn parse_public_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    let k = asn1::parse_single::<SubjectPublicKeyInfo<'_>>(data)?;

    match k.algorithm.params {
        AlgorithmParameters::Ec(ec_params) => {
            let group = crate::ec::ec_params_to_group(&ec_params)?;
            let mut bn_ctx = openssl::bn::BigNumContext::new()?;
            let ec_point = openssl::ec::EcPoint::from_bytes(
                &group,
                k.subject_public_key.as_bytes(),
                &mut bn_ctx,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?;
            let ec_key = openssl::ec::EcKey::from_public_key(&group, &ec_point)?;
            Ok(openssl::pkey::PKey::from_ec_key(ec_key)?)
        }
        AlgorithmParameters::Ed25519 => Ok(openssl::pkey::PKey::public_key_from_raw_bytes(
            k.subject_public_key.as_bytes(),
            openssl::pkey::Id::ED25519,
        )
        .map_err(|_| KeyParsingError::InvalidKey)?),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::Ed448 => Ok(openssl::pkey::PKey::public_key_from_raw_bytes(
            k.subject_public_key.as_bytes(),
            openssl::pkey::Id::ED448,
        )
        .map_err(|_| KeyParsingError::InvalidKey)?),
        AlgorithmParameters::X25519 => Ok(openssl::pkey::PKey::public_key_from_raw_bytes(
            k.subject_public_key.as_bytes(),
            openssl::pkey::Id::X25519,
        )
        .map_err(|_| KeyParsingError::InvalidKey)?),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::X448 => Ok(openssl::pkey::PKey::public_key_from_raw_bytes(
            k.subject_public_key.as_bytes(),
            openssl::pkey::Id::X448,
        )
        .map_err(|_| KeyParsingError::InvalidKey)?),
        AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_) => {
            // RSA-PSS keys are treated the same as bare RSA keys.
            crate::rsa::parse_pkcs1_public_key(k.subject_public_key.as_bytes())
        }
        AlgorithmParameters::Dsa(dsa_params) => {
            let p = openssl::bn::BigNum::from_slice(dsa_params.p.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dsa_params.q.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dsa_params.g.as_bytes())?;

            let pub_key_int =
                asn1::parse_single::<asn1::BigUint<'_>>(k.subject_public_key.as_bytes())?;
            let pub_key = openssl::bn::BigNum::from_slice(pub_key_int.as_bytes())?;

            let dsa = openssl::dsa::Dsa::from_public_components(p, q, g, pub_key)?;
            Ok(openssl::pkey::PKey::from_dsa(dsa)?)
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::Dh(dh_params) => {
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dh_params.q.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;
            let dh = openssl::dh::Dh::from_pqg(p, Some(q), g)?;

            let pub_key_int =
                asn1::parse_single::<asn1::BigUint<'_>>(k.subject_public_key.as_bytes())?;
            let pub_key = openssl::bn::BigNum::from_slice(pub_key_int.as_bytes())?;
            let dh = dh.set_public_key(pub_key)?;

            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::DhKeyAgreement(dh_params) => {
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;
            let dh = openssl::dh::Dh::from_pqg(p, None, g)?;

            let pub_key_int =
                asn1::parse_single::<asn1::BigUint<'_>>(k.subject_public_key.as_bytes())?;
            let pub_key = openssl::bn::BigNum::from_slice(pub_key_int.as_bytes())?;
            let dh = dh.set_public_key(pub_key)?;

            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }
        _ => Err(KeyParsingError::UnsupportedKeyType(
            k.algorithm.oid().clone(),
        )),
    }
}
