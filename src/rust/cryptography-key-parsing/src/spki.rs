// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, BasicDHParams, DHXParams, DssParams, EcParameters,
    SubjectPublicKeyInfo,
};

use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

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

// these functions exist because you can't use conditional compilation easily
// in `else if` chain.
fn is_ed448(id: openssl::pkey::Id) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))] {
            id == openssl::pkey::Id::ED448
        } else {
            _ = id;
            false
        }
    }
}

fn is_x448(id: openssl::pkey::Id) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))] {
            id == openssl::pkey::Id::X448
        } else {
            _ = id;
            false
        }
    }
}

pub fn serialize_public_key(
    pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>,
) -> KeySerializationResult<Vec<u8>> {
    let p_bytes;
    let q_bytes;
    let g_bytes;
    let q_bytes_opt: Option<Vec<u8>>;

    let (params, public_key_bytes) = if let Ok(rsa) = pkey.rsa() {
        let pkcs1_der = crate::rsa::serialize_pkcs1_public_key(&rsa)?;
        (AlgorithmParameters::Rsa(Some(())), pkcs1_der)
    } else if let Ok(ec) = pkey.ec_key() {
        let curve_nid = ec.group().curve_name();
        let curve_oid = match curve_nid {
            Some(openssl::nid::Nid::X9_62_PRIME192V1) => cryptography_x509::oid::EC_SECP192R1,
            Some(openssl::nid::Nid::SECP224R1) => cryptography_x509::oid::EC_SECP224R1,
            Some(openssl::nid::Nid::X9_62_PRIME256V1) => cryptography_x509::oid::EC_SECP256R1,
            Some(openssl::nid::Nid::SECP384R1) => cryptography_x509::oid::EC_SECP384R1,
            Some(openssl::nid::Nid::SECP521R1) => cryptography_x509::oid::EC_SECP521R1,
            Some(openssl::nid::Nid::SECP256K1) => cryptography_x509::oid::EC_SECP256K1,
            Some(openssl::nid::Nid::SECT233R1) => cryptography_x509::oid::EC_SECT233R1,
            Some(openssl::nid::Nid::SECT283R1) => cryptography_x509::oid::EC_SECT283R1,
            Some(openssl::nid::Nid::SECT409R1) => cryptography_x509::oid::EC_SECT409R1,
            Some(openssl::nid::Nid::SECT571R1) => cryptography_x509::oid::EC_SECT571R1,
            Some(openssl::nid::Nid::SECT163R2) => cryptography_x509::oid::EC_SECT163R2,
            Some(openssl::nid::Nid::SECT163K1) => cryptography_x509::oid::EC_SECT163K1,
            Some(openssl::nid::Nid::SECT233K1) => cryptography_x509::oid::EC_SECT233K1,
            Some(openssl::nid::Nid::SECT283K1) => cryptography_x509::oid::EC_SECT283K1,
            Some(openssl::nid::Nid::SECT409K1) => cryptography_x509::oid::EC_SECT409K1,
            Some(openssl::nid::Nid::SECT571K1) => cryptography_x509::oid::EC_SECT571K1,
            #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
            Some(openssl::nid::Nid::BRAINPOOL_P256R1) => cryptography_x509::oid::EC_BRAINPOOLP256R1,
            #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
            Some(openssl::nid::Nid::BRAINPOOL_P384R1) => cryptography_x509::oid::EC_BRAINPOOLP384R1,
            #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
            Some(openssl::nid::Nid::BRAINPOOL_P512R1) => cryptography_x509::oid::EC_BRAINPOOLP512R1,
            _ => unimplemented!("Unknown curve"),
        };

        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let point_bytes = ec.public_key().to_bytes(
            ec.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;

        (
            AlgorithmParameters::Ec(EcParameters::NamedCurve(curve_oid)),
            point_bytes,
        )
    } else if pkey.id() == openssl::pkey::Id::ED25519 {
        let raw_bytes = pkey.raw_public_key()?;
        (AlgorithmParameters::Ed25519, raw_bytes)
    } else if pkey.id() == openssl::pkey::Id::X25519 {
        let raw_bytes = pkey.raw_public_key()?;
        (AlgorithmParameters::X25519, raw_bytes)
    } else if is_ed448(pkey.id()) {
        let raw_bytes = pkey.raw_public_key()?;
        (AlgorithmParameters::Ed448, raw_bytes)
    } else if is_x448(pkey.id()) {
        let raw_bytes = pkey.raw_public_key()?;
        (AlgorithmParameters::X448, raw_bytes)
    } else if let Ok(dsa) = pkey.dsa() {
        p_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.p())?;
        q_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.q())?;
        g_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.g())?;
        let pub_key_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dsa.pub_key())?;

        let pub_key_int = asn1::BigUint::new(&pub_key_bytes).unwrap();
        let pub_key_der = asn1::write_single(&pub_key_int)?;

        let dsa_params = DssParams {
            p: asn1::BigUint::new(&p_bytes).unwrap(),
            q: asn1::BigUint::new(&q_bytes).unwrap(),
            g: asn1::BigUint::new(&g_bytes).unwrap(),
        };

        (AlgorithmParameters::Dsa(dsa_params), pub_key_der)
    } else if let Ok(dh) = pkey.dh() {
        p_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dh.prime_p())?;
        g_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dh.generator())?;
        q_bytes_opt = dh
            .prime_q()
            .map(cryptography_openssl::utils::bn_to_big_endian_bytes)
            .transpose()?;
        let pub_key_bytes = cryptography_openssl::utils::bn_to_big_endian_bytes(dh.public_key())?;

        let pub_key_int = asn1::BigUint::new(&pub_key_bytes).unwrap();
        let pub_key_der = asn1::write_single(&pub_key_int)?;

        let params = if let Some(ref q_bytes) = q_bytes_opt {
            let dhx_params = DHXParams {
                p: asn1::BigUint::new(&p_bytes).unwrap(),
                g: asn1::BigUint::new(&g_bytes).unwrap(),
                q: asn1::BigUint::new(q_bytes).unwrap(),
                j: None,
                validation_params: None,
            };
            AlgorithmParameters::Dh(dhx_params)
        } else {
            let basic_params = BasicDHParams {
                p: asn1::BigUint::new(&p_bytes).unwrap(),
                g: asn1::BigUint::new(&g_bytes).unwrap(),
                private_value_length: None,
            };
            AlgorithmParameters::DhKeyAgreement(basic_params)
        };

        (params, pub_key_der)
    } else {
        unimplemented!("Unknown key type");
    };

    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params,
        },
        subject_public_key: asn1::BitString::new(&public_key_bytes, 0).unwrap(),
    };
    Ok(asn1::write_single(&spki)?)
}

#[cfg(test)]
mod tests {
    use super::serialize_public_key;

    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    #[test]
    #[should_panic(expected = "Unknown key type")]
    fn test_serialize_public_key_unknown_key_type() {
        let pkey = openssl::pkey::PKey::hmac(&[0u8; 16]).unwrap();
        // Expected to panic
        _ = serialize_public_key(&pkey);
    }

    #[cfg(not(any(
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC,
        CRYPTOGRAPHY_IS_LIBRESSL
    )))]
    #[test]
    #[should_panic(expected = "Unknown curve")]
    fn test_serialize_public_key_unknown_curve() {
        let pkey = openssl::pkey::PKey::ec_gen("brainpoolP512t1").unwrap();
        // Expected to panic
        _ = serialize_public_key(&pkey);
    }
}
