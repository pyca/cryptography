// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, BasicDHParams, DHXParams, DssParams, EcParameters,
    SubjectPublicKeyInfo,
};

use crate::{
    KeyParsingError, KeyParsingResult, KeySerializationResult, ParsedPublicKey, PublicKeyRef,
};

pub fn parse_public_key(data: &[u8]) -> KeyParsingResult<ParsedPublicKey> {
    parse_public_key_info(asn1::parse_single::<SubjectPublicKeyInfo<'_>>(data)?)
}
pub(crate) fn parse_public_key_info(
    k: SubjectPublicKeyInfo<'_>,
) -> KeyParsingResult<ParsedPublicKey> {
    if k.subject_public_key.padding_bits() != 0 {
        return Err(KeyParsingError::InvalidKey);
    }
    let bytes = k.subject_public_key.as_bytes();
    match k.algorithm.params {
        AlgorithmParameters::Ec(params) => {
            let curve = crate::ec::ec_params_to_group(&params)?;
            Ok(ParsedPublicKey::Ec(
                openssl_bridge::ec::PublicKey::from_encoded(curve, bytes)
                    .map_err(|_| KeyParsingError::InvalidKey)?,
            ))
        }
        AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_) => {
            crate::rsa::parse_pkcs1_public_key(bytes).map(ParsedPublicKey::Rsa)
        }
        AlgorithmParameters::Dsa(params) => {
            let params = openssl_bridge::dsa::ParameterMaterial::from_components(
                openssl_bridge::dsa::Components {
                    p: params.p.as_bytes(),
                    q: params.q.as_bytes(),
                    g: params.g.as_bytes(),
                },
            )?;
            let value = asn1::parse_single::<asn1::BigUint<'_>>(bytes)?;
            Ok(ParsedPublicKey::Dsa(
                openssl_bridge::dsa::PublicKeyMaterial::from_components(params, value.as_bytes())?,
            ))
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::Dh(params) => {
            let params =
                openssl_bridge::dh::Parameters::from_components(openssl_bridge::dh::Components {
                    p: params.p.as_bytes(),
                    q: Some(params.q.as_bytes()),
                    g: params.g.as_bytes(),
                })?;
            let value = asn1::parse_single::<asn1::BigUint<'_>>(bytes)?;
            Ok(ParsedPublicKey::Dh(
                openssl_bridge::dh::PublicKeyMaterial::from_components(params, value.as_bytes())?,
            ))
        }
        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::DhKeyAgreement(params) => {
            let params =
                openssl_bridge::dh::Parameters::from_components(openssl_bridge::dh::Components {
                    p: params.p.as_bytes(),
                    q: None,
                    g: params.g.as_bytes(),
                })?;
            let value = asn1::parse_single::<asn1::BigUint<'_>>(bytes)?;
            Ok(ParsedPublicKey::Dh(
                openssl_bridge::dh::PublicKeyMaterial::from_components(params, value.as_bytes())?,
            ))
        }
        AlgorithmParameters::Ed25519 => Ok(ParsedPublicKey::Ed25519(
            openssl_bridge::curve25519::Ed25519VerifyingKey::from_bytes(
                bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
            )?,
        )),
        AlgorithmParameters::X25519 => Ok(ParsedPublicKey::X25519(
            openssl_bridge::curve25519::X25519PublicKey::from_bytes(
                bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
            )?,
        )),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::Ed448 => Ok(ParsedPublicKey::Ed448(
            openssl_bridge::curve448::Ed448VerifyingKey::from_bytes(
                bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
            )?,
        )),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        AlgorithmParameters::X448 => Ok(ParsedPublicKey::X448(
            openssl_bridge::curve448::X448PublicKey::from_bytes(
                bytes.try_into().map_err(|_| KeyParsingError::InvalidKey)?,
            )?,
        )),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa44 => Ok(ParsedPublicKey::MlDsa(
            openssl_bridge::mldsa::PublicKey::from_bytes(
                openssl_bridge::mldsa::Variant::MlDsa44,
                bytes,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?,
        )),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa65 => Ok(ParsedPublicKey::MlDsa(
            openssl_bridge::mldsa::PublicKey::from_bytes(
                openssl_bridge::mldsa::Variant::MlDsa65,
                bytes,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?,
        )),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlDsa87 => Ok(ParsedPublicKey::MlDsa(
            openssl_bridge::mldsa::PublicKey::from_bytes(
                openssl_bridge::mldsa::Variant::MlDsa87,
                bytes,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?,
        )),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlKem768 => Ok(ParsedPublicKey::MlKem(
            openssl_bridge::mlkem::PublicKey::from_bytes(
                openssl_bridge::mlkem::Variant::MlKem768,
                bytes,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?,
        )),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        AlgorithmParameters::MlKem1024 => Ok(ParsedPublicKey::MlKem(
            openssl_bridge::mlkem::PublicKey::from_bytes(
                openssl_bridge::mlkem::Variant::MlKem1024,
                bytes,
            )
            .map_err(|_| KeyParsingError::InvalidKey)?,
        )),
        _ => Err(KeyParsingError::UnsupportedKeyType(
            k.algorithm.oid().clone(),
        )),
    }
}

/// The closed key view has no HMAC or arbitrary-curve serialization case.
/// ```compile_fail
/// use cryptography_key_parsing::PublicKeyRef;
/// let key = PublicKeyRef::Hmac(&[0; 16]);
/// ```
pub fn serialize_public_key(key: PublicKeyRef<'_>) -> KeySerializationResult<Vec<u8>> {
    let (p_bytes, q_bytes, g_bytes, q_optional);
    let (params, public_key_bytes) = match key {
        PublicKeyRef::Rsa(key) => (
            AlgorithmParameters::Rsa(Some(())),
            crate::rsa::serialize_pkcs1_public_key(key)?,
        ),
        PublicKeyRef::Ec(key) => (
            AlgorithmParameters::Ec(EcParameters::NamedCurve(crate::ec::group_to_curve_oid(
                key.curve(),
            ))),
            key.to_encoded(openssl_bridge::ec::PointEncoding::Uncompressed)?,
        ),
        PublicKeyRef::Dsa(key) => {
            let parts = key.parameters().components();
            p_bytes = crate::utils::integer_bytes(parts.p);
            q_bytes = crate::utils::integer_bytes(parts.q);
            g_bytes = crate::utils::integer_bytes(parts.g);
            let public = crate::utils::integer_bytes(key.public_value());
            (
                AlgorithmParameters::Dsa(DssParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    q: asn1::BigUint::new(q_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                }),
                asn1::write_single(&asn1::BigUint::new(public.as_ref()).unwrap())?,
            )
        }
        PublicKeyRef::Dh(key) => {
            let parts = key.parameters().components();
            p_bytes = crate::utils::integer_bytes(parts.p);
            g_bytes = crate::utils::integer_bytes(parts.g);
            q_optional = parts.q.map(crate::utils::integer_bytes);
            let public = crate::utils::integer_bytes(key.public_value());
            let params = if let Some(ref q) = q_optional {
                AlgorithmParameters::Dh(DHXParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                    q: asn1::BigUint::new(q.as_ref()).unwrap(),
                    j: None,
                    validation_params: None,
                })
            } else {
                AlgorithmParameters::DhKeyAgreement(BasicDHParams {
                    p: asn1::BigUint::new(p_bytes.as_ref()).unwrap(),
                    g: asn1::BigUint::new(g_bytes.as_ref()).unwrap(),
                    private_value_length: None,
                })
            };
            (
                params,
                asn1::write_single(&asn1::BigUint::new(public.as_ref()).unwrap())?,
            )
        }
        PublicKeyRef::Ed25519(key) => (AlgorithmParameters::Ed25519, key.to_bytes()?.to_vec()),
        PublicKeyRef::X25519(key) => (AlgorithmParameters::X25519, key.to_bytes()?.to_vec()),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        PublicKeyRef::Ed448(key) => (AlgorithmParameters::Ed448, key.to_bytes()?.to_vec()),
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        PublicKeyRef::X448(key) => (AlgorithmParameters::X448, key.to_bytes()?.to_vec()),
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        PublicKeyRef::MlDsa(key) => {
            let params = match key.variant() {
                openssl_bridge::mldsa::Variant::MlDsa44 => AlgorithmParameters::MlDsa44,
                openssl_bridge::mldsa::Variant::MlDsa65 => AlgorithmParameters::MlDsa65,
                openssl_bridge::mldsa::Variant::MlDsa87 => AlgorithmParameters::MlDsa87,
            };
            (params, key.as_bytes().to_vec())
        }
        #[cfg(any(
            CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        ))]
        PublicKeyRef::MlKem(key) => {
            let params = match key.variant() {
                openssl_bridge::mlkem::Variant::MlKem768 => AlgorithmParameters::MlKem768,
                openssl_bridge::mlkem::Variant::MlKem1024 => AlgorithmParameters::MlKem1024,
            };
            (params, key.as_bytes().to_vec())
        }
    };
    Ok(asn1::write_single(&SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params,
        },
        subject_public_key: asn1::BitString::new(&public_key_bytes, 0).unwrap(),
    })?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsupported_curve_is_rejected_before_serialization() {
        assert!(openssl_bridge::ec::Curve::from_name("brainpoolP512t1").is_err());
    }
}
