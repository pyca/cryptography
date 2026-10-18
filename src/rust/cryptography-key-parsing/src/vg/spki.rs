// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! SubjectPublicKeyInfo, as raw key components.

use cryptography_x509::common::{
    AlgorithmIdentifier, AlgorithmParameters, BasicDHParams, DHXParams, DssParams, EcParameters,
    SubjectPublicKeyInfo,
};

use crate::raw::{DhParameters, DhPublicKey, DsaParameters, DsaPublicKey, EcPublicKey, PublicKey};
use crate::vg_util::{big_uint, der_uint, ec_params_to_curve, uint};
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult, ParsedPublicKey};

pub fn parse_public_key(data: &[u8]) -> KeyParsingResult<ParsedPublicKey> {
    let k = asn1::parse_single::<SubjectPublicKeyInfo<'_>>(data)?;
    parse_public_key_info(k).map(ParsedPublicKey::Raw)
}

/// A fixed-length raw public key.
fn fixed<const N: usize>(data: &[u8]) -> KeyParsingResult<[u8; N]> {
    data.try_into().map_err(|_| KeyParsingError::InvalidKey)
}

/// A variable-length raw public key that must be `len` bytes long.
fn sized(data: &[u8], len: usize) -> KeyParsingResult<Vec<u8>> {
    if data.len() != len {
        return Err(KeyParsingError::InvalidKey);
    }
    Ok(data.to_vec())
}

pub(crate) fn parse_public_key_info(k: SubjectPublicKeyInfo<'_>) -> KeyParsingResult<PublicKey> {
    // The subjectPublicKey BIT STRING wraps whole octets for every key type
    // we support, so a non-zero unused-bits count is a malformed encoding.
    if k.subject_public_key.padding_bits() != 0 {
        return Err(KeyParsingError::InvalidKey);
    }
    let data = k.subject_public_key.as_bytes();

    Ok(match k.algorithm.params {
        AlgorithmParameters::Ec(ec_params) => PublicKey::Ec(EcPublicKey {
            curve: ec_params_to_curve(&ec_params)?,
            // The backend checks the point's encoding and that it is on the
            // curve.
            point: data.to_vec(),
        }),
        AlgorithmParameters::Ed25519 => PublicKey::Ed25519(fixed(data)?),
        AlgorithmParameters::Ed448 => PublicKey::Ed448(fixed(data)?),
        AlgorithmParameters::X25519 => PublicKey::X25519(fixed(data)?),
        AlgorithmParameters::X448 => PublicKey::X448(fixed(data)?),
        AlgorithmParameters::Rsa(_) => PublicKey::Rsa(crate::rsa::parse_pkcs1_public_key(data)?),
        // RSA-PSS keys are treated the same as bare RSA keys.
        AlgorithmParameters::RsaPss(_) => {
            PublicKey::RsaPss(crate::rsa::parse_pkcs1_public_key(data)?)
        }
        AlgorithmParameters::Dsa(dsa_params) => {
            let y = asn1::parse_single::<asn1::BigUint<'_>>(data)?;
            PublicKey::Dsa(DsaPublicKey {
                params: DsaParameters {
                    p: uint(dsa_params.p),
                    q: uint(dsa_params.q),
                    g: uint(dsa_params.g),
                },
                y: uint(y),
            })
        }
        AlgorithmParameters::Dh(dh_params) => {
            let y = asn1::parse_single::<asn1::BigUint<'_>>(data)?;
            PublicKey::Dh(DhPublicKey {
                params: DhParameters {
                    p: uint(dh_params.p),
                    g: uint(dh_params.g),
                    q: Some(uint(dh_params.q)),
                },
                y: uint(y),
            })
        }
        AlgorithmParameters::DhKeyAgreement(dh_params) => {
            let y = asn1::parse_single::<asn1::BigUint<'_>>(data)?;
            PublicKey::Dh(DhPublicKey {
                params: DhParameters {
                    p: uint(dh_params.p),
                    g: uint(dh_params.g),
                    q: None,
                },
                y: uint(y),
            })
        }
        AlgorithmParameters::MlKem768 => PublicKey::MlKem768(sized(data, 1184)?),
        AlgorithmParameters::MlKem1024 => PublicKey::MlKem1024(sized(data, 1568)?),
        AlgorithmParameters::MlDsa44 => PublicKey::MlDsa44(sized(data, 1312)?),
        AlgorithmParameters::MlDsa65 => PublicKey::MlDsa65(sized(data, 1952)?),
        AlgorithmParameters::MlDsa87 => PublicKey::MlDsa87(sized(data, 2592)?),
        _ => {
            return Err(KeyParsingError::UnsupportedKeyType(
                k.algorithm.oid().clone(),
            ))
        }
    })
}

/// The algorithm parameters of DH domain parameters: X9.42 (`dhpublicnumber`)
/// with `q`, PKCS #3 (`dhKeyAgreement`) without. `p`, `g` and `q` are the
/// DER encodings of the components.
pub(crate) fn dh_algorithm_parameters<'a>(
    p: &'a [u8],
    g: &'a [u8],
    q: Option<&'a [u8]>,
) -> AlgorithmParameters<'a> {
    match q {
        Some(q) => AlgorithmParameters::Dh(DHXParams {
            p: big_uint(p),
            g: big_uint(g),
            q: big_uint(q),
            j: None,
            validation_params: None,
        }),
        None => AlgorithmParameters::DhKeyAgreement(BasicDHParams {
            p: big_uint(p),
            g: big_uint(g),
            private_value_length: None,
        }),
    }
}

/// The DER encodings of DSA or DH domain parameters' components.
pub(crate) struct EncodedParams {
    pub(crate) p: Vec<u8>,
    pub(crate) q: Option<Vec<u8>>,
    pub(crate) g: Vec<u8>,
}

impl EncodedParams {
    pub(crate) fn dsa(params: &DsaParameters) -> Self {
        EncodedParams {
            p: der_uint(&params.p),
            q: Some(der_uint(&params.q)),
            g: der_uint(&params.g),
        }
    }

    pub(crate) fn dh(params: &DhParameters) -> Self {
        EncodedParams {
            p: der_uint(&params.p),
            q: params.q.as_deref().map(der_uint),
            g: der_uint(&params.g),
        }
    }

    pub(crate) fn dsa_algorithm_parameters(&self) -> AlgorithmParameters<'_> {
        AlgorithmParameters::Dsa(DssParams {
            p: big_uint(&self.p),
            q: big_uint(self.q.as_ref().unwrap()),
            g: big_uint(&self.g),
        })
    }

    pub(crate) fn dh_algorithm_parameters(&self) -> AlgorithmParameters<'_> {
        dh_algorithm_parameters(&self.p, &self.g, self.q.as_deref())
    }
}

pub fn serialize_public_key(key: &PublicKey) -> KeySerializationResult<Vec<u8>> {
    let encoded_params;
    let (params, public_key_bytes) = match key {
        // As with OpenSSL, which parses RSA-PSS keys into plain RSA keys,
        // they are serialized as `rsaEncryption` keys.
        PublicKey::Rsa(rsa) | PublicKey::RsaPss(rsa) => (
            AlgorithmParameters::Rsa(Some(())),
            crate::rsa::serialize_pkcs1_public_key(rsa)?,
        ),
        PublicKey::Ec(ec) => (
            AlgorithmParameters::Ec(EcParameters::NamedCurve(ec.curve.clone())),
            ec.point.clone(),
        ),
        PublicKey::Ed25519(k) => (AlgorithmParameters::Ed25519, k.to_vec()),
        PublicKey::Ed448(k) => (AlgorithmParameters::Ed448, k.to_vec()),
        PublicKey::X25519(k) => (AlgorithmParameters::X25519, k.to_vec()),
        PublicKey::X448(k) => (AlgorithmParameters::X448, k.to_vec()),
        PublicKey::Dsa(dsa) => {
            encoded_params = EncodedParams::dsa(&dsa.params);
            let y = der_uint(&dsa.y);
            (
                encoded_params.dsa_algorithm_parameters(),
                asn1::write_single(&big_uint(&y))?,
            )
        }
        PublicKey::Dh(dh) => {
            encoded_params = EncodedParams::dh(&dh.params);
            let y = der_uint(&dh.y);
            (
                encoded_params.dh_algorithm_parameters(),
                asn1::write_single(&big_uint(&y))?,
            )
        }
        PublicKey::MlKem768(k) => (AlgorithmParameters::MlKem768, k.clone()),
        PublicKey::MlKem1024(k) => (AlgorithmParameters::MlKem1024, k.clone()),
        PublicKey::MlDsa44(k) => (AlgorithmParameters::MlDsa44, k.clone()),
        PublicKey::MlDsa65(k) => (AlgorithmParameters::MlDsa65, k.clone()),
        PublicKey::MlDsa87(k) => (AlgorithmParameters::MlDsa87, k.clone()),
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
    use super::*;
    use crate::vg_util::{pem_vector, vector};
    use cryptography_x509::oid;

    fn parse(data: &[u8]) -> KeyParsingResult<PublicKey> {
        parse_public_key(data).map(|ParsedPublicKey::Raw(k)| k)
    }

    /// Parses `der` and checks that serializing gives it back.
    fn round_trip(der: &[u8]) -> PublicKey {
        let key = parse(der).ok().unwrap();
        assert_eq!(serialize_public_key(&key).ok().unwrap(), der);
        key
    }

    #[test]
    fn test_vectors() {
        assert!(matches!(
            round_trip(vector!("DER_Serialization/rsa_public_key.der")),
            PublicKey::Rsa(_)
        ));
        assert!(matches!(
            round_trip(&pem_vector!("PEM_Serialization/rsa_public_key.pem")),
            PublicKey::Rsa(_)
        ));
        let PublicKey::Ec(ec) = round_trip(vector!("DER_Serialization/ec_public_key.der")) else {
            panic!()
        };
        assert_eq!(ec.curve, oid::EC_SECP256R1);
        assert!(matches!(
            round_trip(vector!("DER_Serialization/dsa_public_key.der")),
            PublicKey::Dsa(_)
        ));
        assert!(matches!(
            round_trip(vector!("Ed25519/ed25519-pub.der")),
            PublicKey::Ed25519(_)
        ));
        assert!(matches!(
            round_trip(vector!("Ed448/ed448-pub.der")),
            PublicKey::Ed448(_)
        ));
        assert!(matches!(
            round_trip(vector!("X25519/x25519-pub.der")),
            PublicKey::X25519(_)
        ));
        assert!(matches!(
            round_trip(vector!("X448/x448-pub.der")),
            PublicKey::X448(_)
        ));
        assert!(matches!(
            round_trip(vector!("MLDSA/mldsa44_pub.der")),
            PublicKey::MlDsa44(_)
        ));
        let PublicKey::Dh(dh) = round_trip(vector!("DH/dhpub.der")) else {
            panic!()
        };
        assert!(dh.params.q.is_none());
        let PublicKey::Dh(dh) = round_trip(vector!("DH/dhpub_rfc5114_2.der")) else {
            panic!()
        };
        assert!(dh.params.q.is_some());
    }

    #[test]
    fn test_rsa_pss() {
        let der = vector!("PKCS8/rsa_pss_2048_pub.der");
        let PublicKey::RsaPss(rsa) = parse(der).ok().unwrap() else {
            panic!()
        };
        assert!(ParsedPublicKey::Raw(PublicKey::RsaPss(rsa.clone())).is_rsa());
        // Serialized as an `rsaEncryption` key, as with OpenSSL.
        let reserialized = serialize_public_key(&PublicKey::RsaPss(rsa.clone()))
            .ok()
            .unwrap();
        assert_eq!(
            reserialized,
            serialize_public_key(&PublicKey::Rsa(rsa)).ok().unwrap()
        );
    }

    #[test]
    fn test_errors() {
        assert!(matches!(
            parse(vector!("Ed25519/ed25519-pub-non-zero-unused-bits.der")),
            Err(KeyParsingError::InvalidKey)
        ));
        assert!(matches!(
            parse(vector!(
                "DER_Serialization/dsa_public_key_invalid_bit_string.der"
            )),
            Err(KeyParsingError::InvalidKey | KeyParsingError::Parse(_))
        ));
        assert!(matches!(
            parse(vector!("DER_Serialization/dsa_public_key_no_params.der")),
            Err(KeyParsingError::Parse(_) | KeyParsingError::UnsupportedKeyType(_))
        ));
        assert!(matches!(
            parse(&pem_vector!("EC/sect163k1-spki.pem")),
            Err(KeyParsingError::UnsupportedEllipticCurve(_))
        ));
        assert!(matches!(
            parse(&pem_vector!("EC/secp256r1-pub-explicit-seed.pem")),
            Ok(PublicKey::Ec(EcPublicKey {
                curve: oid::EC_SECP256R1,
                ..
            }))
        ));
        assert!(matches!(
            parse(&pem_vector!("EC/secp256k1-pub-explicit-no-seed.pem")),
            Err(KeyParsingError::ExplicitCurveUnsupported)
        ));

        // Raw keys of the wrong length.
        for (params, len) in [
            (AlgorithmParameters::Ed25519, 32),
            (AlgorithmParameters::Ed448, 57),
            (AlgorithmParameters::X25519, 32),
            (AlgorithmParameters::X448, 56),
            (AlgorithmParameters::MlKem768, 1184),
            (AlgorithmParameters::MlKem1024, 1568),
            (AlgorithmParameters::MlDsa44, 1312),
            (AlgorithmParameters::MlDsa65, 1952),
            (AlgorithmParameters::MlDsa87, 2592),
        ] {
            for (n, ok) in [(len, true), (len - 1, false), (len + 1, false)] {
                let data = vec![7; n];
                let spki = SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: params.clone(),
                    },
                    subject_public_key: asn1::BitString::new(&data, 0).unwrap(),
                };
                let der = asn1::write_single(&spki).unwrap();
                if ok {
                    assert_eq!(
                        serialize_public_key(&parse(&der).ok().unwrap())
                            .ok()
                            .unwrap(),
                        der
                    );
                } else {
                    assert!(matches!(parse(&der), Err(KeyParsingError::InvalidKey)));
                }
            }
        }

        // An unsupported algorithm.
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Other(oid::EC_SECP256R1, None),
            },
            subject_public_key: asn1::BitString::new(&[1], 0).unwrap(),
        };
        let der = asn1::write_single(&spki).unwrap();
        assert!(matches!(
            parse(&der),
            Err(KeyParsingError::UnsupportedKeyType(oid::EC_SECP256R1))
        ));
    }
}
