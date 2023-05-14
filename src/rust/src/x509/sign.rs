// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use crate::x509::certificate;
use cryptography_x509::{common, oid};

#[derive(Debug, PartialEq)]
pub(crate) enum KeyType {
    Rsa,
    Dsa,
    Ec,
    Ed25519,
    Ed448,
}

enum HashType {
    None,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

fn identify_key_type(py: pyo3::Python<'_>, private_key: &pyo3::PyAny) -> pyo3::PyResult<KeyType> {
    let rsa_private_key: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.rsa"
        ))?
        .getattr(pyo3::intern!(py, "RSAPrivateKey"))?
        .extract()?;
    let dsa_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.dsa"
        ))?
        .getattr(pyo3::intern!(py, "DSAPrivateKey"))?
        .extract()?;
    let ec_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ec"
        ))?
        .getattr(pyo3::intern!(py, "EllipticCurvePrivateKey"))?
        .extract()?;
    let ed25519_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ed25519"
        ))?
        .getattr(pyo3::intern!(py, "Ed25519PrivateKey"))?
        .extract()?;
    let ed448_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ed448"
        ))?
        .getattr(pyo3::intern!(py, "Ed448PrivateKey"))?
        .extract()?;

    if private_key.is_instance(rsa_private_key)? {
        Ok(KeyType::Rsa)
    } else if private_key.is_instance(dsa_key_type)? {
        Ok(KeyType::Dsa)
    } else if private_key.is_instance(ec_key_type)? {
        Ok(KeyType::Ec)
    } else if private_key.is_instance(ed25519_key_type)? {
        Ok(KeyType::Ed25519)
    } else if private_key.is_instance(ed448_key_type)? {
        Ok(KeyType::Ed448)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "Key must be an rsa, dsa, ec, ed25519, or ed448 private key.",
        ))
    }
}

fn identify_hash_type(
    py: pyo3::Python<'_>,
    hash_algorithm: &pyo3::PyAny,
) -> pyo3::PyResult<HashType> {
    if hash_algorithm.is_none() {
        return Ok(HashType::None);
    }

    let hash_algorithm_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
        .getattr(pyo3::intern!(py, "HashAlgorithm"))?
        .extract()?;
    if !hash_algorithm.is_instance(hash_algorithm_type)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm.",
        ));
    }

    match hash_algorithm
        .getattr(pyo3::intern!(py, "name"))?
        .extract()?
    {
        "sha224" => Ok(HashType::Sha224),
        "sha256" => Ok(HashType::Sha256),
        "sha384" => Ok(HashType::Sha384),
        "sha512" => Ok(HashType::Sha512),
        "sha3-224" => Ok(HashType::Sha3_224),
        "sha3-256" => Ok(HashType::Sha3_256),
        "sha3-384" => Ok(HashType::Sha3_384),
        "sha3-512" => Ok(HashType::Sha3_512),
        name => Err(exceptions::UnsupportedAlgorithm::new_err(format!(
            "Hash algorithm {:?} not supported for signatures",
            name
        ))),
    }
}

fn compute_pss_salt_length<'p>(
    py: pyo3::Python<'p>,
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
    rsa_padding: &'p pyo3::PyAny,
) -> pyo3::PyResult<u16> {
    let padding_mod = py.import(pyo3::intern!(
        py,
        "cryptography.hazmat.primitives.asymmetric.padding"
    ))?;
    let maxlen = padding_mod.getattr(pyo3::intern!(py, "_MaxLength"))?;
    let digestlen = padding_mod.getattr(pyo3::intern!(py, "_DigestLength"))?;
    let py_saltlen = rsa_padding.getattr(pyo3::intern!(py, "_salt_length"))?;
    if py_saltlen.is_instance(maxlen)? {
        padding_mod
            .getattr(pyo3::intern!(py, "calculate_max_pss_salt_length"))?
            .call1((private_key, hash_algorithm))?
            .extract::<u16>()
    } else if py_saltlen.is_instance(digestlen)? {
        hash_algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<u16>()
    } else if py_saltlen.is_instance(py.get_type::<pyo3::types::PyLong>())? {
        py_saltlen.extract::<u16>()
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "salt_length must be an int, MaxLength, or DigestLength.",
        ))
    }
}

pub(crate) fn compute_signature_algorithm<'p>(
    py: pyo3::Python<'p>,
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
    rsa_padding: &'p pyo3::PyAny,
) -> pyo3::PyResult<common::AlgorithmIdentifier<'static>> {
    let key_type = identify_key_type(py, private_key)?;
    let hash_type = identify_hash_type(py, hash_algorithm)?;

    let pss_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.padding"
        ))?
        .getattr(pyo3::intern!(py, "PSS"))?
        .extract()?;
    // If this is RSA-PSS we need to compute the signature algorithm from the
    // parameters provided in rsa_padding.
    if !rsa_padding.is_none() && rsa_padding.is_instance(pss_type)? {
        let hash_alg_params = identify_alg_params_for_hash_type(hash_type)?;
        let hash_algorithm_id = common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: hash_alg_params,
        };
        let salt_length = compute_pss_salt_length(py, private_key, hash_algorithm, rsa_padding)?;
        let py_mgf_alg = rsa_padding
            .getattr(pyo3::intern!(py, "_mgf"))?
            .getattr(pyo3::intern!(py, "_algorithm"))?;
        let mgf_hash_type = identify_hash_type(py, py_mgf_alg)?;
        let mgf_alg = common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: identify_alg_params_for_hash_type(mgf_hash_type)?,
        };
        let params =
            common::AlgorithmParameters::RsaPss(Some(Box::new(common::RsaPssParameters {
                hash_algorithm: hash_algorithm_id,
                mask_gen_algorithm: common::MaskGenAlgorithm {
                    oid: oid::MGF1_OID,
                    params: mgf_alg,
                },
                salt_length,
                _trailer_field: 1,
            })));

        return Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params,
        });
    }
    // It's not an RSA PSS signature, so we compute the signature algorithm from
    // the union of key type and hash type.
    match (key_type, hash_type) {
        (KeyType::Ed25519, HashType::None) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::Ed25519,
        }),
        (KeyType::Ed448, HashType::None) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::Ed448,
        }),
        (KeyType::Ed25519 | KeyType::Ed448, _) => Err(pyo3::exceptions::PyValueError::new_err(
            "Algorithm must be None when signing via ed25519 or ed448",
        )),

        (KeyType::Ec, HashType::Sha224) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha224,
        }),
        (KeyType::Ec, HashType::Sha256) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha256,
        }),
        (KeyType::Ec, HashType::Sha384) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha384,
        }),
        (KeyType::Ec, HashType::Sha512) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha512,
        }),
        (KeyType::Ec, HashType::Sha3_224) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha3_224,
        }),
        (KeyType::Ec, HashType::Sha3_256) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha3_256,
        }),
        (KeyType::Ec, HashType::Sha3_384) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha3_384,
        }),
        (KeyType::Ec, HashType::Sha3_512) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::EcDsaWithSha3_512,
        }),

        (KeyType::Rsa, HashType::Sha224) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha224(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha256) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha256(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha384) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha384(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha512) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha512(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha3_224) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha3_224(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha3_256) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha3_256(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha3_384) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha3_384(Some(())),
        }),
        (KeyType::Rsa, HashType::Sha3_512) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::RsaWithSha3_512(Some(())),
        }),

        (KeyType::Dsa, HashType::Sha224) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::DsaWithSha224,
        }),
        (KeyType::Dsa, HashType::Sha256) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::DsaWithSha256,
        }),
        (KeyType::Dsa, HashType::Sha384) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::DsaWithSha384,
        }),
        (KeyType::Dsa, HashType::Sha512) => Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::DsaWithSha512,
        }),
        (
            KeyType::Dsa,
            HashType::Sha3_224 | HashType::Sha3_256 | HashType::Sha3_384 | HashType::Sha3_512,
        ) => Err(exceptions::UnsupportedAlgorithm::new_err(
            "SHA3 hashes are not supported with DSA keys",
        )),
        (_, HashType::None) => Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm, not None.",
        )),
    }
}

pub(crate) fn sign_data<'p>(
    py: pyo3::Python<'p>,
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
    rsa_padding: &'p pyo3::PyAny,
    data: &[u8],
) -> pyo3::PyResult<&'p [u8]> {
    let key_type = identify_key_type(py, private_key)?;

    let signature = match key_type {
        KeyType::Ed25519 | KeyType::Ed448 => {
            private_key.call_method1(pyo3::intern!(py, "sign"), (data,))?
        }
        KeyType::Ec => {
            let ec_mod = py.import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.ec"
            ))?;
            let ecdsa = ec_mod
                .getattr(pyo3::intern!(py, "ECDSA"))?
                .call1((hash_algorithm,))?;
            private_key.call_method1(pyo3::intern!(py, "sign"), (data, ecdsa))?
        }
        KeyType::Rsa => {
            let mut padding = rsa_padding;
            if padding.is_none() {
                let padding_mod = py.import(pyo3::intern!(
                    py,
                    "cryptography.hazmat.primitives.asymmetric.padding"
                ))?;
                padding = padding_mod
                    .getattr(pyo3::intern!(py, "PKCS1v15"))?
                    .call0()?;
            }
            private_key.call_method1(pyo3::intern!(py, "sign"), (data, padding, hash_algorithm))?
        }
        KeyType::Dsa => {
            private_key.call_method1(pyo3::intern!(py, "sign"), (data, hash_algorithm))?
        }
    };
    signature.extract()
}

pub(crate) fn verify_signature_with_signature_algorithm<'p>(
    py: pyo3::Python<'p>,
    issuer_public_key: &'p pyo3::PyAny,
    signature_algorithm: &common::AlgorithmIdentifier<'_>,
    signature: &[u8],
    data: &[u8],
) -> CryptographyResult<()> {
    let key_type = identify_public_key_type(py, issuer_public_key)?;
    let sig_key_type = identify_key_type_for_algorithm_params(&signature_algorithm.params)?;
    if key_type != sig_key_type {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Signature algorithm does not match issuer key type",
            ),
        ));
    }
    let py_signature_algorithm_parameters =
        certificate::identify_signature_algorithm_parameters(py, signature_algorithm)?;
    let py_signature_hash_algorithm =
        certificate::identify_signature_hash_algorithm(py, signature_algorithm)?;
    match key_type {
        KeyType::Ed25519 | KeyType::Ed448 => {
            issuer_public_key.call_method1(pyo3::intern!(py, "verify"), (signature, data))?
        }
        KeyType::Ec => issuer_public_key.call_method1(
            pyo3::intern!(py, "verify"),
            (signature, data, py_signature_algorithm_parameters),
        )?,
        KeyType::Rsa => issuer_public_key.call_method1(
            pyo3::intern!(py, "verify"),
            (
                signature,
                data,
                py_signature_algorithm_parameters,
                py_signature_hash_algorithm,
            ),
        )?,
        KeyType::Dsa => issuer_public_key.call_method1(
            pyo3::intern!(py, "verify"),
            (signature, data, py_signature_hash_algorithm),
        )?,
    };
    Ok(())
}

pub(crate) fn identify_public_key_type(
    py: pyo3::Python<'_>,
    public_key: &pyo3::PyAny,
) -> pyo3::PyResult<KeyType> {
    let rsa_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.rsa"
        ))?
        .getattr(pyo3::intern!(py, "RSAPublicKey"))?
        .extract()?;
    let dsa_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.dsa"
        ))?
        .getattr(pyo3::intern!(py, "DSAPublicKey"))?
        .extract()?;
    let ec_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ec"
        ))?
        .getattr(pyo3::intern!(py, "EllipticCurvePublicKey"))?
        .extract()?;
    let ed25519_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ed25519"
        ))?
        .getattr(pyo3::intern!(py, "Ed25519PublicKey"))?
        .extract()?;
    let ed448_key_type: &pyo3::types::PyType = py
        .import(pyo3::intern!(
            py,
            "cryptography.hazmat.primitives.asymmetric.ed448"
        ))?
        .getattr(pyo3::intern!(py, "Ed448PublicKey"))?
        .extract()?;

    if public_key.is_instance(rsa_key_type)? {
        Ok(KeyType::Rsa)
    } else if public_key.is_instance(dsa_key_type)? {
        Ok(KeyType::Dsa)
    } else if public_key.is_instance(ec_key_type)? {
        Ok(KeyType::Ec)
    } else if public_key.is_instance(ed25519_key_type)? {
        Ok(KeyType::Ed25519)
    } else if public_key.is_instance(ed448_key_type)? {
        Ok(KeyType::Ed448)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "Key must be an rsa, dsa, ec, ed25519, or ed448 public key.",
        ))
    }
}

fn identify_key_type_for_algorithm_params(
    params: &common::AlgorithmParameters<'_>,
) -> pyo3::PyResult<KeyType> {
    match params {
        common::AlgorithmParameters::RsaWithSha224(..)
        | common::AlgorithmParameters::RsaWithSha256(..)
        | common::AlgorithmParameters::RsaWithSha384(..)
        | common::AlgorithmParameters::RsaWithSha512(..)
        | common::AlgorithmParameters::RsaWithSha3_224(..)
        | common::AlgorithmParameters::RsaWithSha3_256(..)
        | common::AlgorithmParameters::RsaWithSha3_384(..)
        | common::AlgorithmParameters::RsaWithSha3_512(..)
        | common::AlgorithmParameters::RsaPss(..) => Ok(KeyType::Rsa),
        common::AlgorithmParameters::EcDsaWithSha224
        | common::AlgorithmParameters::EcDsaWithSha256
        | common::AlgorithmParameters::EcDsaWithSha384
        | common::AlgorithmParameters::EcDsaWithSha512
        | common::AlgorithmParameters::EcDsaWithSha3_224
        | common::AlgorithmParameters::EcDsaWithSha3_256
        | common::AlgorithmParameters::EcDsaWithSha3_384
        | common::AlgorithmParameters::EcDsaWithSha3_512 => Ok(KeyType::Ec),
        common::AlgorithmParameters::Ed25519 => Ok(KeyType::Ed25519),
        common::AlgorithmParameters::Ed448 => Ok(KeyType::Ed448),
        common::AlgorithmParameters::DsaWithSha224
        | common::AlgorithmParameters::DsaWithSha256
        | common::AlgorithmParameters::DsaWithSha384
        | common::AlgorithmParameters::DsaWithSha512 => Ok(KeyType::Dsa),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "Unsupported signature algorithm",
        )),
    }
}

fn identify_alg_params_for_hash_type(
    hash_type: HashType,
) -> pyo3::PyResult<common::AlgorithmParameters<'static>> {
    match hash_type {
        HashType::Sha224 => Ok(common::AlgorithmParameters::Sha224(())),
        HashType::Sha256 => Ok(common::AlgorithmParameters::Sha256(())),
        HashType::Sha384 => Ok(common::AlgorithmParameters::Sha384(())),
        HashType::Sha512 => Ok(common::AlgorithmParameters::Sha512(())),
        HashType::Sha3_224 => Ok(common::AlgorithmParameters::Sha3_224(())),
        HashType::Sha3_256 => Ok(common::AlgorithmParameters::Sha3_256(())),
        HashType::Sha3_384 => Ok(common::AlgorithmParameters::Sha3_384(())),
        HashType::Sha3_512 => Ok(common::AlgorithmParameters::Sha3_512(())),
        HashType::None => Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm, not None.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        identify_alg_params_for_hash_type, identify_key_type_for_algorithm_params, HashType,
        KeyType,
    };
    use cryptography_x509::{common, oid};

    #[test]
    fn test_identify_key_type_for_algorithm_params() {
        for (params, keytype) in [
            (
                &common::AlgorithmParameters::RsaWithSha224(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha256(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha384(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha512(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha3_224(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha3_256(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha3_384(Some(())),
                KeyType::Rsa,
            ),
            (
                &common::AlgorithmParameters::RsaWithSha3_512(Some(())),
                KeyType::Rsa,
            ),
            (&common::AlgorithmParameters::EcDsaWithSha224, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha256, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha384, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha512, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha3_224, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha3_256, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha3_384, KeyType::Ec),
            (&common::AlgorithmParameters::EcDsaWithSha3_512, KeyType::Ec),
            (&common::AlgorithmParameters::Ed25519, KeyType::Ed25519),
            (&common::AlgorithmParameters::Ed448, KeyType::Ed448),
            (&common::AlgorithmParameters::DsaWithSha224, KeyType::Dsa),
            (&common::AlgorithmParameters::DsaWithSha256, KeyType::Dsa),
            (&common::AlgorithmParameters::DsaWithSha384, KeyType::Dsa),
            (&common::AlgorithmParameters::DsaWithSha512, KeyType::Dsa),
        ] {
            assert_eq!(
                identify_key_type_for_algorithm_params(params).unwrap(),
                keytype
            );
        }
        assert!(
            identify_key_type_for_algorithm_params(&common::AlgorithmParameters::Other(
                oid::TLS_FEATURE_OID,
                None
            ))
            .is_err()
        );
    }

    #[test]
    fn test_identify_alg_params_for_hash_type() {
        for (hash, params) in [
            (HashType::Sha224, common::AlgorithmParameters::Sha224(())),
            (HashType::Sha256, common::AlgorithmParameters::Sha256(())),
            (HashType::Sha384, common::AlgorithmParameters::Sha384(())),
            (HashType::Sha512, common::AlgorithmParameters::Sha512(())),
            (
                HashType::Sha3_224,
                common::AlgorithmParameters::Sha3_224(()),
            ),
            (
                HashType::Sha3_256,
                common::AlgorithmParameters::Sha3_256(()),
            ),
            (
                HashType::Sha3_384,
                common::AlgorithmParameters::Sha3_384(()),
            ),
            (
                HashType::Sha3_512,
                common::AlgorithmParameters::Sha3_512(()),
            ),
        ] {
            assert_eq!(identify_alg_params_for_hash_type(hash).unwrap(), params);
        }
    }
}
