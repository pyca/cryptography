// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};
use crate::x509;
use crate::x509::oid;

use once_cell::sync::Lazy;

static NULL_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    // TODO: kind of verbose way to say "\x05\x00".
    asn1::write_single(&()).unwrap()
});
pub(crate) static NULL_TLV: Lazy<asn1::Tlv<'static>> =
    Lazy::new(|| asn1::parse_single(&NULL_DER).unwrap());

#[derive(Debug, PartialEq)]
pub(crate) enum KeyType {
    Rsa,
    Dsa,
    Ec,
    Ed25519,
    Ed448,
}

#[derive(Debug, PartialEq)]
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
        name => Err(pyo3::PyErr::from_value(
            py.import(pyo3::intern!(py, "cryptography.exceptions"))?
                .call_method1(
                    "UnsupportedAlgorithm",
                    (format!(
                        "Hash algorithm {:?} not supported for signatures",
                        name
                    ),),
                )?,
        )),
    }
}

pub(crate) fn compute_signature_algorithm<'p>(
    py: pyo3::Python<'p>,
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
) -> pyo3::PyResult<x509::AlgorithmIdentifier<'static>> {
    let key_type = identify_key_type(py, private_key)?;
    let hash_type = identify_hash_type(py, hash_algorithm)?;

    match (key_type, hash_type) {
        (KeyType::Ed25519, HashType::None) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ED25519_OID).clone(),
            params: None,
        }),
        (KeyType::Ed448, HashType::None) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ED448_OID).clone(),
            params: None,
        }),
        (KeyType::Ed25519 | KeyType::Ed448, _) => Err(pyo3::exceptions::PyValueError::new_err(
            "Algorithm must be None when signing via ed25519 or ed448",
        )),

        (KeyType::Ec, HashType::Sha224) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA224_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA256_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA384_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha512) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA512_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha3_224) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA3_224_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha3_256) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA3_256_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha3_384) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA3_384_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha3_512) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::ECDSA_WITH_SHA3_512_OID).clone(),
            params: None,
        }),

        (KeyType::Rsa, HashType::Sha224) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA224_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA256_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA384_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha512) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA512_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha3_224) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA3_224_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha3_256) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA3_256_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha3_384) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA3_384_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha3_512) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::RSA_WITH_SHA3_512_OID).clone(),
            params: Some(*NULL_TLV),
        }),

        (KeyType::Dsa, HashType::Sha224) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::DSA_WITH_SHA224_OID).clone(),
            params: None,
        }),
        (KeyType::Dsa, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::DSA_WITH_SHA256_OID).clone(),
            params: None,
        }),
        (KeyType::Dsa, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::DSA_WITH_SHA384_OID).clone(),
            params: None,
        }),
        (KeyType::Dsa, HashType::Sha512) => Ok(x509::AlgorithmIdentifier {
            oid: (oid::DSA_WITH_SHA512_OID).clone(),
            params: None,
        }),
        (
            KeyType::Dsa,
            HashType::Sha3_224 | HashType::Sha3_256 | HashType::Sha3_384 | HashType::Sha3_512,
        ) => Err(pyo3::PyErr::from_value(
            py.import(pyo3::intern!(py, "cryptography.exceptions"))?
                .call_method1(
                    "UnsupportedAlgorithm",
                    ("SHA3 hashes are not supported with DSA keys",),
                )?,
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
            let padding_mod = py.import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.padding"
            ))?;
            let pkcs1v15 = padding_mod
                .getattr(pyo3::intern!(py, "PKCS1v15"))?
                .call0()?;
            private_key.call_method1(pyo3::intern!(py, "sign"), (data, pkcs1v15, hash_algorithm))?
        }
        KeyType::Dsa => {
            private_key.call_method1(pyo3::intern!(py, "sign"), (data, hash_algorithm))?
        }
    };
    signature.extract()
}

fn py_hash_name_from_hash_type(hash_type: HashType) -> Option<&'static str> {
    match hash_type {
        HashType::None => None,
        HashType::Sha224 => Some("SHA224"),
        HashType::Sha256 => Some("SHA256"),
        HashType::Sha384 => Some("SHA384"),
        HashType::Sha512 => Some("SHA512"),
        HashType::Sha3_224 => Some("SHA3_224"),
        HashType::Sha3_256 => Some("SHA3_256"),
        HashType::Sha3_384 => Some("SHA3_384"),
        HashType::Sha3_512 => Some("SHA3_512"),
    }
}

pub(crate) fn verify_signature_with_oid<'p>(
    py: pyo3::Python<'p>,
    issuer_public_key: &'p pyo3::PyAny,
    signature_oid: &asn1::ObjectIdentifier,
    signature: &[u8],
    data: &[u8],
) -> CryptographyResult<()> {
    let key_type = identify_public_key_type(py, issuer_public_key)?;
    let (sig_key_type, sig_hash_type) = identify_key_hash_type_for_oid(signature_oid)?;
    if key_type != sig_key_type {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Signature algorithm does not match issuer key type",
            ),
        ));
    }
    let sig_hash_name = py_hash_name_from_hash_type(sig_hash_type);
    let hashes = py.import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?;
    let signature_hash = match sig_hash_name {
        Some(data) => hashes.getattr(data)?.call0()?,
        None => py.None().into_ref(py),
    };

    match key_type {
        KeyType::Ed25519 | KeyType::Ed448 => {
            issuer_public_key.call_method1(pyo3::intern!(py, "verify"), (signature, data))?
        }
        KeyType::Ec => {
            let ec_mod = py.import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.ec"
            ))?;
            let ecdsa = ec_mod
                .getattr(pyo3::intern!(py, "ECDSA"))?
                .call1((signature_hash,))?;
            issuer_public_key.call_method1(pyo3::intern!(py, "verify"), (signature, data, ecdsa))?
        }
        KeyType::Rsa => {
            let padding_mod = py.import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.asymmetric.padding"
            ))?;
            let pkcs1v15 = padding_mod
                .getattr(pyo3::intern!(py, "PKCS1v15"))?
                .call0()?;
            issuer_public_key.call_method1(
                pyo3::intern!(py, "verify"),
                (signature, data, pkcs1v15, signature_hash),
            )?
        }
        KeyType::Dsa => issuer_public_key.call_method1(
            pyo3::intern!(py, "verify"),
            (signature, data, signature_hash),
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

fn identify_key_hash_type_for_oid(
    oid: &asn1::ObjectIdentifier,
) -> pyo3::PyResult<(KeyType, HashType)> {
    match *oid {
        oid::RSA_WITH_SHA224_OID => Ok((KeyType::Rsa, HashType::Sha224)),
        oid::RSA_WITH_SHA256_OID => Ok((KeyType::Rsa, HashType::Sha256)),
        oid::RSA_WITH_SHA384_OID => Ok((KeyType::Rsa, HashType::Sha384)),
        oid::RSA_WITH_SHA512_OID => Ok((KeyType::Rsa, HashType::Sha512)),
        oid::RSA_WITH_SHA3_224_OID => Ok((KeyType::Rsa, HashType::Sha3_224)),
        oid::RSA_WITH_SHA3_256_OID => Ok((KeyType::Rsa, HashType::Sha3_256)),
        oid::RSA_WITH_SHA3_384_OID => Ok((KeyType::Rsa, HashType::Sha3_384)),
        oid::RSA_WITH_SHA3_512_OID => Ok((KeyType::Rsa, HashType::Sha3_512)),
        oid::ECDSA_WITH_SHA224_OID => Ok((KeyType::Ec, HashType::Sha224)),
        oid::ECDSA_WITH_SHA256_OID => Ok((KeyType::Ec, HashType::Sha256)),
        oid::ECDSA_WITH_SHA384_OID => Ok((KeyType::Ec, HashType::Sha384)),
        oid::ECDSA_WITH_SHA512_OID => Ok((KeyType::Ec, HashType::Sha512)),
        oid::ECDSA_WITH_SHA3_224_OID => Ok((KeyType::Ec, HashType::Sha3_224)),
        oid::ECDSA_WITH_SHA3_256_OID => Ok((KeyType::Ec, HashType::Sha3_256)),
        oid::ECDSA_WITH_SHA3_384_OID => Ok((KeyType::Ec, HashType::Sha3_384)),
        oid::ECDSA_WITH_SHA3_512_OID => Ok((KeyType::Ec, HashType::Sha3_512)),
        oid::ED25519_OID => Ok((KeyType::Ed25519, HashType::None)),
        oid::ED448_OID => Ok((KeyType::Ed448, HashType::None)),
        oid::DSA_WITH_SHA224_OID => Ok((KeyType::Dsa, HashType::Sha224)),
        oid::DSA_WITH_SHA256_OID => Ok((KeyType::Dsa, HashType::Sha256)),
        oid::DSA_WITH_SHA384_OID => Ok((KeyType::Dsa, HashType::Sha384)),
        oid::DSA_WITH_SHA512_OID => Ok((KeyType::Dsa, HashType::Sha512)),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "Unsupported signature algorithm",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{identify_key_hash_type_for_oid, py_hash_name_from_hash_type, HashType, KeyType};
    use crate::x509::oid;

    #[test]
    fn test_identify_key_hash_type_for_oid() {
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA224_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha224)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA256_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha256)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA384_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha384)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA512_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha512)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA3_224_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha3_224)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA3_256_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha3_256)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA3_384_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha3_384)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::RSA_WITH_SHA3_512_OID).unwrap(),
            (KeyType::Rsa, HashType::Sha3_512)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA224_OID).unwrap(),
            (KeyType::Ec, HashType::Sha224)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA256_OID).unwrap(),
            (KeyType::Ec, HashType::Sha256)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA384_OID).unwrap(),
            (KeyType::Ec, HashType::Sha384)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA512_OID).unwrap(),
            (KeyType::Ec, HashType::Sha512)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA3_224_OID).unwrap(),
            (KeyType::Ec, HashType::Sha3_224)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA3_256_OID).unwrap(),
            (KeyType::Ec, HashType::Sha3_256)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA3_384_OID).unwrap(),
            (KeyType::Ec, HashType::Sha3_384)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ECDSA_WITH_SHA3_512_OID).unwrap(),
            (KeyType::Ec, HashType::Sha3_512)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ED25519_OID).unwrap(),
            (KeyType::Ed25519, HashType::None)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::ED448_OID).unwrap(),
            (KeyType::Ed448, HashType::None)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::DSA_WITH_SHA224_OID).unwrap(),
            (KeyType::Dsa, HashType::Sha224)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::DSA_WITH_SHA256_OID).unwrap(),
            (KeyType::Dsa, HashType::Sha256)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::DSA_WITH_SHA384_OID).unwrap(),
            (KeyType::Dsa, HashType::Sha384)
        );
        assert_eq!(
            identify_key_hash_type_for_oid(&oid::DSA_WITH_SHA512_OID).unwrap(),
            (KeyType::Dsa, HashType::Sha512)
        );
        assert!(identify_key_hash_type_for_oid(&oid::TLS_FEATURE_OID).is_err());
    }

    #[test]
    fn test_py_hash_name_from_hash_type() {
        for (hash, name) in [
            (HashType::Sha224, "SHA224"),
            (HashType::Sha256, "SHA256"),
            (HashType::Sha384, "SHA384"),
            (HashType::Sha512, "SHA512"),
            (HashType::Sha3_224, "SHA3_224"),
            (HashType::Sha3_256, "SHA3_256"),
            (HashType::Sha3_384, "SHA3_384"),
            (HashType::Sha3_512, "SHA3_512"),
        ] {
            let hash_str = py_hash_name_from_hash_type(hash).unwrap();
            assert_eq!(hash_str, name);
        }
    }
}
