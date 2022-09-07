// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::x509;
use crate::x509::oid;

use once_cell::sync::Lazy;

static NULL_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    // TODO: kind of verbose way to say "\x05\x00".
    asn1::write_single(&()).unwrap()
});
pub(crate) static NULL_TLV: Lazy<asn1::Tlv<'static>> =
    Lazy::new(|| asn1::parse_single(&NULL_DER).unwrap());

enum KeyType {
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
        .import("cryptography.hazmat.primitives.asymmetric.rsa")?
        .getattr(crate::intern!(py, "RSAPrivateKey"))?
        .extract()?;
    let dsa_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.dsa")?
        .getattr(crate::intern!(py, "DSAPrivateKey"))?
        .extract()?;
    let ec_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ec")?
        .getattr(crate::intern!(py, "EllipticCurvePrivateKey"))?
        .extract()?;
    let ed25519_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ed25519")?
        .getattr(crate::intern!(py, "Ed25519PrivateKey"))?
        .extract()?;
    let ed448_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ed448")?
        .getattr(crate::intern!(py, "Ed448PrivateKey"))?
        .extract()?;

    if rsa_private_key.is_instance(private_key)? {
        Ok(KeyType::Rsa)
    } else if dsa_key_type.is_instance(private_key)? {
        Ok(KeyType::Dsa)
    } else if ec_key_type.is_instance(private_key)? {
        Ok(KeyType::Ec)
    } else if ed25519_key_type.is_instance(private_key)? {
        Ok(KeyType::Ed25519)
    } else if ed448_key_type.is_instance(private_key)? {
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
        .import("cryptography.hazmat.primitives.hashes")?
        .getattr(crate::intern!(py, "HashAlgorithm"))?
        .extract()?;
    if !hash_algorithm_type.is_instance(hash_algorithm)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm.",
        ));
    }

    match hash_algorithm
        .getattr(crate::intern!(py, "name"))?
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
        name => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Hash algorithm {:?} not supported for signatures",
            name
        ))),
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
        (KeyType::Ed25519, _) | (KeyType::Ed448, _) => {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Algorithm must be None when signing via ed25519 or ed448",
            ))
        }

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
        (KeyType::Dsa, HashType::Sha3_224)
        | (KeyType::Dsa, HashType::Sha3_256)
        | (KeyType::Dsa, HashType::Sha3_384)
        | (KeyType::Dsa, HashType::Sha3_512) => Err(pyo3::exceptions::PyValueError::new_err(
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
    data: &[u8],
) -> pyo3::PyResult<&'p [u8]> {
    let key_type = identify_key_type(py, private_key)?;

    let signature = match key_type {
        KeyType::Ed25519 | KeyType::Ed448 => private_key.call_method1("sign", (data,))?,
        KeyType::Ec => {
            let ec_mod = py.import("cryptography.hazmat.primitives.asymmetric.ec")?;
            let ecdsa = ec_mod
                .getattr(crate::intern!(py, "ECDSA"))?
                .call1((hash_algorithm,))?;
            private_key.call_method1("sign", (data, ecdsa))?
        }
        KeyType::Rsa => {
            let padding_mod = py.import("cryptography.hazmat.primitives.asymmetric.padding")?;
            let pkcs1v15 = padding_mod
                .getattr(crate::intern!(py, "PKCS1v15"))?
                .call0()?;
            private_key.call_method1("sign", (data, pkcs1v15, hash_algorithm))?
        }
        KeyType::Dsa => private_key.call_method1("sign", (data, hash_algorithm))?,
    };
    signature.extract()
}
