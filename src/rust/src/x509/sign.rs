// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::x509;

lazy_static::lazy_static! {
    static ref ECDSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.2").unwrap();

    static ref ED25519_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap();
    static ref ED448_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.113").unwrap();
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum KeyType {
    RSA,
    DSA,
    EC,
    Ed25519,
    Ed448,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum HashType {
    None,
    MD5,
    SHA256,
}

fn identify_key_type(py: pyo3::Python<'_>, private_key: &pyo3::PyAny) -> pyo3::PyResult<KeyType> {
    let rsa_private_key: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.rsa")?
        .getattr("RSAPrivateKey")?
        .extract()?;
    let dsa_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.dsa")?
        .getattr("DSAPrivateKey")?
        .extract()?;
    let ec_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ec")?
        .getattr("EllipticCurvePrivateKey")?
        .extract()?;
    let ed25519_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ed25519")?
        .getattr("Ed25519PrivateKey")?
        .extract()?;
    let ed448_key_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.asymmetric.ed448")?
        .getattr("Ed448PrivateKey")?
        .extract()?;

    if rsa_private_key.is_instance(private_key)? {
        Ok(KeyType::RSA)
    } else if dsa_key_type.is_instance(private_key)? {
        Ok(KeyType::DSA)
    } else if ec_key_type.is_instance(private_key)? {
        Ok(KeyType::EC)
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
    let hash_algorithm_type: &pyo3::types::PyType = py
        .import("cryptography.hazmat.primitives.hashes")?
        .getattr("HashAlgorithm")?
        .extract()?;
    if !hash_algorithm_type.is_instance(hash_algorithm)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm.",
        ));
    }

    match hash_algorithm.getattr("name")?.extract()? {
        "sha256" => Ok(HashType::SHA256),
        _ => todo!("{:?}", hash_algorithm),
    }
}

pub(crate) fn compute_signature_algorithm<'p>(
    py: pyo3::Python<'p>,
    private_key: &'p pyo3::PyAny,
    hash_algorithm: &'p pyo3::PyAny,
) -> pyo3::PyResult<x509::AlgorithmIdentifier<'static>> {
    let key_type = identify_key_type(py, private_key)?;
    let hash_type = if key_type == KeyType::Ed25519 || key_type == KeyType::Ed448 {
        if !hash_algorithm.is_none() {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "algorithm must be None when signing via ed25519 or ed448",
            ));
        }
        HashType::None
    } else {
        identify_hash_type(py, hash_algorithm)?
    };

    if hash_type == HashType::MD5 && key_type != KeyType::RSA {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "MD5 hash algorithm is only supported with RSA keys",
        ));
    }

    match (key_type, hash_type) {
        (KeyType::EC, HashType::SHA256) => Ok(x509::AlgorithmIdentifier {
            oid: (*ECDSA_WITH_SHA256_OID).clone(),
            params: None,
        }),
        _ => todo!("{:?}, {:?}", key_type, hash_type),
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
        KeyType::EC => {
            let ec_mod = py.import("cryptography.hazmat.primitives.asymmetric.ec")?;
            private_key.call_method1(
                "sign",
                (data, ec_mod.getattr("ECDSA")?.call1((hash_algorithm,))?),
            )?
        }
        _ => todo!("{:?}", key_type),
    };
    signature.extract()
}
