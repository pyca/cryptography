// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::x509;

lazy_static::lazy_static! {
    static ref ECDSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.1").unwrap();
    static ref ECDSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.2").unwrap();
    static ref ECDSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.3").unwrap();

    static ref RSA_WITH_MD5_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.4").unwrap();
    static ref RSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.5").unwrap();
    static ref RSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.11").unwrap();
    static ref RSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.12").unwrap();

    static ref DSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10040.4.3").unwrap();
    static ref DSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.2").unwrap();
    static ref DSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.3").unwrap();

    static ref ED25519_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap();
    static ref ED448_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.113").unwrap();

    // TODO: kind of verbose way to say "\x05\x00".
    static ref NULL_DER: Vec<u8> = asn1::write_single(&());
    pub(crate) static ref NULL_TLV: asn1::Tlv<'static> = asn1::parse_single(&NULL_DER).unwrap();
}

enum KeyType {
    Rsa,
    Dsa,
    Ec,
    Ed25519,
    Ed448,
}

enum HashType {
    None,
    Md5,
    Sha1,
    Sha256,
    Sha384,
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
        .getattr("HashAlgorithm")?
        .extract()?;
    if !hash_algorithm_type.is_instance(hash_algorithm)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm.",
        ));
    }

    match hash_algorithm.getattr("name")?.extract()? {
        "md5" => Ok(HashType::Md5),
        "sha1" => Ok(HashType::Sha1),
        "sha256" => Ok(HashType::Sha256),
        "sha384" => Ok(HashType::Sha384),
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
            oid: (*ED25519_OID).clone(),
            params: None,
        }),
        (KeyType::Ed448, HashType::None) => Ok(x509::AlgorithmIdentifier {
            oid: (*ED448_OID).clone(),
            params: None,
        }),
        (KeyType::Ed25519, _) | (KeyType::Ed448, _) => {
            Err(pyo3::exceptions::PyValueError::new_err(
                "Algorithm must be None when signing via ed25519 or ed448",
            ))
        }

        (KeyType::Ec, HashType::Sha1) => Ok(x509::AlgorithmIdentifier {
            oid: (*ECDSA_WITH_SHA1_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (*ECDSA_WITH_SHA256_OID).clone(),
            params: None,
        }),
        (KeyType::Ec, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (*ECDSA_WITH_SHA384_OID).clone(),
            params: None,
        }),

        (KeyType::Rsa, HashType::Md5) => Ok(x509::AlgorithmIdentifier {
            oid: (*RSA_WITH_MD5_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha1) => Ok(x509::AlgorithmIdentifier {
            oid: (*RSA_WITH_SHA1_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (*RSA_WITH_SHA256_OID).clone(),
            params: Some(*NULL_TLV),
        }),
        (KeyType::Rsa, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (*RSA_WITH_SHA384_OID).clone(),
            params: Some(*NULL_TLV),
        }),

        (KeyType::Dsa, HashType::Sha1) => Ok(x509::AlgorithmIdentifier {
            oid: (*DSA_WITH_SHA1_OID).clone(),
            params: None,
        }),
        (KeyType::Dsa, HashType::Sha256) => Ok(x509::AlgorithmIdentifier {
            oid: (*DSA_WITH_SHA256_OID).clone(),
            params: None,
        }),
        (KeyType::Dsa, HashType::Sha384) => Ok(x509::AlgorithmIdentifier {
            oid: (*DSA_WITH_SHA384_OID).clone(),
            params: None,
        }),

        (_, HashType::None) => Err(pyo3::exceptions::PyTypeError::new_err(
            "Algorithm must be a registered hash algorithm, not None.",
        )),
        (_, HashType::Md5) => Err(pyo3::exceptions::PyValueError::new_err(
            "MD5 hash algorithm is only supported with RSA keys",
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
            let ecdsa = ec_mod.getattr("ECDSA")?.call1((hash_algorithm,))?;
            private_key.call_method1("sign", (data, ecdsa))?
        }
        KeyType::Rsa => {
            let padding_mod = py.import("cryptography.hazmat.primitives.asymmetric.padding")?;
            let pkcs1v15 = padding_mod.getattr("PKCS1v15")?.call0()?;
            private_key.call_method1("sign", (data, pkcs1v15, hash_algorithm))?
        }
        KeyType::Dsa => private_key.call_method1("sign", (data, hash_algorithm))?,
    };
    signature.extract()
}
