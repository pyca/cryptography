// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::HashSet;
use std::sync::Arc;

use cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use cryptography_x509_verification::policy::{
    ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, RSASSA_PKCS1V15_SHA256, RSASSA_PKCS1V15_SHA384,
    RSASSA_PKCS1V15_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512, SPKI_RSA,
    SPKI_SECP256R1, SPKI_SECP384R1, SPKI_SECP521R1,
};

use crate::error::{CryptographyError, CryptographyResult};
use pyo3::types::PyAnyMethods;

/// SubjectPublicKeyInfo algorithms exposed to Python policy configuration.
#[pyo3::pyclass(
    frozen,
    eq,
    eq_int,
    from_py_object,
    module = "cryptography.x509.verification",
    name = "SubjectPublicKeyInfoAlgorithm"
)]
#[derive(PartialEq, Clone, Copy, Debug)]
pub(crate) enum PySubjectPublicKeyInfoAlgorithm {
    #[pyo3(name = "RSA")]
    Rsa,
    #[pyo3(name = "SECP256R1")]
    Secp256R1,
    #[pyo3(name = "SECP384R1")]
    Secp384R1,
    #[pyo3(name = "SECP521R1")]
    Secp521R1,
    Ed25519,
    Ed448,
}

/// Signature algorithms exposed to Python policy configuration.
#[pyo3::pyclass(
    frozen,
    eq,
    eq_int,
    from_py_object,
    module = "cryptography.x509.verification",
    name = "SignatureAlgorithm"
)]
#[derive(PartialEq, Clone, Copy, Debug)]
pub(crate) enum PySignatureAlgorithm {
    #[pyo3(name = "RSA_PKCS1_SHA256")]
    RsaPkcs1Sha256,
    #[pyo3(name = "RSA_PKCS1_SHA384")]
    RsaPkcs1Sha384,
    #[pyo3(name = "RSA_PKCS1_SHA512")]
    RsaPkcs1Sha512,
    #[pyo3(name = "RSA_PKCS1_SHA1")]
    RsaPkcs1Sha1,
    #[pyo3(name = "RSA_PSS_SHA256")]
    RsaPssSha256,
    #[pyo3(name = "RSA_PSS_SHA384")]
    RsaPssSha384,
    #[pyo3(name = "RSA_PSS_SHA512")]
    RsaPssSha512,
    #[pyo3(name = "ECDSA_SHA256")]
    EcdsaSha256,
    #[pyo3(name = "ECDSA_SHA384")]
    EcdsaSha384,
    #[pyo3(name = "ECDSA_SHA512")]
    EcdsaSha512,
    Ed25519,
    Ed448,
}

const SPKI_ED25519: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed25519,
};

const SPKI_ED448: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed448,
};

const SIG_ED25519: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed25519,
};

const SIG_ED448: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::Ed448,
};

const SIG_RSA_PKCS1_SHA1: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: asn1::DefinedByMarker::marker(),
    params: AlgorithmParameters::RsaWithSha1(Some(())),
};

pub(crate) fn spki_from_py(
    algorithm: PySubjectPublicKeyInfoAlgorithm,
) -> AlgorithmIdentifier<'static> {
    match algorithm {
        PySubjectPublicKeyInfoAlgorithm::Rsa => SPKI_RSA.clone(),
        PySubjectPublicKeyInfoAlgorithm::Secp256R1 => SPKI_SECP256R1.clone(),
        PySubjectPublicKeyInfoAlgorithm::Secp384R1 => SPKI_SECP384R1.clone(),
        PySubjectPublicKeyInfoAlgorithm::Secp521R1 => SPKI_SECP521R1.clone(),
        PySubjectPublicKeyInfoAlgorithm::Ed25519 => SPKI_ED25519.clone(),
        PySubjectPublicKeyInfoAlgorithm::Ed448 => SPKI_ED448.clone(),
    }
}

pub(crate) fn signature_from_py(algorithm: PySignatureAlgorithm) -> AlgorithmIdentifier<'static> {
    match algorithm {
        PySignatureAlgorithm::RsaPkcs1Sha256 => RSASSA_PKCS1V15_SHA256.clone(),
        PySignatureAlgorithm::RsaPkcs1Sha384 => RSASSA_PKCS1V15_SHA384.clone(),
        PySignatureAlgorithm::RsaPkcs1Sha512 => RSASSA_PKCS1V15_SHA512.clone(),
        PySignatureAlgorithm::RsaPkcs1Sha1 => SIG_RSA_PKCS1_SHA1.clone(),
        PySignatureAlgorithm::RsaPssSha256 => RSASSA_PSS_SHA256.clone(),
        PySignatureAlgorithm::RsaPssSha384 => RSASSA_PSS_SHA384.clone(),
        PySignatureAlgorithm::RsaPssSha512 => RSASSA_PSS_SHA512.clone(),
        PySignatureAlgorithm::EcdsaSha256 => ECDSA_SHA256.clone(),
        PySignatureAlgorithm::EcdsaSha384 => ECDSA_SHA384.clone(),
        PySignatureAlgorithm::EcdsaSha512 => ECDSA_SHA512.clone(),
        PySignatureAlgorithm::Ed25519 => SIG_ED25519.clone(),
        PySignatureAlgorithm::Ed448 => SIG_ED448.clone(),
    }
}

pub(crate) fn parse_spki_frozenset(
    py: pyo3::Python<'_>,
    algorithms: &pyo3::Bound<'_, pyo3::types::PyFrozenSet>,
) -> CryptographyResult<Arc<HashSet<AlgorithmIdentifier<'static>>>> {
    if algorithms.len()? == 0 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "permitted public key algorithms must not be empty.",
            ),
        ));
    }

    let mut set = HashSet::new();
    for item in algorithms.try_iter()? {
        let alg: PySubjectPublicKeyInfoAlgorithm = item?.extract()?;
        set.insert(spki_from_py(alg));
    }
    Ok(Arc::new(set))
}

pub(crate) fn parse_signature_frozenset(
    py: pyo3::Python<'_>,
    algorithms: &pyo3::Bound<'_, pyo3::types::PyFrozenSet>,
) -> CryptographyResult<Arc<HashSet<AlgorithmIdentifier<'static>>>> {
    if algorithms.len()? == 0 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "permitted signature algorithms must not be empty.",
            ),
        ));
    }

    let mut set = HashSet::new();
    for item in algorithms.try_iter()? {
        let alg: PySignatureAlgorithm = item?.extract()?;
        set.insert(signature_from_py(alg));
    }
    Ok(Arc::new(set))
}
