// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::CryptographyResult;
use crate::x509;
use crate::x509::oid;
use once_cell::sync::Lazy;
use std::collections::HashMap;

pub(crate) static OIDS_TO_HASH: Lazy<HashMap<&asn1::ObjectIdentifier, &str>> = Lazy::new(|| {
    let mut h = HashMap::new();
    h.insert(&oid::SHA1_OID, "SHA1");
    h.insert(&oid::SHA224_OID, "SHA224");
    h.insert(&oid::SHA256_OID, "SHA256");
    h.insert(&oid::SHA384_OID, "SHA384");
    h.insert(&oid::SHA512_OID, "SHA512");
    h
});
pub(crate) static HASH_NAME_TO_OIDS: Lazy<HashMap<&str, &asn1::ObjectIdentifier>> =
    Lazy::new(|| {
        let mut h = HashMap::new();
        h.insert("sha1", &oid::SHA1_OID);
        h.insert("sha224", &oid::SHA224_OID);
        h.insert("sha256", &oid::SHA256_OID);
        h.insert("sha384", &oid::SHA384_OID);
        h.insert("sha512", &oid::SHA512_OID);
        h
    });

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct CertID<'a> {
    pub(crate) hash_algorithm: x509::AlgorithmIdentifier<'a>,
    pub(crate) issuer_name_hash: &'a [u8],
    pub(crate) issuer_key_hash: &'a [u8],
    pub(crate) serial_number: asn1::BigInt<'a>,
}

impl CertID<'_> {
    pub(crate) fn new<'p>(
        py: pyo3::Python<'p>,
        cert: &'p x509::Certificate,
        issuer: &'p x509::Certificate,
        hash_algorithm: &'p pyo3::PyAny,
    ) -> CryptographyResult<CertID<'p>> {
        let issuer_der = asn1::write_single(&cert.raw.borrow_value_public().tbs_cert.issuer)?;
        let issuer_name_hash = hash_data(py, hash_algorithm, &issuer_der)?;
        let issuer_key_hash = hash_data(
            py,
            hash_algorithm,
            issuer
                .raw
                .borrow_value_public()
                .tbs_cert
                .spki
                .subject_public_key
                .as_bytes(),
        )?;

        Ok(CertID {
            hash_algorithm: x509::AlgorithmIdentifier {
                oid: HASH_NAME_TO_OIDS[hash_algorithm
                    .getattr(pyo3::intern!(py, "name"))?
                    .extract::<&str>()?]
                .clone(),
                params: Some(*x509::sign::NULL_TLV),
            },
            issuer_name_hash,
            issuer_key_hash,
            serial_number: cert.raw.borrow_value_public().tbs_cert.serial,
        })
    }

    pub(crate) fn new_from_hash<'p>(
        py: pyo3::Python<'p>,
        issuer_name_hash: &'p [u8],
        issuer_key_hash: &'p [u8],
        serial_number: asn1::BigInt<'p>,
        hash_algorithm: &'p pyo3::PyAny,
    ) -> CryptographyResult<CertID<'p>> {
        Ok(CertID {
            hash_algorithm: x509::AlgorithmIdentifier {
                oid: HASH_NAME_TO_OIDS[hash_algorithm
                    .getattr(pyo3::intern!(py, "name"))?
                    .extract::<&str>()?]
                .clone(),
                params: Some(*x509::sign::NULL_TLV),
            },
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }
}

pub(crate) fn hash_data<'p>(
    py: pyo3::Python<'p>,
    py_hash_alg: &'p pyo3::PyAny,
    data: &[u8],
) -> pyo3::PyResult<&'p [u8]> {
    let hash = py
        .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
        .getattr(pyo3::intern!(py, "Hash"))?
        .call1((py_hash_alg,))?;
    hash.call_method1(pyo3::intern!(py, "update"), (data,))?;
    hash.call_method0(pyo3::intern!(py, "finalize"))?.extract()
}
