// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::PyAsn1Result;
use crate::x509;
use crate::x509::oid;
use std::collections::HashMap;

lazy_static::lazy_static! {
    pub(crate) static ref OIDS_TO_HASH: HashMap<&'static asn1::ObjectIdentifier<'static>, &'static str> = {
        let mut h = HashMap::new();
        h.insert(&*oid::SHA1_OID, "SHA1");
        h.insert(&*oid::SHA224_OID, "SHA224");
        h.insert(&*oid::SHA256_OID, "SHA256");
        h.insert(&*oid::SHA384_OID, "SHA384");
        h.insert(&*oid::SHA512_OID, "SHA512");
        h
    };
    pub(crate) static ref HASH_NAME_TO_OIDS: HashMap<&'static str, &'static asn1::ObjectIdentifier<'static>> = {
        let mut h = HashMap::new();
        h.insert("sha1", &*oid::SHA1_OID);
        h.insert("sha224", &*oid::SHA224_OID);
        h.insert("sha256", &*oid::SHA256_OID);
        h.insert("sha384", &*oid::SHA384_OID);
        h.insert("sha512", &*oid::SHA512_OID);
        h
    };
}

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
    ) -> PyAsn1Result<CertID<'p>> {
        let issuer_name_hash = hash_data(
            py,
            hash_algorithm,
            &asn1::write_single(&cert.raw.borrow_value_public().tbs_cert.issuer),
        )?;
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
                oid: HASH_NAME_TO_OIDS[hash_algorithm.getattr("name")?.extract::<&str>()?].clone(),
                params: Some(*x509::sign::NULL_TLV),
            },
            issuer_name_hash,
            issuer_key_hash,
            serial_number: cert.raw.borrow_value_public().tbs_cert.serial,
        })
    }
}

pub(crate) fn hash_data<'p>(
    py: pyo3::Python<'p>,
    py_hash_alg: &'p pyo3::PyAny,
    data: &[u8],
) -> pyo3::PyResult<&'p [u8]> {
    let hash = py
        .import("cryptography.hazmat.primitives.hashes")?
        .getattr("Hash")?
        .call1((py_hash_alg,))?;
    hash.call_method1("update", (data,))?;
    hash.call_method0("finalize")?.extract()
}
