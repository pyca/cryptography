// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::PyAsn1Result;
use crate::x509;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    static ref SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    static ref SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    static ref SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    static ref SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();

    pub(crate) static ref OIDS_TO_HASH: HashMap<&'static asn1::ObjectIdentifier<'static>, &'static str> = {
        let mut h = HashMap::new();
        h.insert(&*SHA1_OID, "SHA1");
        h.insert(&*SHA224_OID, "SHA224");
        h.insert(&*SHA256_OID, "SHA256");
        h.insert(&*SHA384_OID, "SHA384");
        h.insert(&*SHA512_OID, "SHA512");
        h
    };
    pub(crate) static ref HASH_NAME_TO_OIDS: HashMap<&'static str, &'static asn1::ObjectIdentifier<'static>> = {
        let mut h = HashMap::new();
        h.insert("sha1", &*SHA1_OID);
        h.insert("sha224", &*SHA224_OID);
        h.insert("sha256", &*SHA256_OID);
        h.insert("sha384", &*SHA384_OID);
        h.insert("sha512", &*SHA512_OID);
        h
    };

    pub(crate) static ref NONCE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.2").unwrap();

    // TODO: kind of verbose way to say "\x05\x00".
    static ref NULL_DER: Vec<u8> = asn1::write_single(&());
    pub(crate) static ref NULL_TLV: asn1::Tlv<'static> = asn1::parse_single(&NULL_DER).unwrap();
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct CertID<'a> {
    pub(crate) hash_algorithm: x509::AlgorithmIdentifier<'a>,
    pub(crate) issuer_name_hash: &'a [u8],
    pub(crate) issuer_key_hash: &'a [u8],
    pub(crate) serial_number: asn1::BigUint<'a>,
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
                params: Some(*NULL_TLV),
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
