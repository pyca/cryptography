// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, PyAsn1Error};
use pyo3::conversion::ToPyObject;

lazy_static::lazy_static! {
    static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();

    static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();
    static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
}

#[derive(asn1::Asn1Read)]
struct BasicConstraints {
    #[default(false)]
    ca: bool,
    path_length: Option<u64>,
}

fn get_bit(input: &[u8], n: usize) -> bool {
    let idx = n / 8;
    let v = 1 << (7 - (n & 0x07));
    if input.len() < (idx + 1) {
        false
    } else {
        input[idx] & v != 0
    }
}

#[pyo3::prelude::pyfunction]
fn parse_x509_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *TLS_FEATURE_OID {
        let tls_feature_type_to_enum = py
            .import("cryptography.x509.extensions")?
            .getattr("_TLS_FEATURE_TYPE_TO_ENUM")?;

        let features = pyo3::types::PyList::empty(py);
        for feature in asn1::parse_single::<asn1::SequenceOf<u64>>(ext_data)? {
            let py_feature = tls_feature_type_to_enum.get_item(feature.to_object(py))?;
            features.append(py_feature)?;
        }
        Ok(x509_module.call1("TLSFeature", (features,))?.to_object(py))
    } else if oid == *SUBJECT_KEY_IDENTIFIER_OID {
        let identifier = asn1::parse_single::<&[u8]>(ext_data)?;
        Ok(x509_module
            .call1("SubjectKeyIdentifier", (identifier,))?
            .to_object(py))
    } else if oid == *EXTENDED_KEY_USAGE_OID {
        let ekus = pyo3::types::PyList::empty(py);
        for oid in asn1::parse_single::<asn1::SequenceOf<asn1::ObjectIdentifier>>(ext_data)? {
            let oid_obj = x509_module.call_method1("ObjectIdentifier", (oid.to_string(),))?;
            ekus.append(oid_obj)?;
        }
        Ok(x509_module
            .call1("ExtendedKeyUsage", (ekus,))?
            .to_object(py))
    } else if oid == *KEY_USAGE_OID {
        let kus = asn1::parse_single::<asn1::BitString>(ext_data)?.as_bytes();
        let digital_signature = get_bit(kus, 0);
        let content_comitment = get_bit(kus, 1);
        let key_encipherment = get_bit(kus, 2);
        let data_encipherment = get_bit(kus, 3);
        let key_agreement = get_bit(kus, 4);
        let key_cert_sign = get_bit(kus, 5);
        let crl_sign = get_bit(kus, 6);
        let encipher_only = get_bit(kus, 7);
        let decipher_only = get_bit(kus, 8);
        Ok(x509_module
            .call1(
                "KeyUsage",
                (
                    digital_signature,
                    content_comitment,
                    key_encipherment,
                    data_encipherment,
                    key_agreement,
                    key_cert_sign,
                    crl_sign,
                    encipher_only,
                    decipher_only,
                ),
            )?
            .to_object(py))
    } else if oid == *PRECERT_POISON_OID {
        asn1::parse_single::<()>(ext_data)?;
        Ok(x509_module.call0("PrecertPoison")?.to_object(py))
    } else if oid == *OCSP_NO_CHECK_OID {
        asn1::parse_single::<()>(ext_data)?;
        Ok(x509_module.call0("OCSPNoCheck")?.to_object(py))
    } else if oid == *INHIBIT_ANY_POLICY_OID {
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("InhibitAnyPolicy", (pynum,))?
            .to_object(py))
    } else if oid == *BASIC_CONSTRAINTS_OID {
        let bc = asn1::parse_single::<BasicConstraints>(ext_data)?;
        Ok(x509_module
            .call1("BasicConstraints", (bc.ca, bc.path_length))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

#[pyo3::prelude::pyfunction]
fn parse_crl_entry_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_REASON_OID {
        let flag_name = match asn1::parse_single::<asn1::Enumerated>(ext_data)?.value() {
            0 => "unspecified",
            1 => "key_compromise",
            2 => "ca_compromise",
            3 => "affiliation_changed",
            4 => "superseded",
            5 => "cessation_of_operation",
            6 => "certificate_hold",
            8 => "remove_from_crl",
            9 => "privilege_withdrawn",
            10 => "aa_compromise",
            value => {
                return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                    format!("Unsupported reason code: {}", value),
                )))
            }
        };
        let flag = x509_module.getattr("ReasonFlags")?.getattr(flag_name)?;
        Ok(x509_module.call1("CRLReason", (flag,))?.to_object(py))
    } else {
        Ok(py.None())
    }
}

#[pyo3::prelude::pyfunction]
fn parse_crl_extension(
    py: pyo3::Python<'_>,
    der_oid: &[u8],
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let oid = asn1::ObjectIdentifier::from_der(der_oid).unwrap();

    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_NUMBER_OID {
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module.call1("CRLNumber", (pynum,))?.to_object(py))
    } else if oid == *DELTA_CRL_INDICATOR_OID {
        let bignum = asn1::parse_single::<asn1::BigUint>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(x509_module
            .call1("DeltaCRLIndicator", (pynum,))?
            .to_object(py))
    } else {
        Ok(py.None())
    }
}

pub(crate) fn create_submodule(py: pyo3::Python) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "x509")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_x509_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_entry_extension))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_crl_extension))?;

    Ok(submod)
}
