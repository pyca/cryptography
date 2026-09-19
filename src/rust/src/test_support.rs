// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::Time;
use cryptography_x509::name::Name;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use pyo3::prelude::PyAnyMethods;

#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::types;
#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
use crate::x509::certificate::Certificate as PyCertificate;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.test_support")]
struct TestCertificate {
    #[pyo3(get)]
    not_before_tag: u8,
    #[pyo3(get)]
    not_after_tag: u8,
    #[pyo3(get)]
    issuer_value_tags: Vec<u8>,
    #[pyo3(get)]
    subject_value_tags: Vec<u8>,
}

fn parse_name_value_tags(rdns: &Name<'_>) -> Vec<u8> {
    let mut tags = vec![];
    for rdn in rdns.unwrap_read().clone() {
        let mut attributes = rdn.collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);

        tags.push(attributes.pop().unwrap().value.tag().as_u8().unwrap());
    }
    tags
}

fn time_tag(t: &Time) -> u8 {
    match t {
        Time::UtcTime(_) => asn1::UtcTime::TAG.as_u8().unwrap(),
        Time::GeneralizedTime(_) => asn1::GeneralizedTime::TAG.as_u8().unwrap(),
    }
}

#[pyo3::pyfunction]
fn test_parse_certificate(data: &[u8]) -> CryptographyResult<TestCertificate> {
    let cert = asn1::parse_single::<Certificate<'_>>(data)?;

    Ok(TestCertificate {
        not_before_tag: time_tag(&cert.tbs_cert.validity.not_before),
        not_after_tag: time_tag(&cert.tbs_cert.validity.not_after),
        issuer_value_tags: parse_name_value_tags(&cert.tbs_cert.issuer),
        subject_value_tags: parse_name_value_tags(&cert.tbs_cert.subject),
    })
}

#[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
#[pyo3::pyfunction]
#[pyo3(signature = (encoding, sig, msg, certs, options))]
fn pkcs7_verify(
    py: pyo3::Python<'_>,
    encoding: crate::serialization::Encoding,
    sig: &[u8],
    msg: Option<CffiBuf<'_>>,
    certs: Vec<pyo3::Py<PyCertificate>>,
    options: pyo3::Bound<'_, pyo3::types::PyList>,
) -> CryptographyResult<()> {
    let encoding = match encoding {
        crate::serialization::Encoding::DER => openssl_bridge::pkcs7::Encoding::Der,
        crate::serialization::Encoding::PEM => openssl_bridge::pkcs7::Encoding::Pem,
        _ => openssl_bridge::pkcs7::Encoding::Smime,
    };
    let text = options.contains(types::PKCS7_TEXT.get(py)?)?;
    let certificates = certs
        .iter()
        .map(|cert| asn1::write_single(cert.get().raw.borrow_dependent()))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
    openssl_bridge::pkcs7::verify(
        encoding,
        sig,
        msg.as_ref().map(|m| m.as_bytes()),
        &anchors,
        text,
    )?;

    Ok(())
}

/// Seed fixed owned diagnostics for error-boundary regression tests. No raw
/// pointer, callback, arbitrary error number, or allocation crosses Python.
#[pyo3::pyfunction]
fn queue_test_errors(count: u8) -> pyo3::PyResult<(i32, i32)> {
    if !(1..=10).contains(&count) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "test diagnostic count must be 1..=10",
        ));
    }
    // SAFETY: Bounded fixture modifies only the current thread's error queue
    // with fixed native codes. The shim and macro decoders take no pointers.
    unsafe {
        let code = openssl_bridge_sys::OB_test_queue_errors(count.into());
        Ok((
            openssl_bridge_sys::OB_err_lib(code),
            openssl_bridge_sys::OB_err_reason(code),
        ))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod test_support {
    #[cfg(not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)))]
    #[pymodule_export]
    use super::pkcs7_verify;
    #[pymodule_export]
    use super::queue_test_errors;
    #[pymodule_export]
    use super::test_parse_certificate;
}
