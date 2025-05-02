// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::Time;
use cryptography_x509::name::Name;
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use pyo3::prelude::PyAnyMethods;

#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use crate::types;
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
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

#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
#[pyo3::pyfunction]
#[pyo3(signature = (encoding, sig, msg, certs, options))]
fn pkcs7_verify(
    py: pyo3::Python<'_>,
    encoding: pyo3::Bound<'_, pyo3::PyAny>,
    sig: &[u8],
    msg: Option<CffiBuf<'_>>,
    certs: Vec<pyo3::Py<PyCertificate>>,
    options: pyo3::Bound<'_, pyo3::types::PyList>,
) -> CryptographyResult<()> {
    let p7 = if encoding.is(&types::ENCODING_DER.get(py)?) {
        openssl::pkcs7::Pkcs7::from_der(sig)?
    } else if encoding.is(&types::ENCODING_PEM.get(py)?) {
        openssl::pkcs7::Pkcs7::from_pem(sig)?
    } else {
        openssl::pkcs7::Pkcs7::from_smime(sig)?.0
    };

    let mut flags = openssl::pkcs7::Pkcs7Flags::empty();
    if options.contains(types::PKCS7_TEXT.get(py)?)? {
        flags |= openssl::pkcs7::Pkcs7Flags::TEXT;
    }

    let store = {
        let mut b = openssl::x509::store::X509StoreBuilder::new()?;
        for cert in &certs {
            let der = asn1::write_single(cert.get().raw.borrow_dependent())?;
            b.add_cert(openssl::x509::X509::from_der(&der)?)?;
        }
        b.build()
    };
    let certs = openssl::stack::Stack::new()?;

    p7.verify(
        &certs,
        &store,
        msg.as_ref().map(|m| m.as_bytes()),
        None,
        flags,
    )?;

    Ok(())
}

#[pyo3::pymodule]
pub(crate) mod test_support {
    #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
    #[pymodule_export]
    use super::pkcs7_verify;
    #[pymodule_export]
    use super::test_parse_certificate;
}
