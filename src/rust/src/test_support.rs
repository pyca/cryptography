// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::Time;
use cryptography_x509::name::Name;
#[cfg(all(
    feature = "openssl",
    not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
))]
use pyo3::prelude::PyAnyMethods;

#[cfg(all(
    feature = "openssl",
    not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
))]
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
#[cfg(all(
    feature = "openssl",
    not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
))]
use crate::types;
#[cfg(all(
    feature = "openssl",
    not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
))]
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

#[cfg(all(
    feature = "openssl",
    not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
))]
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
    let p7 = match encoding {
        crate::serialization::Encoding::DER => openssl::pkcs7::Pkcs7::from_der(sig)?,
        crate::serialization::Encoding::PEM => openssl::pkcs7::Pkcs7::from_pem(sig)?,
        _ => openssl::pkcs7::Pkcs7::from_smime(sig)?.0,
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

/// The DER of an S/MIME message's PKCS #7 structure: the signature part of a
/// `multipart/signed` message, or the body of an `application/pkcs7-mime`
/// one (as OpenSSL's `SMIME_read_PKCS7` reads them).
#[cfg(feature = "verified-garbage")]
fn smime_pkcs7_der(py: pyo3::Python<'_>, sig: &[u8]) -> CryptographyResult<Vec<u8>> {
    use pyo3::types::{PyAnyMethods, PyDictMethods, PyListMethods};

    let message = py.import(pyo3::intern!(py, "email"))?.call_method1(
        pyo3::intern!(py, "message_from_bytes"),
        (pyo3::types::PyBytes::new(py, sig),),
    )?;
    let part = if message
        .call_method0(pyo3::intern!(py, "is_multipart"))?
        .extract::<bool>()?
    {
        let parts = message
            .call_method0(pyo3::intern!(py, "get_payload"))?
            .cast_into::<pyo3::types::PyList>()?;
        if parts.len() != 2 {
            return Err(crate::error::CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Invalid S/MIME message"),
            ));
        }
        parts.get_item(1)?
    } else {
        message
    };
    let kwargs = pyo3::types::PyDict::new(py);
    kwargs.set_item(pyo3::intern!(py, "decode"), true)?;
    let der = part.call_method(pyo3::intern!(py, "get_payload"), (), Some(&kwargs))?;
    Ok(der.extract::<Vec<u8>>()?)
}

/// The hash of a `SignerInfo`'s digest algorithm, with the RSA PKCS #1 v1.5
/// signature algorithm over it (for signatures whose algorithm is
/// `rsaEncryption`).
#[cfg(feature = "verified-garbage")]
fn pkcs7_digest(
    alg: &cryptography_x509::common::AlgorithmIdentifier<'_>,
) -> Option<(
    cryptography_crypto::hash::MessageDigest,
    cryptography_x509::common::AlgorithmParameters<'static>,
)> {
    use cryptography_crypto::hash::MessageDigest;
    use cryptography_x509::common::AlgorithmParameters;

    Some(match alg.params {
        AlgorithmParameters::Sha1(_) => (
            MessageDigest::Sha1,
            AlgorithmParameters::RsaWithSha1(Some(())),
        ),
        AlgorithmParameters::Sha224(_) => (
            MessageDigest::Sha224,
            AlgorithmParameters::RsaWithSha224(Some(())),
        ),
        AlgorithmParameters::Sha256(_) => (
            MessageDigest::Sha256,
            AlgorithmParameters::RsaWithSha256(Some(())),
        ),
        AlgorithmParameters::Sha384(_) => (
            MessageDigest::Sha384,
            AlgorithmParameters::RsaWithSha384(Some(())),
        ),
        AlgorithmParameters::Sha512(_) => (
            MessageDigest::Sha512,
            AlgorithmParameters::RsaWithSha512(Some(())),
        ),
        _ => return None,
    })
}

/// Verifies a PKCS #7 signature as OpenSSL's `PKCS7_verify` does with an
/// empty stack of untrusted certificates and a store of `certs`: each
/// signer's certificate is found among the structure's certificates by its
/// issuer and serial number, must be one of `certs` or be issued by one of
/// them, and must have signed the content (through the message digest
/// attribute, when there are authenticated attributes). Unlike OpenSSL, it
/// does not check the certificates' validity periods or purposes.
#[cfg(feature = "verified-garbage")]
#[pyo3::pyfunction]
#[pyo3(signature = (encoding, sig, msg, certs, options))]
fn pkcs7_verify(
    py: pyo3::Python<'_>,
    encoding: crate::serialization::Encoding,
    sig: &[u8],
    msg: Option<crate::buf::CffiBuf<'_>>,
    certs: Vec<pyo3::Py<crate::x509::certificate::Certificate>>,
    options: pyo3::Bound<'_, pyo3::types::PyList>,
) -> CryptographyResult<()> {
    use cryptography_x509::pkcs7;
    use pyo3::types::{PyAnyMethods, PyListMethods};

    let fail = |msg: &'static str| {
        crate::error::CryptographyError::from(pyo3::exceptions::PyValueError::new_err(msg))
    };

    let der = match encoding {
        crate::serialization::Encoding::DER => sig.to_vec(),
        crate::serialization::Encoding::PEM => {
            let p = pem::parse(sig)?;
            if p.tag() != "PKCS7" {
                return Err(fail("Not a PKCS7 PEM"));
            }
            p.into_contents()
        }
        _ => smime_pkcs7_der(py, sig)?,
    };
    let content_info = asn1::parse_single::<pkcs7::ContentInfo<'_>>(&der)?;
    let pkcs7::Content::SignedData(signed_data) = content_info.content else {
        return Err(fail("Not a PKCS7 signed data structure"));
    };
    let signed_data = signed_data.into_inner();
    let content = match (&msg, &signed_data.content_info.content) {
        (Some(m), _) => m.as_bytes(),
        (None, pkcs7::Content::Data(Some(data))) => data.as_inner(),
        _ => return Err(fail("No content to verify")),
    };
    let embedded = signed_data
        .certificates
        .as_ref()
        .map(|c| c.unwrap_read().clone().collect::<Vec<_>>())
        .unwrap_or_default();

    for signer_info in signed_data.signer_infos.unwrap_read().clone() {
        let signer = embedded
            .iter()
            .find(|c| {
                c.tbs_cert.issuer == signer_info.issuer_and_serial_number.issuer
                    && c.tbs_cert.serial == signer_info.issuer_and_serial_number.serial_number
            })
            .ok_or_else(|| fail("Signer certificate not found"))?;
        let signer_der = asn1::write_single(signer)?;
        let signer_cert = pyo3::Bound::new(
            py,
            crate::x509::certificate::load_der_x509_certificate(
                py,
                pyo3::types::PyBytes::new(py, &signer_der).unbind(),
                None,
            )?,
        )?;

        let trusted = certs.iter().any(|c| {
            asn1::write_single(c.get().raw.borrow_dependent())
                .ok()
                .as_deref()
                == Some(&signer_der[..])
                || signer_cert
                    .call_method1(
                        pyo3::intern!(py, "verify_directly_issued_by"),
                        (c.bind(py),),
                    )
                    .is_ok()
        });
        if !trusted {
            return Err(fail("Signer certificate is not trusted"));
        }

        let (md, rsa_params) = pkcs7_digest(&signer_info.digest_algorithm)
            .ok_or_else(|| fail("Unsupported digest algorithm"))?;
        let signed_bytes = match &signer_info.authenticated_attributes {
            Some(attrs) => {
                let digest = cryptography_crypto::hash::hash(md, content)
                    .map_err(|_| fail("Unsupported digest algorithm"))?;
                let message_digest = attrs
                    .unwrap_read()
                    .clone()
                    .find(|a| a.type_id == asn1::oid!(1, 2, 840, 113549, 1, 9, 4))
                    .and_then(|a| a.values.unwrap_read().clone().next())
                    .and_then(|v| v.parse::<&[u8]>().ok())
                    .ok_or_else(|| fail("No message digest attribute"))?;
                if message_digest != &digest[..] {
                    return Err(fail("Message digest mismatch"));
                }
                asn1::write_single(attrs.unwrap_read())?
            }
            None => content.to_vec(),
        };

        let signature_algorithm = match signer_info.digest_encryption_algorithm.params {
            cryptography_x509::common::AlgorithmParameters::Rsa(_) => {
                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: rsa_params,
                }
            }
            _ => signer_info.digest_encryption_algorithm.clone(),
        };
        crate::x509::sign::verify_signature_with_signature_algorithm(
            py,
            signer_cert.call_method0(pyo3::intern!(py, "public_key"))?,
            &signature_algorithm,
            signer_info.encrypted_digest,
            &signed_bytes,
        )
        .map_err(|_| fail("Signature verification failed"))?;
    }

    // As OpenSSL's SMIME_text, the Text option requires text/plain content.
    if options.contains(crate::types::PKCS7_TEXT.get(py)?)? {
        let header = content
            .split(|&b| b == b'\n')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !header.starts_with(b"content-type: text/plain") {
            return Err(fail("Content is not text/plain"));
        }
    }

    Ok(())
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod test_support {
    #[cfg(all(
        feature = "openssl",
        not(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))
    ))]
    #[pymodule_export]
    use super::pkcs7_verify;
    #[cfg(feature = "verified-garbage")]
    #[pymodule_export]
    use super::pkcs7_verify;
    #[pymodule_export]
    use super::test_parse_certificate;
}
