// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{
    big_byte_slice_to_py_int, encode_der_data, oid_to_py_oid, py_uint_to_big_endian_bytes,
};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509;
use crate::x509::{crl, extensions, oid, sct, sign, Asn1ReadableOrWritable};
use pyo3::{IntoPy, ToPyObject};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub(crate) struct RawCertificate<'a> {
    pub(crate) tbs_cert: TbsCertificate<'a>,
    signature_alg: x509::AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub(crate) struct TbsCertificate<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    pub(crate) serial: asn1::BigInt<'a>,
    signature_alg: x509::AlgorithmIdentifier<'a>,

    pub(crate) issuer: x509::Name<'a>,
    validity: Validity,
    pub(crate) subject: x509::Name<'a>,

    pub(crate) spki: SubjectPublicKeyInfo<'a>,
    #[implicit(1)]
    issuer_unique_id: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    subject_unique_id: Option<asn1::BitString<'a>>,
    #[explicit(3)]
    extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub(crate) struct Validity {
    not_before: x509::Time,
    not_after: x509::Time,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq, Clone)]
pub(crate) struct SubjectPublicKeyInfo<'a> {
    _algorithm: x509::AlgorithmIdentifier<'a>,
    pub(crate) subject_public_key: asn1::BitString<'a>,
}

#[ouroboros::self_referencing]
pub(crate) struct OwnedRawCertificate {
    data: pyo3::Py<pyo3::types::PyBytes>,

    #[borrows(data)]
    #[covariant]
    value: RawCertificate<'this>,
}

impl OwnedRawCertificate {
    // Re-expose ::new with `pub(crate)` visibility.
    pub(crate) fn new_public(
        data: pyo3::Py<pyo3::types::PyBytes>,
        value_ref_builder: impl for<'this> FnOnce(
            &'this pyo3::Py<pyo3::types::PyBytes>,
        ) -> RawCertificate<'this>,
    ) -> OwnedRawCertificate {
        OwnedRawCertificate::new(data, value_ref_builder)
    }

    pub(crate) fn borrow_value_public(&self) -> &RawCertificate<'_> {
        self.borrow_value()
    }
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
pub(crate) struct Certificate {
    pub(crate) raw: OwnedRawCertificate,
    pub(crate) cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pymethods]
impl Certificate {
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_value().hash(&mut hasher);
        hasher.finish()
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, Certificate>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.raw.borrow_value() == other.raw.borrow_value()),
            pyo3::basic::CompareOp::Ne => Ok(self.raw.borrow_value() != other.raw.borrow_value()),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "Certificates cannot be ordered",
            )),
        }
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let subject = self.subject(py)?;
        let subject_repr = subject.repr()?.extract::<&str>()?;
        Ok(format!("<Certificate(subject={}, ...)>", subject_repr))
    }

    fn __deepcopy__(slf: pyo3::PyRef<'_, Self>, _memo: pyo3::PyObject) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn public_key<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized = pyo3::types::PyBytes::new(
            py,
            &asn1::write_single(&self.raw.borrow_value().tbs_cert.spki)?,
        );
        Ok(py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "load_der_public_key"))?
            .call1((serialized,))?)
    }

    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::PyObject,
    ) -> CryptographyResult<&'p pyo3::PyAny> {
        let hasher = py
            .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
            .getattr(pyo3::intern!(py, "Hash"))?
            .call1((algorithm,))?;
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized =
            pyo3::types::PyBytes::new(py, &asn1::write_single(&self.raw.borrow_value())?);
        hasher.call_method1(pyo3::intern!(py, "update"), (serialized,))?;
        Ok(hasher.call_method0(pyo3::intern!(py, "finalize"))?)
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &'p pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = asn1::write_single(self.raw.borrow_value())?;

        encode_der_data(py, "CERTIFICATE".to_string(), result, encoding)
    }

    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, CryptographyError> {
        let bytes = self.raw.borrow_value().tbs_cert.serial.as_bytes();
        warn_if_negative_serial(py, bytes)?;
        Ok(big_byte_slice_to_py_int(py, bytes)?)
    }

    #[getter]
    fn version<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, CryptographyError> {
        let version = &self.raw.borrow_value().tbs_cert.version;
        cert_version(py, *version)
    }

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        Ok(
            x509::parse_name(py, &self.raw.borrow_value().tbs_cert.issuer)
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("issuer")))?,
        )
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        Ok(
            x509::parse_name(py, &self.raw.borrow_value().tbs_cert.subject)
                .map_err(|e| e.add_location(asn1::ParseLocation::Field("subject")))?,
        )
    }

    #[getter]
    fn tbs_certificate_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = asn1::write_single(&self.raw.borrow_value().tbs_cert)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn tbs_precertificate_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let val = self.raw.borrow_value();
        let mut tbs_precert = val.tbs_cert.clone();
        // Remove the SCT list extension
        match tbs_precert.extensions {
            Some(extensions) => {
                let readable_extensions = extensions.unwrap_read().clone();
                let ext_count = readable_extensions.len();
                let filtered_extensions: Vec<x509::common::Extension<'_>> = readable_extensions
                    .filter(|x| x.extn_id != oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID)
                    .collect();
                if filtered_extensions.len() == ext_count {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Could not find pre-certificate SCT list extension",
                        ),
                    ));
                }
                let filtered_extensions: x509::Extensions<'_> = Asn1ReadableOrWritable::new_write(
                    asn1::SequenceOfWriter::new(filtered_extensions),
                );
                tbs_precert.extensions = Some(filtered_extensions);
                let result = asn1::write_single(&tbs_precert)?;
                Ok(pyo3::types::PyBytes::new(py, &result))
            }
            None => Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Could not find any extensions in TBS certificate",
                ),
            )),
        }
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> &'p pyo3::types::PyBytes {
        pyo3::types::PyBytes::new(py, self.raw.borrow_value().signature.as_bytes())
    }

    #[getter]
    fn not_valid_before<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let dt = &self
            .raw
            .borrow_value()
            .tbs_cert
            .validity
            .not_before
            .as_datetime();
        x509::datetime_to_py(py, dt)
    }

    #[getter]
    fn not_valid_after<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let dt = &self
            .raw
            .borrow_value()
            .tbs_cert
            .validity
            .not_after
            .as_datetime();
        x509::datetime_to_py(py, dt)
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, CryptographyError> {
        let sig_oids_to_hash = py
            .import(pyo3::intern!(py, "cryptography.hazmat._oid"))?
            .getattr(pyo3::intern!(py, "_SIG_OIDS_TO_HASH"))?;
        let hash_alg = sig_oids_to_hash.get_item(self.signature_algorithm_oid(py)?);
        match hash_alg {
            Ok(data) => Ok(data),
            Err(_) => Err(CryptographyError::from(pyo3::PyErr::from_value(
                py.import(pyo3::intern!(py, "cryptography.exceptions"))?
                    .call_method1(
                        "UnsupportedAlgorithm",
                        (format!(
                            "Signature algorithm OID: {} not recognized",
                            self.raw.borrow_value().signature_alg.oid
                        ),),
                    )?,
            ))),
        }
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        oid_to_py_oid(py, &self.raw.borrow_value().signature_alg.oid)
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_cert.extensions,
            |oid, ext_data| match *oid {
                oid::PRECERT_POISON_OID => {
                    asn1::parse_single::<()>(ext_data)?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "PrecertPoison"))?
                            .call0()?,
                    ))
                }
                oid::PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
                    let contents = asn1::parse_single::<&[u8]>(ext_data)?;
                    let scts = sct::parse_scts(py, contents, sct::LogEntryType::PreCertificate)?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(
                                py,
                                "PrecertificateSignedCertificateTimestamps"
                            ))?
                            .call1((scts,))?,
                    ))
                }
                _ => parse_cert_ext(py, oid.clone(), ext_data),
            },
        )
    }

    fn verify_directly_issued_by(
        &self,
        py: pyo3::Python<'_>,
        issuer: pyo3::PyRef<'_, Certificate>,
    ) -> CryptographyResult<()> {
        if self.raw.borrow_value().tbs_cert.signature_alg != self.raw.borrow_value().signature_alg {
            return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "Inner and outer signature algorithms do not match. This is an invalid certificate."
            )));
        };
        if self.raw.borrow_value().tbs_cert.issuer != issuer.raw.borrow_value().tbs_cert.subject {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Issuer certificate subject does not match certificate issuer.",
                ),
            ));
        };
        sign::verify_signature_with_oid(
            py,
            issuer.public_key(py)?,
            &self.raw.borrow_value().signature_alg.oid,
            self.raw.borrow_value().signature.as_bytes(),
            &asn1::write_single(&self.raw.borrow_value().tbs_cert)?,
        )
    }
}

fn cert_version(py: pyo3::Python<'_>, version: u8) -> Result<&pyo3::PyAny, CryptographyError> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    match version {
        0 => Ok(x509_module
            .getattr(pyo3::intern!(py, "Version"))?
            .get_item(pyo3::intern!(py, "v1"))?),
        2 => Ok(x509_module
            .getattr(pyo3::intern!(py, "Version"))?
            .get_item(pyo3::intern!(py, "v3"))?),
        _ => Err(CryptographyError::from(pyo3::PyErr::from_value(
            x509_module
                .getattr(pyo3::intern!(py, "InvalidVersion"))?
                .call1((format!("{} is not a valid X509 version", version), version))?,
        ))),
    }
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_certificate(py: pyo3::Python<'_>, data: &[u8]) -> CryptographyResult<Certificate> {
    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L32-L33
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag == "CERTIFICATE" || p.tag == "X509 CERTIFICATE",
        "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
    )?;
    load_der_x509_certificate(
        py,
        pyo3::types::PyBytes::new(py, &parsed.contents).into_py(py),
    )
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_certificates(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> CryptographyResult<Vec<Certificate>> {
    let certs = pem::parse_many(data)?
        .iter()
        .filter(|p| p.tag == "CERTIFICATE" || p.tag == "X509 CERTIFICATE")
        .map(|p| {
            load_der_x509_certificate(py, pyo3::types::PyBytes::new(py, &p.contents).into_py(py))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(CryptographyError::from(pem::PemError::MalformedFraming));
    }

    Ok(certs)
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_certificate(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> CryptographyResult<Certificate> {
    let raw = OwnedRawCertificate::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;
    // Parse cert version immediately so we can raise error on parse if it is invalid.
    cert_version(py, raw.borrow_value().tbs_cert.version)?;
    // determine if the serial is negative and raise a warning if it is. We want to drop support
    // for this sort of invalid encoding eventually.
    warn_if_negative_serial(py, raw.borrow_value().tbs_cert.serial.as_bytes())?;

    Ok(Certificate {
        raw,
        cached_extensions: None,
    })
}

fn warn_if_negative_serial(py: pyo3::Python<'_>, bytes: &'_ [u8]) -> pyo3::PyResult<()> {
    if bytes[0] & 0x80 != 0 {
        let cryptography_warning = py
            .import(pyo3::intern!(py, "cryptography.utils"))?
            .getattr(pyo3::intern!(py, "DeprecatedIn36"))?;
        pyo3::PyErr::warn(
            py,
            cryptography_warning,
            "Parsed a negative serial number, which is disallowed by RFC 5280.",
            1,
        )?;
    }
    Ok(())
}

// Needed due to clippy type complexity warning.
type SequenceOfPolicyQualifiers<'a> = x509::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>,
    asn1::SequenceOfWriter<'a, PolicyQualifierInfo<'a>, Vec<PolicyQualifierInfo<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct PolicyInformation<'a> {
    pub policy_identifier: asn1::ObjectIdentifier,
    pub policy_qualifiers: Option<SequenceOfPolicyQualifiers<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct PolicyQualifierInfo<'a> {
    pub policy_qualifier_id: asn1::ObjectIdentifier,
    pub qualifier: Qualifier<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) enum Qualifier<'a> {
    CpsUri(asn1::IA5String<'a>),
    UserNotice(UserNotice<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct UserNotice<'a> {
    pub notice_ref: Option<NoticeReference<'a>>,
    pub explicit_text: Option<DisplayText<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct NoticeReference<'a> {
    pub organization: DisplayText<'a>,
    pub notice_numbers: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, asn1::BigUint<'a>>,
        asn1::SequenceOfWriter<'a, asn1::BigUint<'a>, Vec<asn1::BigUint<'a>>>,
    >,
}

// DisplayText also allows BMPString, which we currently do not support.
#[allow(clippy::enum_variant_names)]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) enum DisplayText<'a> {
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    VisibleString(asn1::VisibleString<'a>),
    BmpString(asn1::BMPString<'a>),
}

fn parse_display_text(
    py: pyo3::Python<'_>,
    text: DisplayText<'_>,
) -> pyo3::PyResult<pyo3::PyObject> {
    match text {
        DisplayText::IA5String(o) => Ok(pyo3::types::PyString::new(py, o.as_str()).to_object(py)),
        DisplayText::Utf8String(o) => Ok(pyo3::types::PyString::new(py, o.as_str()).to_object(py)),
        DisplayText::VisibleString(o) => {
            Ok(pyo3::types::PyString::new(py, o.as_str()).to_object(py))
        }
        DisplayText::BmpString(o) => {
            let py_bytes = pyo3::types::PyBytes::new(py, o.as_utf16_be_bytes());
            // TODO: do the string conversion in rust perhaps
            Ok(py_bytes
                .call_method1(
                    pyo3::intern!(py, "decode"),
                    (pyo3::intern!(py, "utf_16_be"),),
                )?
                .to_object(py))
        }
    }
}

fn parse_user_notice(
    py: pyo3::Python<'_>,
    un: UserNotice<'_>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    let et = match un.explicit_text {
        Some(data) => parse_display_text(py, data)?,
        None => py.None(),
    };
    let nr = match un.notice_ref {
        Some(data) => {
            let org = parse_display_text(py, data.organization)?;
            let numbers = pyo3::types::PyList::empty(py);
            for num in data.notice_numbers.unwrap_read().clone() {
                numbers.append(big_byte_slice_to_py_int(py, num.as_bytes())?.to_object(py))?;
            }
            x509_module
                .call_method1(pyo3::intern!(py, "NoticeReference"), (org, numbers))?
                .to_object(py)
        }
        None => py.None(),
    };
    Ok(x509_module
        .call_method1(pyo3::intern!(py, "UserNotice"), (nr, et))?
        .to_object(py))
}

fn parse_policy_qualifiers<'a>(
    py: pyo3::Python<'_>,
    policy_qualifiers: &asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let py_pq = pyo3::types::PyList::empty(py);
    for pqi in policy_qualifiers.clone() {
        let qualifier = match pqi.qualifier {
            Qualifier::CpsUri(data) => {
                if pqi.policy_qualifier_id == oid::CP_CPS_URI_OID {
                    pyo3::types::PyString::new(py, data.as_str()).to_object(py)
                } else {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "CpsUri ASN.1 structure found but OID did not match",
                        ),
                    ));
                }
            }
            Qualifier::UserNotice(un) => {
                if pqi.policy_qualifier_id != oid::CP_USER_NOTICE_OID {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "UserNotice ASN.1 structure found but OID did not match",
                        ),
                    ));
                }
                parse_user_notice(py, un)?
            }
        };
        py_pq.append(qualifier)?;
    }
    Ok(py_pq.to_object(py))
}

fn parse_cp(py: pyo3::Python<'_>, ext_data: &[u8]) -> Result<pyo3::PyObject, CryptographyError> {
    let cp = asn1::parse_single::<asn1::SequenceOf<'_, PolicyInformation<'_>>>(ext_data)?;
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    let certificate_policies = pyo3::types::PyList::empty(py);
    for policyinfo in cp {
        let pi_oid = oid_to_py_oid(py, &policyinfo.policy_identifier)?.to_object(py);
        let py_pqis = match policyinfo.policy_qualifiers {
            Some(policy_qualifiers) => {
                parse_policy_qualifiers(py, policy_qualifiers.unwrap_read())?
            }
            None => py.None(),
        };
        let pi = x509_module
            .call_method1(pyo3::intern!(py, "PolicyInformation"), (pi_oid, py_pqis))?
            .to_object(py);
        certificate_policies.append(pi)?;
    }
    Ok(certificate_policies.to_object(py))
}

// Needed due to clippy type complexity warning.
pub(crate) type SequenceOfSubtrees<'a> = x509::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, GeneralSubtree<'a>>,
    asn1::SequenceOfWriter<'a, GeneralSubtree<'a>, Vec<GeneralSubtree<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct NameConstraints<'a> {
    #[implicit(0)]
    pub permitted_subtrees: Option<SequenceOfSubtrees<'a>>,

    #[implicit(1)]
    pub excluded_subtrees: Option<SequenceOfSubtrees<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct GeneralSubtree<'a> {
    pub base: x509::GeneralName<'a>,

    #[implicit(0)]
    #[default(0u64)]
    pub minimum: u64,

    #[implicit(1)]
    pub maximum: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct MSCertificateTemplate {
    pub template_id: asn1::ObjectIdentifier,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
}

fn parse_general_subtrees(
    py: pyo3::Python<'_>,
    subtrees: SequenceOfSubtrees<'_>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let gns = pyo3::types::PyList::empty(py);
    for gs in subtrees.unwrap_read().clone() {
        gns.append(x509::parse_general_name(py, gs.base)?)?;
    }
    Ok(gns.to_object(py))
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct DistributionPoint<'a> {
    #[explicit(0)]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    pub reasons: crl::ReasonFlags<'a>,

    #[implicit(2)]
    pub crl_issuer: Option<x509::common::SequenceOfGeneralName<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) enum DistributionPointName<'a> {
    #[implicit(0)]
    FullName(x509::common::SequenceOfGeneralName<'a>),

    #[implicit(1)]
    NameRelativeToCRLIssuer(
        x509::Asn1ReadableOrWritable<
            'a,
            asn1::SetOf<'a, x509::AttributeTypeValue<'a>>,
            asn1::SetOfWriter<'a, x509::AttributeTypeValue<'a>, Vec<x509::AttributeTypeValue<'a>>>,
        >,
    ),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct AuthorityKeyIdentifier<'a> {
    #[implicit(0)]
    pub key_identifier: Option<&'a [u8]>,
    #[implicit(1)]
    pub authority_cert_issuer: Option<x509::common::SequenceOfGeneralName<'a>>,
    #[implicit(2)]
    pub authority_cert_serial_number: Option<asn1::BigUint<'a>>,
}

pub(crate) fn parse_distribution_point_name(
    py: pyo3::Python<'_>,
    dp: DistributionPointName<'_>,
) -> Result<(pyo3::PyObject, pyo3::PyObject), CryptographyError> {
    Ok(match dp {
        DistributionPointName::FullName(data) => (
            x509::parse_general_names(py, data.unwrap_read())?,
            py.None(),
        ),
        DistributionPointName::NameRelativeToCRLIssuer(data) => {
            (py.None(), x509::parse_rdn(py, data.unwrap_read())?)
        }
    })
}

fn parse_distribution_point(
    py: pyo3::Python<'_>,
    dp: DistributionPoint<'_>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let (full_name, relative_name) = match dp.distribution_point {
        Some(data) => parse_distribution_point_name(py, data)?,
        None => (py.None(), py.None()),
    };
    let reasons =
        parse_distribution_point_reasons(py, dp.reasons.as_ref().map(|v| v.unwrap_read()))?;
    let crl_issuer = match dp.crl_issuer {
        Some(aci) => x509::parse_general_names(py, aci.unwrap_read())?,
        None => py.None(),
    };
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    Ok(x509_module
        .getattr(pyo3::intern!(py, "DistributionPoint"))?
        .call1((full_name, relative_name, reasons, crl_issuer))?
        .to_object(py))
}

pub(crate) fn parse_distribution_points(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let dps = asn1::parse_single::<asn1::SequenceOf<'_, DistributionPoint<'_>>>(data)?;
    let py_dps = pyo3::types::PyList::empty(py);
    for dp in dps {
        let py_dp = parse_distribution_point(py, dp)?;
        py_dps.append(py_dp)?;
    }
    Ok(py_dps.to_object(py))
}

pub(crate) fn parse_distribution_point_reasons(
    py: pyo3::Python<'_>,
    reasons: Option<&asn1::BitString<'_>>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let reason_bit_mapping = py
        .import(pyo3::intern!(py, "cryptography.x509.extensions"))?
        .getattr(pyo3::intern!(py, "_REASON_BIT_MAPPING"))?;
    Ok(match reasons {
        Some(bs) => {
            let mut vec = Vec::new();
            for i in 1..=8 {
                if bs.has_bit_set(i) {
                    vec.push(reason_bit_mapping.get_item(i)?);
                }
            }
            pyo3::types::PyFrozenSet::new(py, &vec)?.to_object(py)
        }
        None => py.None(),
    })
}

pub(crate) fn encode_distribution_point_reasons(
    py: pyo3::Python<'_>,
    py_reasons: &pyo3::PyAny,
) -> pyo3::PyResult<asn1::OwnedBitString> {
    let reason_flag_mapping = py
        .import(pyo3::intern!(py, "cryptography.x509.extensions"))?
        .getattr(pyo3::intern!(py, "_CRLREASONFLAGS"))?;

    let mut bits = vec![0, 0];
    for py_reason in py_reasons.iter()? {
        let bit = reason_flag_mapping
            .get_item(py_reason?)?
            .extract::<usize>()?;
        set_bit(&mut bits, bit, true)
    }
    if bits[1] == 0 {
        bits.truncate(1);
    }
    let unused_bits = bits.last().unwrap().trailing_zeros() as u8;
    Ok(asn1::OwnedBitString::new(bits, unused_bits).unwrap())
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, pyo3::prelude::FromPyObject)]
pub(crate) struct BasicConstraints {
    #[default(false)]
    pub ca: bool,
    pub path_length: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct PolicyConstraints {
    #[implicit(0)]
    pub require_explicit_policy: Option<u64>,
    #[implicit(1)]
    pub inhibit_policy_mapping: Option<u64>,
}

pub(crate) fn parse_authority_key_identifier<'p>(
    py: pyo3::Python<'p>,
    ext_data: &[u8],
) -> Result<&'p pyo3::PyAny, CryptographyError> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    let aki = asn1::parse_single::<AuthorityKeyIdentifier<'_>>(ext_data)?;
    let serial = match aki.authority_cert_serial_number {
        Some(biguint) => big_byte_slice_to_py_int(py, biguint.as_bytes())?.to_object(py),
        None => py.None(),
    };
    let issuer = match aki.authority_cert_issuer {
        Some(aci) => x509::parse_general_names(py, aci.unwrap_read())?,
        None => py.None(),
    };
    Ok(x509_module
        .getattr(pyo3::intern!(py, "AuthorityKeyIdentifier"))?
        .call1((aki.key_identifier, issuer, serial))?)
}

pub(crate) fn parse_access_descriptions(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    let ads = pyo3::types::PyList::empty(py);
    let parsed = asn1::parse_single::<x509::common::SequenceOfAccessDescriptions<'_>>(ext_data)?;
    for access in parsed.unwrap_read().clone() {
        let py_oid = oid_to_py_oid(py, &access.access_method)?.to_object(py);
        let gn = x509::parse_general_name(py, access.access_location)?;
        let ad = x509_module
            .getattr(pyo3::intern!(py, "AccessDescription"))?
            .call1((py_oid, gn))?
            .to_object(py);
        ads.append(ad)?;
    }
    Ok(ads.to_object(py))
}

pub fn parse_cert_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier,
    ext_data: &[u8],
) -> CryptographyResult<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    match oid {
        oid::SUBJECT_ALTERNATIVE_NAME_OID => {
            let gn_seq =
                asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(ext_data)?;
            let sans = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "SubjectAlternativeName"))?
                    .call1((sans,))?,
            ))
        }
        oid::ISSUER_ALTERNATIVE_NAME_OID => {
            let gn_seq =
                asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(ext_data)?;
            let ians = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "IssuerAlternativeName"))?
                    .call1((ians,))?,
            ))
        }
        oid::TLS_FEATURE_OID => {
            let tls_feature_type_to_enum = py
                .import(pyo3::intern!(py, "cryptography.x509.extensions"))?
                .getattr(pyo3::intern!(py, "_TLS_FEATURE_TYPE_TO_ENUM"))?;

            let features = pyo3::types::PyList::empty(py);
            for feature in asn1::parse_single::<asn1::SequenceOf<'_, u64>>(ext_data)? {
                let py_feature = tls_feature_type_to_enum.get_item(feature.to_object(py))?;
                features.append(py_feature)?;
            }
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "TLSFeature"))?
                    .call1((features,))?,
            ))
        }
        oid::SUBJECT_KEY_IDENTIFIER_OID => {
            let identifier = asn1::parse_single::<&[u8]>(ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "SubjectKeyIdentifier"))?
                    .call1((identifier,))?,
            ))
        }
        oid::EXTENDED_KEY_USAGE_OID => {
            let ekus = pyo3::types::PyList::empty(py);
            for oid in asn1::parse_single::<asn1::SequenceOf<'_, asn1::ObjectIdentifier>>(ext_data)?
            {
                let oid_obj = oid_to_py_oid(py, &oid)?;
                ekus.append(oid_obj)?;
            }
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "ExtendedKeyUsage"))?
                    .call1((ekus,))?,
            ))
        }
        oid::KEY_USAGE_OID => {
            let kus = asn1::parse_single::<asn1::BitString<'_>>(ext_data)?;
            let digital_signature = kus.has_bit_set(0);
            let content_comitment = kus.has_bit_set(1);
            let key_encipherment = kus.has_bit_set(2);
            let data_encipherment = kus.has_bit_set(3);
            let key_agreement = kus.has_bit_set(4);
            let key_cert_sign = kus.has_bit_set(5);
            let crl_sign = kus.has_bit_set(6);
            let encipher_only = kus.has_bit_set(7);
            let decipher_only = kus.has_bit_set(8);
            Ok(Some(
                x509_module.getattr(pyo3::intern!(py, "KeyUsage"))?.call1((
                    digital_signature,
                    content_comitment,
                    key_encipherment,
                    data_encipherment,
                    key_agreement,
                    key_cert_sign,
                    crl_sign,
                    encipher_only,
                    decipher_only,
                ))?,
            ))
        }
        oid::AUTHORITY_INFORMATION_ACCESS_OID => {
            let ads = parse_access_descriptions(py, ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "AuthorityInformationAccess"))?
                    .call1((ads,))?,
            ))
        }
        oid::SUBJECT_INFORMATION_ACCESS_OID => {
            let ads = parse_access_descriptions(py, ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "SubjectInformationAccess"))?
                    .call1((ads,))?,
            ))
        }
        oid::CERTIFICATE_POLICIES_OID => {
            let cp = parse_cp(py, ext_data)?;
            Ok(Some(x509_module.call_method1(
                pyo3::intern!(py, "CertificatePolicies"),
                (cp,),
            )?))
        }
        oid::POLICY_CONSTRAINTS_OID => {
            let pc = asn1::parse_single::<PolicyConstraints>(ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "PolicyConstraints"))?
                    .call1((pc.require_explicit_policy, pc.inhibit_policy_mapping))?,
            ))
        }
        oid::OCSP_NO_CHECK_OID => {
            asn1::parse_single::<()>(ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "OCSPNoCheck"))?
                    .call0()?,
            ))
        }
        oid::INHIBIT_ANY_POLICY_OID => {
            let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
            let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "InhibitAnyPolicy"))?
                    .call1((pynum,))?,
            ))
        }
        oid::BASIC_CONSTRAINTS_OID => {
            let bc = asn1::parse_single::<BasicConstraints>(ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "BasicConstraints"))?
                    .call1((bc.ca, bc.path_length))?,
            ))
        }
        oid::AUTHORITY_KEY_IDENTIFIER_OID => {
            Ok(Some(parse_authority_key_identifier(py, ext_data)?))
        }
        oid::CRL_DISTRIBUTION_POINTS_OID => {
            let dp = parse_distribution_points(py, ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "CRLDistributionPoints"))?
                    .call1((dp,))?,
            ))
        }
        oid::FRESHEST_CRL_OID => {
            let dp = parse_distribution_points(py, ext_data)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "FreshestCRL"))?
                    .call1((dp,))?,
            ))
        }
        oid::NAME_CONSTRAINTS_OID => {
            let nc = asn1::parse_single::<NameConstraints<'_>>(ext_data)?;
            let permitted_subtrees = match nc.permitted_subtrees {
                Some(data) => parse_general_subtrees(py, data)?,
                None => py.None(),
            };
            let excluded_subtrees = match nc.excluded_subtrees {
                Some(data) => parse_general_subtrees(py, data)?,
                None => py.None(),
            };
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "NameConstraints"))?
                    .call1((permitted_subtrees, excluded_subtrees))?,
            ))
        }
        oid::MS_CERTIFICATE_TEMPLATE => {
            let ms_cert_tpl = asn1::parse_single::<MSCertificateTemplate>(ext_data)?;
            let py_oid = oid_to_py_oid(py, &ms_cert_tpl.template_id)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "MSCertificateTemplate"))?
                    .call1((py_oid, ms_cert_tpl.major_version, ms_cert_tpl.minor_version))?,
            ))
        }
        _ => Ok(None),
    }
}

pub(crate) fn time_from_py(
    py: pyo3::Python<'_>,
    val: &pyo3::PyAny,
) -> CryptographyResult<x509::Time> {
    let dt = x509::py_to_datetime(py, val)?;
    time_from_datetime(dt)
}

pub(crate) fn time_from_datetime(dt: asn1::DateTime) -> CryptographyResult<x509::Time> {
    if dt.year() >= 2050 {
        Ok(x509::Time::GeneralizedTime(asn1::GeneralizedTime::new(dt)?))
    } else {
        Ok(x509::Time::UtcTime(asn1::UtcTime::new(dt).unwrap()))
    }
}

#[pyo3::prelude::pyfunction]
fn create_x509_certificate(
    py: pyo3::Python<'_>,
    builder: &pyo3::PyAny,
    private_key: &pyo3::PyAny,
    hash_algorithm: &pyo3::PyAny,
) -> CryptographyResult<Certificate> {
    let sigalg = x509::sign::compute_signature_algorithm(py, private_key, hash_algorithm)?;
    let serialization_mod = py.import(pyo3::intern!(
        py,
        "cryptography.hazmat.primitives.serialization"
    ))?;
    let der_encoding = serialization_mod
        .getattr(pyo3::intern!(py, "Encoding"))?
        .getattr(pyo3::intern!(py, "DER"))?;
    let spki_format = serialization_mod
        .getattr(pyo3::intern!(py, "PublicFormat"))?
        .getattr(pyo3::intern!(py, "SubjectPublicKeyInfo"))?;

    let spki_bytes = builder
        .getattr(pyo3::intern!(py, "_public_key"))?
        .call_method1(
            pyo3::intern!(py, "public_bytes"),
            (der_encoding, spki_format),
        )?
        .extract::<&[u8]>()?;

    let py_serial = builder
        .getattr(pyo3::intern!(py, "_serial_number"))?
        .extract()?;

    let py_issuer_name = builder.getattr(pyo3::intern!(py, "_issuer_name"))?;
    let py_subject_name = builder.getattr(pyo3::intern!(py, "_subject_name"))?;
    let py_not_before = builder.getattr(pyo3::intern!(py, "_not_valid_before"))?;
    let py_not_after = builder.getattr(pyo3::intern!(py, "_not_valid_after"))?;

    let tbs_cert = TbsCertificate {
        version: builder
            .getattr(pyo3::intern!(py, "_version"))?
            .getattr(pyo3::intern!(py, "value"))?
            .extract()?,
        serial: asn1::BigInt::new(py_uint_to_big_endian_bytes(py, py_serial)?).unwrap(),
        signature_alg: sigalg.clone(),
        issuer: x509::common::encode_name(py, py_issuer_name)?,
        validity: Validity {
            not_before: time_from_py(py, py_not_before)?,
            not_after: time_from_py(py, py_not_after)?,
        },
        subject: x509::common::encode_name(py, py_subject_name)?,
        spki: asn1::parse_single(spki_bytes)?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: x509::common::encode_extensions(
            py,
            builder.getattr(pyo3::intern!(py, "_extensions"))?,
            extensions::encode_extension,
        )?,
    };

    let tbs_bytes = asn1::write_single(&tbs_cert)?;
    let signature = x509::sign::sign_data(py, private_key, hash_algorithm, &tbs_bytes)?;
    let data = asn1::write_single(&RawCertificate {
        tbs_cert,
        signature_alg: sigalg,
        signature: asn1::BitString::new(signature, 0).unwrap(),
    })?;
    load_der_x509_certificate(py, pyo3::types::PyBytes::new(py, &data).into_py(py))
}

pub(crate) fn set_bit(vals: &mut [u8], n: usize, set: bool) {
    let idx = n / 8;
    let v = 1 << (7 - (n & 0x07));
    if set {
        vals[idx] |= v;
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_certificate))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_certificate))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_certificates))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(create_x509_certificate))?;

    module.add_class::<Certificate>()?;

    Ok(())
}
