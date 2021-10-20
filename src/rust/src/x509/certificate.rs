// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, py_uint_to_big_endian_bytes, PyAsn1Error, PyAsn1Result};
use crate::x509;
use crate::x509::{crl, sct};
use pyo3::ToPyObject;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    static ref PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.2").unwrap();
    static ref CP_CPS_URI_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.1").unwrap();
    static ref CP_USER_NOTICE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.2").unwrap();
    static ref SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap();
    static ref ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.18").unwrap();
    static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    static ref AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1").unwrap();
    static ref SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.11").unwrap();
    static ref CERTIFICATE_POLICIES_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.32").unwrap();
    static ref POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.36").unwrap();
    static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();
    static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();
    static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    static ref AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    static ref CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.31").unwrap();
    static ref FRESHEST_CRL_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.46").unwrap();
    static ref NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.30").unwrap();
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
pub(crate) struct RawCertificate<'a> {
    tbs_cert: TbsCertificate<'a>,
    signature_alg: x509::AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
struct TbsCertificate<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    serial: asn1::BigUint<'a>,
    _signature_alg: asn1::Sequence<'a>,

    issuer: x509::Name<'a>,
    validity: Validity,
    subject: x509::Name<'a>,

    spki: SubjectPublicKeyInfo<'a>,
    #[implicit(1)]
    _issuer_unique_id: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    _subject_unique_id: Option<asn1::BitString<'a>>,
    #[explicit(3)]
    extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
pub(crate) struct Validity {
    not_before: x509::Time,
    not_after: x509::Time,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
pub(crate) struct SubjectPublicKeyInfo<'a> {
    _algorithm: x509::AlgorithmIdentifier<'a>,
    _subject_public_key: asn1::BitString<'a>,
}

#[ouroboros::self_referencing]
pub(crate) struct OwnedRawCertificate {
    data: Arc<[u8]>,

    #[borrows(data)]
    #[covariant]
    value: RawCertificate<'this>,
}

impl OwnedRawCertificate {
    // Re-expose ::new with `pub(crate)` visibility.
    pub(crate) fn new_public(
        data: Arc<[u8]>,
        value_ref_builder: impl for<'this> FnOnce(&'this Arc<[u8]>) -> RawCertificate<'this>,
    ) -> OwnedRawCertificate {
        OwnedRawCertificate::new(data, value_ref_builder)
    }
}

#[pyo3::prelude::pyclass]
pub(crate) struct Certificate {
    pub(crate) raw: OwnedRawCertificate,
    pub(crate) cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pyproto]
impl pyo3::PyObjectProtocol for Certificate {
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_value().hash(&mut hasher);
        hasher.finish()
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<Certificate>,
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

    fn __repr__(&self) -> pyo3::PyResult<String> {
        let gil = pyo3::Python::acquire_gil();
        let py = gil.python();

        let subject = self.subject(py)?;
        let subject_repr = subject.repr()?.extract::<&str>()?;
        Ok(format!("<Certificate(subject={}, ...)>", subject_repr))
    }
}

#[pyo3::prelude::pymethods]
impl Certificate {
    fn __deepcopy__(slf: pyo3::PyRef<'_, Self>, _memo: pyo3::PyObject) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn public_key<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized = pyo3::types::PyBytes::new(
            py,
            &asn1::write_single(&self.raw.borrow_value().tbs_cert.spki),
        );
        py.import("cryptography.hazmat.primitives.serialization")?
            .getattr("load_der_public_key")?
            .call1((serialized,))
    }

    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::PyObject,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let hasher = py
            .import("cryptography.hazmat.primitives.hashes")?
            .getattr("Hash")?
            .call1((algorithm,))?;
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized =
            pyo3::types::PyBytes::new(py, &asn1::write_single(&self.raw.borrow_value()));
        hasher.call_method1("update", (serialized,))?;
        hasher.call_method0("finalize")
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
        let encoding_class = py
            .import("cryptography.hazmat.primitives.serialization")?
            .getattr("Encoding")?;

        let result = asn1::write_single(self.raw.borrow_value());
        if encoding == encoding_class.getattr("DER")? {
            Ok(pyo3::types::PyBytes::new(py, &result))
        } else if encoding == encoding_class.getattr("PEM")? {
            let pem = pem::encode_config(
                &pem::Pem {
                    tag: "CERTIFICATE".to_string(),
                    contents: result,
                },
                pem::EncodeConfig {
                    line_ending: pem::LineEnding::LF,
                },
            )
            .into_bytes();
            Ok(pyo3::types::PyBytes::new(py, &pem))
        } else {
            Err(pyo3::exceptions::PyTypeError::new_err(
                "encoding must be Encoding.DER or Encoding.PEM",
            ))
        }
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        Ok(big_asn1_uint_to_py(
            py,
            self.raw.borrow_value().tbs_cert.serial,
        )?)
    }

    #[getter]
    fn version<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let version = &self.raw.borrow_value().tbs_cert.version;
        cert_version(py, *version)
    }

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::parse_name(py, &self.raw.borrow_value().tbs_cert.issuer)
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::parse_name(py, &self.raw.borrow_value().tbs_cert.subject)
    }

    #[getter]
    fn tbs_certificate_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::types::PyBytes, PyAsn1Error> {
        let result = asn1::write_single(&self.raw.borrow_value().tbs_cert);
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::types::PyBytes, PyAsn1Error> {
        Ok(pyo3::types::PyBytes::new(
            py,
            self.raw.borrow_value().signature.as_bytes(),
        ))
    }

    #[getter]
    fn not_valid_before<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let chrono = &self
            .raw
            .borrow_value()
            .tbs_cert
            .validity
            .not_before
            .as_chrono();
        x509::chrono_to_py(py, chrono)
    }

    #[getter]
    fn not_valid_after<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let chrono = &self
            .raw
            .borrow_value()
            .tbs_cert
            .validity
            .not_after
            .as_chrono();
        x509::chrono_to_py(py, chrono)
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let sig_oids_to_hash = py
            .import("cryptography.hazmat._oid")?
            .getattr("_SIG_OIDS_TO_HASH")?;
        let hash_alg = sig_oids_to_hash.get_item(self.signature_algorithm_oid(py)?);
        match hash_alg {
            Ok(data) => Ok(data),
            Err(_) => Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                py.import("cryptography.exceptions")?.call_method1(
                    "UnsupportedAlgorithm",
                    (format!(
                        "Signature algorithm OID: {} not recognized",
                        self.raw.borrow_value().signature_alg.oid.to_string()
                    ),),
                )?,
            ))),
        }
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        py.import("cryptography.x509")?.call_method1(
            "ObjectIdentifier",
            (self.raw.borrow_value().signature_alg.oid.to_string(),),
        )
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_cert.extensions,
            |oid, ext_data| {
                if oid == &*PRECERT_POISON_OID {
                    asn1::parse_single::<()>(ext_data)?;
                    Ok(Some(x509_module.getattr("PrecertPoison")?.call0()?))
                } else if oid == &*PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID {
                    let contents = asn1::parse_single::<&[u8]>(ext_data)?;
                    let scts = sct::parse_scts(py, contents, sct::LogEntryType::PreCertificate)?;
                    Ok(Some(
                        x509_module
                            .getattr("PrecertificateSignedCertificateTimestamps")?
                            .call1((scts,))?,
                    ))
                } else {
                    parse_cert_ext(py, oid.clone(), ext_data)
                }
            },
        )
    }
    // This getter exists for compatibility with pyOpenSSL and will be removed.
    // DO NOT RELY ON IT. WE WILL BREAK YOU WHEN WE FEEL LIKE IT.
    #[getter]
    fn _x509<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let cryptography_warning = py.import("cryptography.utils")?.getattr("DeprecatedIn35")?;
        let warnings = py.import("warnings")?;
        warnings.call_method1(
            "warn",
            (
                "This version of cryptography contains a temporary pyOpenSSL fallback path. Upgrade pyOpenSSL now.",
                cryptography_warning,
            ),
        )?;
        let backend = py
            .import("cryptography.hazmat.backends.openssl.backend")?
            .getattr("backend")?;
        Ok(backend.call_method1("_cert2ossl", (slf,))?)
    }
}

fn cert_version(py: pyo3::Python<'_>, version: u8) -> Result<&pyo3::PyAny, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    match version {
        0 => Ok(x509_module.getattr("Version")?.get_item("v1")?),
        2 => Ok(x509_module.getattr("Version")?.get_item("v3")?),
        _ => Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
            x509_module
                .getattr("InvalidVersion")?
                .call1((format!("{} is not a valid X509 version", version), version))?,
        ))),
    }
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_certificate(py: pyo3::Python<'_>, data: &[u8]) -> PyAsn1Result<Certificate> {
    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L32-L33
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag == "CERTIFICATE" || p.tag == "X509 CERTIFICATE",
        "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
        "Valid PEM but multiple BEGIN CERTIFICATE/END CERTIFICATE delimiters."
    )?;
    load_der_x509_certificate(py, &parsed.contents)
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_certificate(py: pyo3::Python<'_>, data: &[u8]) -> PyAsn1Result<Certificate> {
    let raw = OwnedRawCertificate::try_new(Arc::from(data), |data| asn1::parse_single(data))?;
    // Parse cert version immediately so we can raise error on parse if it is invalid.
    cert_version(py, raw.borrow_value().tbs_cert.version)?;
    Ok(Certificate {
        raw,
        cached_extensions: None,
    })
}

// Needed due to clippy type complexity warning.
type SequenceOfPolicyQualifiers<'a> = x509::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>,
    asn1::SequenceOfWriter<'a, PolicyQualifierInfo<'a>, Vec<PolicyQualifierInfo<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct PolicyInformation<'a> {
    policy_identifier: asn1::ObjectIdentifier<'a>,
    policy_qualifiers: Option<SequenceOfPolicyQualifiers<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct PolicyQualifierInfo<'a> {
    policy_qualifier_id: asn1::ObjectIdentifier<'a>,
    qualifier: Qualifier<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
enum Qualifier<'a> {
    CpsUri(asn1::IA5String<'a>),
    UserNotice(UserNotice<'a>),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct UserNotice<'a> {
    notice_ref: Option<NoticeReference<'a>>,
    explicit_text: Option<DisplayText<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct NoticeReference<'a> {
    organization: DisplayText<'a>,
    notice_numbers: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, asn1::BigUint<'a>>,
        asn1::SequenceOfWriter<'a, asn1::BigUint<'a>, Vec<asn1::BigUint<'a>>>,
    >,
}

// DisplayText also allows BMPString, which we currently do not support.
#[allow(clippy::enum_variant_names)]
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
enum DisplayText<'a> {
    IA5String(asn1::IA5String<'a>),
    Utf8String(asn1::Utf8String<'a>),
    VisibleString(asn1::VisibleString<'a>),
}

fn parse_display_text(py: pyo3::Python<'_>, text: DisplayText<'_>) -> pyo3::PyObject {
    match text {
        DisplayText::IA5String(o) => pyo3::types::PyString::new(py, o.as_str()).to_object(py),
        DisplayText::Utf8String(o) => pyo3::types::PyString::new(py, o.as_str()).to_object(py),
        DisplayText::VisibleString(o) => pyo3::types::PyString::new(py, o.as_str()).to_object(py),
    }
}

fn parse_user_notice(
    py: pyo3::Python<'_>,
    un: UserNotice<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let et = match un.explicit_text {
        Some(data) => parse_display_text(py, data),
        None => py.None(),
    };
    let nr = match un.notice_ref {
        Some(data) => {
            let org = parse_display_text(py, data.organization);
            let numbers = pyo3::types::PyList::empty(py);
            for num in data.notice_numbers.unwrap_read().clone() {
                numbers.append(big_asn1_uint_to_py(py, num)?.to_object(py))?;
            }
            x509_module
                .call_method1("NoticeReference", (org, numbers))?
                .to_object(py)
        }
        None => py.None(),
    };
    Ok(x509_module
        .call_method1("UserNotice", (nr, et))?
        .to_object(py))
}

fn parse_policy_qualifiers<'a>(
    py: pyo3::Python<'_>,
    policy_qualifiers: &asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let py_pq = pyo3::types::PyList::empty(py);
    for pqi in policy_qualifiers.clone() {
        let qualifier = match pqi.qualifier {
            Qualifier::CpsUri(data) => {
                if pqi.policy_qualifier_id == *CP_CPS_URI_OID {
                    pyo3::types::PyString::new(py, data.as_str()).to_object(py)
                } else {
                    return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                        "CpsUri ASN.1 structure found but OID did not match",
                    )));
                }
            }
            Qualifier::UserNotice(un) => {
                if pqi.policy_qualifier_id != *CP_USER_NOTICE_OID {
                    return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                        "UserNotice ASN.1 structure found but OID did not match",
                    )));
                }
                parse_user_notice(py, un)?
            }
        };
        py_pq.append(qualifier)?;
    }
    Ok(py_pq.to_object(py))
}

fn parse_cp(py: pyo3::Python<'_>, ext_data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let cp = asn1::parse_single::<asn1::SequenceOf<'_, PolicyInformation<'_>>>(ext_data)?;
    let x509_module = py.import("cryptography.x509")?;
    let certificate_policies = pyo3::types::PyList::empty(py);
    for policyinfo in cp {
        let pi_oid = x509_module
            .call_method1(
                "ObjectIdentifier",
                (policyinfo.policy_identifier.to_string(),),
            )?
            .to_object(py);
        let py_pqis = match policyinfo.policy_qualifiers {
            Some(policy_qualifiers) => {
                parse_policy_qualifiers(py, policy_qualifiers.unwrap_read())?
            }
            None => py.None(),
        };
        let pi = x509_module
            .call_method1("PolicyInformation", (pi_oid, py_pqis))?
            .to_object(py);
        certificate_policies.append(pi)?;
    }
    Ok(certificate_policies.to_object(py))
}

// Needed due to clippy type complexity warning.
type SequenceOfSubtrees<'a> = x509::Asn1ReadableOrWritable<
    'a,
    asn1::SequenceOf<'a, GeneralSubtree<'a>>,
    asn1::SequenceOfWriter<'a, GeneralSubtree<'a>, Vec<GeneralSubtree<'a>>>,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct NameConstraints<'a> {
    #[implicit(0)]
    permitted_subtrees: Option<SequenceOfSubtrees<'a>>,

    #[implicit(1)]
    excluded_subtrees: Option<SequenceOfSubtrees<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct GeneralSubtree<'a> {
    base: x509::GeneralName<'a>,

    #[implicit(0)]
    #[default(0u64)]
    minimum: u64,

    #[implicit(1)]
    maximum: Option<u64>,
}

fn encode_general_subtrees<'a>(
    py: pyo3::Python<'a>,
    subtrees: &'a pyo3::PyAny,
) -> Result<Option<SequenceOfSubtrees<'a>>, PyAsn1Error> {
    if subtrees.is_none() {
        Ok(None)
    } else {
        let mut subtree_seq = vec![];
        for name in subtrees.iter()? {
            let gn = x509::common::encode_general_name(py, name?)?;
            subtree_seq.push(GeneralSubtree {
                base: gn,
                minimum: 0,
                maximum: None,
            });
        }
        Ok(Some(x509::Asn1ReadableOrWritable::new_write(
            asn1::SequenceOfWriter::new(subtree_seq),
        )))
    }
}

fn parse_general_subtrees(
    py: pyo3::Python<'_>,
    subtrees: SequenceOfSubtrees<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gs in subtrees.unwrap_read().clone() {
        gns.append(x509::parse_general_name(py, gs.base)?)?;
    }
    Ok(gns.to_object(py))
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub(crate) struct DistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    reasons: crl::ReasonFlags<'a>,

    #[implicit(2)]
    crl_issuer: Option<x509::common::SequenceOfGeneralName<'a>>,
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
    key_identifier: Option<&'a [u8]>,
    #[implicit(1)]
    authority_cert_issuer: Option<x509::common::SequenceOfGeneralName<'a>>,
    #[implicit(2)]
    authority_cert_serial_number: Option<asn1::BigUint<'a>>,
}

pub(crate) fn encode_authority_key_identifier<'a>(
    py: pyo3::Python<'a>,
    py_aki: &'a pyo3::PyAny,
) -> pyo3::PyResult<AuthorityKeyIdentifier<'a>> {
    let key_identifier = if py_aki.getattr("key_identifier")?.is_none() {
        None
    } else {
        Some(py_aki.getattr("key_identifier")?.extract::<&[u8]>()?)
    };
    let authority_cert_issuer = if py_aki.getattr("authority_cert_issuer")?.is_none() {
        None
    } else {
        let gns = x509::common::encode_general_names(py, py_aki.getattr("authority_cert_issuer")?)?;
        Some(x509::Asn1ReadableOrWritable::new_write(
            asn1::SequenceOfWriter::new(gns),
        ))
    };
    let authority_cert_serial_number = if py_aki.getattr("authority_cert_serial_number")?.is_none()
    {
        None
    } else {
        let py_num = py_aki.getattr("authority_cert_serial_number")?.downcast()?;
        let serial_bytes = py_uint_to_big_endian_bytes(py, py_num)?;
        Some(asn1::BigUint::new(serial_bytes).unwrap())
    };
    Ok(AuthorityKeyIdentifier {
        key_identifier,
        authority_cert_issuer,
        authority_cert_serial_number,
    })
}

pub(crate) fn parse_distribution_point_name(
    py: pyo3::Python<'_>,
    dp: DistributionPointName<'_>,
) -> Result<(pyo3::PyObject, pyo3::PyObject), PyAsn1Error> {
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
) -> Result<pyo3::PyObject, PyAsn1Error> {
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
    let x509_module = py.import("cryptography.x509")?;
    Ok(x509_module
        .getattr("DistributionPoint")?
        .call1((full_name, relative_name, reasons, crl_issuer))?
        .to_object(py))
}

pub(crate) fn parse_distribution_points(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let dps = asn1::parse_single::<asn1::SequenceOf<'_, DistributionPoint<'_>>>(data)?;
    let py_dps = pyo3::types::PyList::empty(py);
    for dp in dps {
        let py_dp = parse_distribution_point(py, dp)?;
        py_dps.append(py_dp)?;
    }
    Ok(py_dps.to_object(py))
}

pub(crate) fn encode_distribution_points<'p>(
    py: pyo3::Python<'p>,
    py_dps: &'p pyo3::PyAny,
) -> pyo3::PyResult<Vec<DistributionPoint<'p>>> {
    let mut dps = vec![];
    for py_dp in py_dps.iter()? {
        let py_dp = py_dp?;

        let crl_issuer = if py_dp.getattr("crl_issuer")?.is_true()? {
            let gns = x509::common::encode_general_names(py, py_dp.getattr("crl_issuer")?)?;
            Some(x509::Asn1ReadableOrWritable::new_write(
                asn1::SequenceOfWriter::new(gns),
            ))
        } else {
            None
        };
        let distribution_point = if py_dp.getattr("full_name")?.is_true()? {
            let gns = x509::common::encode_general_names(py, py_dp.getattr("full_name")?)?;
            Some(DistributionPointName::FullName(
                x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(gns)),
            ))
        } else if py_dp.getattr("relative_name")?.is_true()? {
            let mut name_entries = vec![];
            for py_name_entry in py_dp.getattr("relative_name")?.iter()? {
                name_entries.push(x509::common::encode_name_entry(py, py_name_entry?)?);
            }
            Some(DistributionPointName::NameRelativeToCRLIssuer(
                x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(name_entries)),
            ))
        } else {
            None
        };
        let reasons = if py_dp.getattr("reasons")?.is_true()? {
            let py_reasons = py_dp.getattr("reasons")?;
            let reasons = encode_distribution_point_reasons(py, py_reasons)?;
            Some(x509::Asn1ReadableOrWritable::new_write(reasons))
        } else {
            None
        };
        dps.push(DistributionPoint {
            crl_issuer,
            distribution_point,
            reasons,
        });
    }
    Ok(dps)
}

pub(crate) fn parse_distribution_point_reasons(
    py: pyo3::Python<'_>,
    reasons: Option<&asn1::BitString<'_>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let reason_bit_mapping = py
        .import("cryptography.x509.extensions")?
        .getattr("_REASON_BIT_MAPPING")?;
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
        .import("cryptography.hazmat.backends.openssl.encode_asn1")?
        .getattr("_CRLREASONFLAGS")?;

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
    Ok(asn1::OwnedBitString::new(bits, 0).unwrap())
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct BasicConstraints {
    #[default(false)]
    ca: bool,
    path_length: Option<u64>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct PolicyConstraints {
    #[implicit(0)]
    require_explicit_policy: Option<u64>,
    #[implicit(1)]
    inhibit_policy_mapping: Option<u64>,
}

pub(crate) fn parse_authority_key_identifier<'p>(
    py: pyo3::Python<'p>,
    ext_data: &[u8],
) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let aki = asn1::parse_single::<AuthorityKeyIdentifier<'_>>(ext_data)?;
    let serial = match aki.authority_cert_serial_number {
        Some(biguint) => big_asn1_uint_to_py(py, biguint)?.to_object(py),
        None => py.None(),
    };
    let issuer = match aki.authority_cert_issuer {
        Some(aci) => x509::parse_general_names(py, aci.unwrap_read())?,
        None => py.None(),
    };
    Ok(x509_module.getattr("AuthorityKeyIdentifier")?.call1((
        aki.key_identifier,
        issuer,
        serial,
    ))?)
}

pub(crate) fn parse_access_descriptions(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let ads = pyo3::types::PyList::empty(py);
    let parsed = asn1::parse_single::<x509::common::SequenceOfAccessDescriptions<'_>>(ext_data)?;
    for access in parsed.unwrap_read().clone() {
        let py_oid = x509_module
            .call_method1("ObjectIdentifier", (access.access_method.to_string(),))?
            .to_object(py);
        let gn = x509::parse_general_name(py, access.access_location)?;
        let ad = x509_module
            .getattr("AccessDescription")?
            .call1((py_oid, gn))?
            .to_object(py);
        ads.append(ad)?;
    }
    Ok(ads.to_object(py))
}

pub fn parse_cert_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier<'_>,
    ext_data: &[u8],
) -> PyAsn1Result<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import("cryptography.x509")?;
    if oid == *SUBJECT_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(ext_data)?;
        let sans = x509::parse_general_names(py, &gn_seq)?;
        Ok(Some(
            x509_module
                .getattr("SubjectAlternativeName")?
                .call1((sans,))?,
        ))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(ext_data)?;
        let ians = x509::parse_general_names(py, &gn_seq)?;
        Ok(Some(
            x509_module
                .getattr("IssuerAlternativeName")?
                .call1((ians,))?,
        ))
    } else if oid == *TLS_FEATURE_OID {
        let tls_feature_type_to_enum = py
            .import("cryptography.x509.extensions")?
            .getattr("_TLS_FEATURE_TYPE_TO_ENUM")?;

        let features = pyo3::types::PyList::empty(py);
        for feature in asn1::parse_single::<asn1::SequenceOf<'_, u64>>(ext_data)? {
            let py_feature = tls_feature_type_to_enum.get_item(feature.to_object(py))?;
            features.append(py_feature)?;
        }
        Ok(Some(x509_module.getattr("TLSFeature")?.call1((features,))?))
    } else if oid == *SUBJECT_KEY_IDENTIFIER_OID {
        let identifier = asn1::parse_single::<&[u8]>(ext_data)?;
        Ok(Some(
            x509_module
                .getattr("SubjectKeyIdentifier")?
                .call1((identifier,))?,
        ))
    } else if oid == *EXTENDED_KEY_USAGE_OID {
        let ekus = pyo3::types::PyList::empty(py);
        for oid in asn1::parse_single::<asn1::SequenceOf<'_, asn1::ObjectIdentifier<'_>>>(ext_data)?
        {
            let oid_obj = x509_module.call_method1("ObjectIdentifier", (oid.to_string(),))?;
            ekus.append(oid_obj)?;
        }
        Ok(Some(
            x509_module.getattr("ExtendedKeyUsage")?.call1((ekus,))?,
        ))
    } else if oid == *KEY_USAGE_OID {
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
        Ok(Some(x509_module.getattr("KeyUsage")?.call1((
            digital_signature,
            content_comitment,
            key_encipherment,
            data_encipherment,
            key_agreement,
            key_cert_sign,
            crl_sign,
            encipher_only,
            decipher_only,
        ))?))
    } else if oid == *AUTHORITY_INFORMATION_ACCESS_OID {
        let ads = parse_access_descriptions(py, ext_data)?;
        Ok(Some(
            x509_module
                .getattr("AuthorityInformationAccess")?
                .call1((ads,))?,
        ))
    } else if oid == *SUBJECT_INFORMATION_ACCESS_OID {
        let ads = parse_access_descriptions(py, ext_data)?;
        Ok(Some(
            x509_module
                .getattr("SubjectInformationAccess")?
                .call1((ads,))?,
        ))
    } else if oid == *CERTIFICATE_POLICIES_OID {
        let cp = parse_cp(py, ext_data)?;
        Ok(Some(
            x509_module.call_method1("CertificatePolicies", (cp,))?,
        ))
    } else if oid == *POLICY_CONSTRAINTS_OID {
        let pc = asn1::parse_single::<PolicyConstraints>(ext_data)?;
        Ok(Some(x509_module.getattr("PolicyConstraints")?.call1((
            pc.require_explicit_policy,
            pc.inhibit_policy_mapping,
        ))?))
    } else if oid == *OCSP_NO_CHECK_OID {
        asn1::parse_single::<()>(ext_data)?;
        Ok(Some(x509_module.getattr("OCSPNoCheck")?.call0()?))
    } else if oid == *INHIBIT_ANY_POLICY_OID {
        let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
        let pynum = big_asn1_uint_to_py(py, bignum)?;
        Ok(Some(
            x509_module.getattr("InhibitAnyPolicy")?.call1((pynum,))?,
        ))
    } else if oid == *BASIC_CONSTRAINTS_OID {
        let bc = asn1::parse_single::<BasicConstraints>(ext_data)?;
        Ok(Some(
            x509_module
                .getattr("BasicConstraints")?
                .call1((bc.ca, bc.path_length))?,
        ))
    } else if oid == *AUTHORITY_KEY_IDENTIFIER_OID {
        Ok(Some(parse_authority_key_identifier(py, ext_data)?))
    } else if oid == *CRL_DISTRIBUTION_POINTS_OID {
        let dp = parse_distribution_points(py, ext_data)?;
        Ok(Some(
            x509_module.getattr("CRLDistributionPoints")?.call1((dp,))?,
        ))
    } else if oid == *FRESHEST_CRL_OID {
        let dp = parse_distribution_points(py, ext_data)?;
        Ok(Some(x509_module.getattr("FreshestCRL")?.call1((dp,))?))
    } else if oid == *NAME_CONSTRAINTS_OID {
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
                .getattr("NameConstraints")?
                .call1((permitted_subtrees, excluded_subtrees))?,
        ))
    } else {
        Ok(None)
    }
}

fn set_bit(vals: &mut [u8], n: usize, set: bool) {
    let idx = n / 8;
    let v = 1 << (7 - (n & 0x07));
    if set {
        vals[idx] |= v;
    }
}

#[pyo3::prelude::pyfunction]
fn encode_certificate_extension<'p>(
    py: pyo3::Python<'p>,
    ext: &pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let oid = asn1::ObjectIdentifier::from_string(
        ext.getattr("oid")?
            .getattr("dotted_string")?
            .extract::<&str>()?,
    )
    .unwrap();
    if oid == *BASIC_CONSTRAINTS_OID {
        let bc = BasicConstraints {
            ca: ext.getattr("value")?.getattr("ca")?.extract::<bool>()?,
            path_length: ext
                .getattr("value")?
                .getattr("path_length")?
                .extract::<Option<u64>>()?,
        };
        let result = asn1::write_single(&bc);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *SUBJECT_KEY_IDENTIFIER_OID {
        let result = asn1::write_single(
            &ext.getattr("value")?
                .getattr("digest")?
                .extract::<&[u8]>()?,
        );
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *KEY_USAGE_OID {
        let mut bs = [0, 0];
        set_bit(
            &mut bs,
            0,
            ext.getattr("value")?
                .getattr("digital_signature")?
                .is_true()?,
        );
        set_bit(
            &mut bs,
            1,
            ext.getattr("value")?
                .getattr("content_commitment")?
                .is_true()?,
        );
        set_bit(
            &mut bs,
            2,
            ext.getattr("value")?
                .getattr("key_encipherment")?
                .is_true()?,
        );
        set_bit(
            &mut bs,
            3,
            ext.getattr("value")?
                .getattr("data_encipherment")?
                .is_true()?,
        );
        set_bit(
            &mut bs,
            4,
            ext.getattr("value")?.getattr("key_agreement")?.is_true()?,
        );
        set_bit(
            &mut bs,
            5,
            ext.getattr("value")?.getattr("key_cert_sign")?.is_true()?,
        );
        set_bit(
            &mut bs,
            6,
            ext.getattr("value")?.getattr("crl_sign")?.is_true()?,
        );
        if ext.getattr("value")?.getattr("key_agreement")?.is_true()? {
            set_bit(
                &mut bs,
                7,
                ext.getattr("value")?.getattr("encipher_only")?.is_true()?,
            );
            set_bit(
                &mut bs,
                8,
                ext.getattr("value")?.getattr("decipher_only")?.is_true()?,
            );
        }
        let bits = if bs[1] == 0 { &bs[..1] } else { &bs[..] };
        let result = asn1::write_single(&asn1::BitString::new(bits, 0));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *AUTHORITY_INFORMATION_ACCESS_OID || oid == *SUBJECT_INFORMATION_ACCESS_OID {
        let py_ads = ext.getattr("value")?;
        let ads = x509::common::encode_access_descriptions(py, py_ads)?;
        let result = asn1::write_single(&ads);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *EXTENDED_KEY_USAGE_OID {
        let mut oids = vec![];
        for el in ext.getattr("value")?.iter()? {
            let oid = asn1::ObjectIdentifier::from_string(
                el?.getattr("dotted_string")?.extract::<&str>()?,
            )
            .unwrap();
            oids.push(oid);
        }
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(oids));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *CERTIFICATE_POLICIES_OID {
        let mut policy_informations = vec![];
        for py_policy_info in ext.getattr("value")?.iter()? {
            let py_policy_info = py_policy_info?;
            let py_policy_qualifiers = py_policy_info.getattr("policy_qualifiers")?;
            let qualifiers = if py_policy_qualifiers.is_true()? {
                let mut qualifiers = vec![];
                for py_qualifier in py_policy_qualifiers.iter()? {
                    let py_qualifier = py_qualifier?;
                    let qualifier = if py_qualifier.is_instance::<pyo3::types::PyString>()? {
                        let cps_uri = match asn1::IA5String::new(py_qualifier.extract()?) {
                            Some(s) => s,
                            None => {
                                return Err(pyo3::exceptions::PyValueError::new_err(
                                    "Qualifier must be an ASCII-string.",
                                ))
                            }
                        };
                        PolicyQualifierInfo {
                            policy_qualifier_id: (*CP_CPS_URI_OID).clone(),
                            qualifier: Qualifier::CpsUri(cps_uri),
                        }
                    } else {
                        let py_notice = py_qualifier.getattr("notice_reference")?;
                        let notice_ref = if py_notice.is_true()? {
                            let mut notice_numbers = vec![];
                            for py_num in py_notice.getattr("notice_numbers")?.iter()? {
                                let bytes = py_uint_to_big_endian_bytes(py, py_num?.downcast()?)?;
                                notice_numbers.push(asn1::BigUint::new(bytes).unwrap());
                            }

                            Some(NoticeReference {
                                organization: DisplayText::Utf8String(asn1::Utf8String::new(
                                    py_notice.getattr("organization")?.extract()?,
                                )),
                                notice_numbers: x509::Asn1ReadableOrWritable::new_write(
                                    asn1::SequenceOfWriter::new(notice_numbers),
                                ),
                            })
                        } else {
                            None
                        };
                        let py_explicit_text = py_qualifier.getattr("explicit_text")?;
                        let explicit_text = if py_explicit_text.is_true()? {
                            Some(DisplayText::Utf8String(asn1::Utf8String::new(
                                py_explicit_text.extract()?,
                            )))
                        } else {
                            None
                        };

                        PolicyQualifierInfo {
                            policy_qualifier_id: (*CP_USER_NOTICE_OID).clone(),
                            qualifier: Qualifier::UserNotice(UserNotice {
                                notice_ref,
                                explicit_text,
                            }),
                        }
                    };
                    qualifiers.push(qualifier);
                }
                Some(x509::Asn1ReadableOrWritable::new_write(
                    asn1::SequenceOfWriter::new(qualifiers),
                ))
            } else {
                None
            };
            policy_informations.push(PolicyInformation {
                policy_identifier: asn1::ObjectIdentifier::from_string(
                    py_policy_info
                        .getattr("policy_identifier")?
                        .getattr("dotted_string")?
                        .extract()?,
                )
                .unwrap(),
                policy_qualifiers: qualifiers,
            });
        }
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(policy_informations));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *POLICY_CONSTRAINTS_OID {
        let pc = PolicyConstraints {
            require_explicit_policy: ext
                .getattr("value")?
                .getattr("require_explicit_policy")?
                .extract()?,
            inhibit_policy_mapping: ext
                .getattr("value")?
                .getattr("inhibit_policy_mapping")?
                .extract()?,
        };
        let result = asn1::write_single(&pc);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *NAME_CONSTRAINTS_OID {
        let py_nc = ext.getattr("value")?;
        let permitted = py_nc.getattr("permitted_subtrees")?;
        let excluded = py_nc.getattr("excluded_subtrees")?;
        let nc = NameConstraints {
            permitted_subtrees: encode_general_subtrees(py, permitted)?,
            excluded_subtrees: encode_general_subtrees(py, excluded)?,
        };
        let result = asn1::write_single(&nc);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *INHIBIT_ANY_POLICY_OID {
        let intval = ext
            .getattr("value")?
            .getattr("skip_certs")?
            .downcast::<pyo3::types::PyLong>()?;
        let bytes = py_uint_to_big_endian_bytes(py, intval)?;
        let result = asn1::write_single(&asn1::BigUint::new(bytes).unwrap());
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID || oid == *SUBJECT_ALTERNATIVE_NAME_OID {
        let gns = x509::common::encode_general_names(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(gns));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *AUTHORITY_KEY_IDENTIFIER_OID {
        let aki = encode_authority_key_identifier(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&aki);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *FRESHEST_CRL_OID || oid == *CRL_DISTRIBUTION_POINTS_OID {
        let dps = encode_distribution_points(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(dps));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *OCSP_NO_CHECK_OID {
        let result = asn1::write_single(&());
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *TLS_FEATURE_OID {
        // Ideally we'd skip building up a vec and just write directly into the
        // writer. This isn't possible at the moment because the callback to write
        // an asn1::Sequence can't return an error, and we need to handle errors
        // from Python.
        let mut els = vec![];
        for el in ext.getattr("value")?.iter()? {
            els.push(el?.getattr("value")?.extract::<u64>()?);
        }

        let result = asn1::write_single(&asn1::SequenceOfWriter::new(els));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *PRECERT_POISON_OID {
        let result = asn1::write_single(&());
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID {
        let mut length = 0;
        for sct in ext.getattr("value")?.iter()? {
            let sct = sct?.downcast::<pyo3::PyCell<sct::Sct>>()?;
            length += sct.borrow().sct_data.len() + 2;
        }

        let mut result = vec![];
        result.extend_from_slice(&(length as u16).to_be_bytes());
        for sct in ext.getattr("value")?.iter()? {
            let sct = sct?.downcast::<pyo3::PyCell<sct::Sct>>()?;
            result.extend_from_slice(&(sct.borrow().sct_data.len() as u16).to_be_bytes());
            result.extend_from_slice(&sct.borrow().sct_data);
        }
        Ok(pyo3::types::PyBytes::new(
            py,
            &asn1::write_single(&result.as_slice()),
        ))
    } else {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
            "Extension not supported: {}",
            oid
        )))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_certificate))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_certificate))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(encode_certificate_extension))?;

    module.add_class::<Certificate>()?;

    Ok(())
}
