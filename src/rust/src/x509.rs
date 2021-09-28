// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, py_uint_to_big_endian_bytes, PyAsn1Error, PyAsn1Result};
use asn1::SimpleAsn1Readable;
use chrono::{Datelike, Timelike};
use pyo3::types::IntoPyDict;
use pyo3::ToPyObject;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();
    static ref AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1").unwrap();
    static ref SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.11").unwrap();

    static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    static ref POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.36").unwrap();
    static ref AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();
    static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    static ref ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.28").unwrap();
    static ref CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.29").unwrap();
    static ref NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.30").unwrap();
    static ref CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.31").unwrap();
    static ref CERTIFICATE_POLICIES_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.32").unwrap();
    static ref FRESHEST_CRL_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.46").unwrap();
    static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    static ref INVALIDITY_DATE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.24").unwrap();
    static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
    static ref SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap();
    static ref ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.18").unwrap();
    static ref PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.2").unwrap();

    static ref CP_CPS_URI_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.1").unwrap();
    static ref CP_USER_NOTICE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.2").unwrap();

    static ref MS_EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.311.2.1.14").unwrap();
    static ref EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.9.14").unwrap();
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
pub(crate) struct RawCertificate<'a> {
    tbs_cert: TbsCertificate<'a>,
    signature_alg: AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
struct TbsCertificate<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    serial: asn1::BigUint<'a>,
    _signature_alg: asn1::Sequence<'a>,

    issuer: Name<'a>,
    validity: Validity,
    subject: Name<'a>,

    spki: asn1::Sequence<'a>,
    #[implicit(1)]
    _issuer_unique_id: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    _subject_unique_id: Option<asn1::BitString<'a>>,
    #[explicit(3)]
    extensions: Option<Extensions<'a>>,
}

pub(crate) type Name<'a> = asn1::SequenceOf<'a, asn1::SetOf<'a, AttributeTypeValue<'a>>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub(crate) struct AttributeTypeValue<'a> {
    pub(crate) type_id: asn1::ObjectIdentifier<'a>,
    pub(crate) value: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
enum Time {
    UtcTime(asn1::UtcTime),
    GeneralizedTime(asn1::GeneralizedTime),
}

impl Time {
    fn as_chrono(&self) -> &chrono::DateTime<chrono::Utc> {
        match self {
            Time::UtcTime(data) => data.as_chrono(),
            Time::GeneralizedTime(data) => data.as_chrono(),
        }
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Hash, PartialEq)]
pub(crate) struct Validity {
    not_before: Time,
    not_after: Time,
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
        let mut repr = String::from("<Certificate(subject=<Name(");
        for rdn in self.raw.borrow_value().tbs_cert.subject.clone() {
            for attribute in rdn {
                let mut attr = attribute.type_id.to_string();
                attr.push('=');
                attr.push_str(std::str::from_utf8(attribute.value.data()).unwrap());
                repr.push_str(&attr);
                repr.push_str(", ");
            }
        }
        repr.push_str(")>, ...)>");
        Ok(repr)
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
        parse_name(py, &self.raw.borrow_value().tbs_cert.issuer)
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        parse_name(py, &self.raw.borrow_value().tbs_cert.subject)
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
        chrono_to_py(py, chrono)
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
        chrono_to_py(py, chrono)
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
        parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_cert.extensions,
            |oid, ext_data| {
                if oid == &*PRECERT_POISON_OID {
                    asn1::parse_single::<()>(ext_data)?;
                    Ok(Some(x509_module.getattr("PrecertPoison")?.call0()?))
                } else if oid == &*PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID {
                    let contents = asn1::parse_single::<&[u8]>(ext_data)?;
                    let scts = parse_scts(py, contents, LogEntryType::PreCertificate)?;
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
    let parsed = pem::parse(data)?;
    if parsed.tag != "CERTIFICATE" {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?"
        )));
    }
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

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RawCsr<'a> {
    csr_info: CertificationRequestInfo<'a>,
    signature_alg: AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct CertificationRequestInfo<'a> {
    version: u8,
    subject: Name<'a>,
    spki: asn1::Sequence<'a>,
    #[implicit(0, required)]
    attributes: asn1::SetOf<'a, Attribute<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Attribute<'a> {
    type_id: asn1::ObjectIdentifier<'a>,
    values: asn1::SetOf<'a, asn1::Tlv<'a>>,
}

fn check_attribute_length<'a>(values: asn1::SetOf<'a, asn1::Tlv<'a>>) -> Result<(), PyAsn1Error> {
    if values.count() > 1 {
        Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Only single-valued attributes are supported",
        )))
    } else {
        Ok(())
    }
}

impl CertificationRequestInfo<'_> {
    fn get_extension_attribute<'a>(&'a self) -> Result<Option<Extensions<'a>>, PyAsn1Error> {
        for attribute in self.attributes.clone() {
            if attribute.type_id == *EXTENSION_REQUEST || attribute.type_id == *MS_EXTENSION_REQUEST
            {
                check_attribute_length(attribute.values.clone())?;
                let val = attribute.values.clone().next().unwrap();
                let exts = asn1::parse_single::<Extensions<'a>>(val.full_data())?;
                return Ok(Some(exts));
            }
        }
        Ok(None)
    }
}

#[ouroboros::self_referencing]
struct OwnedRawCsr {
    data: Vec<u8>,
    #[borrows(data)]
    #[covariant]
    value: RawCsr<'this>,
}

#[pyo3::prelude::pyclass]
struct CertificateSigningRequest {
    raw: OwnedRawCsr,
    cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pyproto]
impl pyo3::basic::PyObjectProtocol for CertificateSigningRequest {
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_data().hash(&mut hasher);
        hasher.finish()
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<CertificateSigningRequest>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.raw.borrow_data() == other.raw.borrow_data()),
            pyo3::basic::CompareOp::Ne => Ok(self.raw.borrow_data() != other.raw.borrow_data()),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "CSRs cannot be ordered",
            )),
        }
    }
}

#[pyo3::prelude::pymethods]
impl CertificateSigningRequest {
    fn public_key<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized = pyo3::types::PyBytes::new(
            py,
            &asn1::write_single(&self.raw.borrow_value().csr_info.spki),
        );
        py.import("cryptography.hazmat.primitives.serialization")?
            .getattr("load_der_public_key")?
            .call1((serialized,))
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        parse_name(py, &self.raw.borrow_value().csr_info.subject)
    }

    #[getter]
    fn tbs_certrequest_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::types::PyBytes, PyAsn1Error> {
        let result = asn1::write_single(&self.raw.borrow_value().csr_info);
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
                    tag: "CERTIFICATE REQUEST".to_string(),
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

    fn get_attribute_for_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
        oid: &pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let oid_str = oid.getattr("dotted_string")?.extract::<&str>()?;
        let rust_oid = asn1::ObjectIdentifier::from_string(oid_str).unwrap();
        for attribute in self.raw.borrow_value().csr_info.attributes.clone() {
            if rust_oid == attribute.type_id {
                check_attribute_length(attribute.values.clone())?;
                let val = attribute.values.clone().next().unwrap();
                // We allow utf8string, printablestring, and ia5string at this time
                if val.tag() == asn1::Utf8String::TAG
                    || val.tag() == asn1::PrintableString::TAG
                    || val.tag() == asn1::IA5String::TAG
                {
                    return Ok(pyo3::types::PyBytes::new(py, val.data()));
                } else {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "OID {} has a disallowed ASN.1 type: {}",
                        oid,
                        val.tag()
                    )));
                }
            }
        }
        Err(pyo3::PyErr::from_instance(
            py.import("cryptography.x509")?.call_method1(
                "AttributeNotFound",
                (format!("No {} attribute was found", oid_str), oid),
            )?,
        ))
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let exts = self.raw.borrow_value().csr_info.get_extension_attribute()?;
        parse_and_cache_extensions(py, &mut self.cached_extensions, &exts, |oid, ext_data| {
            parse_cert_ext(py, oid.clone(), ext_data)
        })
    }

    #[getter]
    fn is_signature_valid<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let backend = py
            .import("cryptography.hazmat.backends.openssl.backend")?
            .getattr("backend")?;
        backend.call_method1("_csr_is_signature_valid", (slf,))
    }

    // This getter exists for compatibility with pyOpenSSL and will be removed.
    // DO NOT RELY ON IT. WE WILL BREAK YOU WHEN WE FEEL LIKE IT.
    #[getter]
    fn _x509_req<'p>(
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
        Ok(backend.call_method1("_csr2ossl", (slf,))?)
    }
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_csr(py: pyo3::Python<'_>, data: &[u8]) -> PyAsn1Result<CertificateSigningRequest> {
    let parsed = pem::parse(data)?;
    if parsed.tag != "CERTIFICATE REQUEST" {
        // TODO: The old errors had the following URL:
        // See https://cryptography.io/en/latest/faq.html#why-can-t-i-import-my-pem-file for more details.
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is a CSR?"
        )));
    }
    load_der_x509_csr(py, &parsed.contents)
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_csr(
    _py: pyo3::Python<'_>,
    data: &[u8],
) -> PyAsn1Result<CertificateSigningRequest> {
    let raw = OwnedRawCsr::try_new(data.to_vec(), |data| asn1::parse_single(data))?;
    Ok(CertificateSigningRequest {
        raw,
        cached_extensions: None,
    })
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_crl(
    _py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<CertificateRevocationList, PyAsn1Error> {
    let raw = OwnedRawCertificateRevocationList::try_new(
        Arc::from(data),
        |data| asn1::parse_single(data),
        |_| Ok(pyo3::once_cell::GILOnceCell::new()),
    )?;

    Ok(CertificateRevocationList {
        raw: Arc::new(raw),
        cached_extensions: None,
    })
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_crl(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<CertificateRevocationList, PyAsn1Error> {
    let block = pem::parse(data)?;
    if block.tag != "X509 CRL" {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Valid PEM but no BEGIN X509 CRL/END X509 delimiters. Are you sure this is a CRL?",
        )));
    }
    // TODO: Produces an extra copy
    load_der_x509_crl(py, &block.contents)
}

#[ouroboros::self_referencing]
struct OwnedRawCertificateRevocationList {
    data: Arc<[u8]>,
    #[borrows(data)]
    #[covariant]
    value: RawCertificateRevocationList<'this>,
    #[borrows(data)]
    #[not_covariant]
    revoked_certs: pyo3::once_cell::GILOnceCell<Vec<RawRevokedCertificate<'this>>>,
}

#[pyo3::prelude::pyclass]
struct CertificateRevocationList {
    raw: Arc<OwnedRawCertificateRevocationList>,

    cached_extensions: Option<pyo3::PyObject>,
}

impl CertificateRevocationList {
    fn public_bytes_der(&self) -> Vec<u8> {
        asn1::write_single(self.raw.borrow_value())
    }

    fn revoked_cert(&self, py: pyo3::Python<'_>, idx: usize) -> pyo3::PyResult<RevokedCertificate> {
        let raw = try_map_arc_data_crl(&self.raw, |_crl, revoked_certs| {
            let revoked_certs = revoked_certs.get(py).unwrap();
            Ok::<_, pyo3::PyErr>(revoked_certs[idx].clone())
        })?;
        Ok(RevokedCertificate {
            raw,
            cached_extensions: None,
        })
    }

    fn len(&self) -> usize {
        self.raw
            .borrow_value()
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .map_or(0, |v| v.len())
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyObjectProtocol for CertificateRevocationList {
    fn __richcmp__(
        &self,
        other: pyo3::PyRef<CertificateRevocationList>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.raw.borrow_value() == other.raw.borrow_value()),
            pyo3::basic::CompareOp::Ne => Ok(self.raw.borrow_value() != other.raw.borrow_value()),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "CRLs cannot be ordered",
            )),
        }
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyMappingProtocol for CertificateRevocationList {
    fn __len__(&self) -> usize {
        self.len()
    }

    fn __getitem__(&self, idx: &pyo3::PyAny) -> pyo3::PyResult<pyo3::PyObject> {
        let gil = pyo3::Python::acquire_gil();
        let py = gil.python();

        self.raw.with(|val| {
            val.revoked_certs.get_or_init(py, || {
                match &val.value.tbs_cert_list.revoked_certificates {
                    Some(c) => c.clone().collect(),
                    None => vec![],
                }
            });
        });

        if idx.is_instance::<pyo3::types::PySlice>()? {
            let indices = idx
                .downcast::<pyo3::types::PySlice>()?
                .indices(self.len().try_into().unwrap())?;
            let result = pyo3::types::PyList::empty(py);
            for i in (indices.start..indices.stop).step_by(indices.step.try_into().unwrap()) {
                let revoked_cert = pyo3::PyCell::new(py, self.revoked_cert(py, i as usize)?)?;
                result.append(revoked_cert)?;
            }
            Ok(result.to_object(py))
        } else {
            let mut idx = idx.extract::<isize>()?;
            if idx < 0 {
                idx += self.len() as isize;
            }
            if idx >= (self.len() as isize) || idx < 0 {
                return Err(pyo3::exceptions::PyIndexError::new_err(()));
            }
            Ok(pyo3::PyCell::new(py, self.revoked_cert(py, idx as usize)?)?.to_object(py))
        }
    }
}

#[pyo3::prelude::pymethods]
impl CertificateRevocationList {
    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::PyObject,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let hashes_mod = py.import("cryptography.hazmat.primitives.hashes")?;
        let h = hashes_mod.getattr("Hash")?.call1((algorithm,))?;
        h.call_method1("update", (self.public_bytes_der().as_slice(),))?;
        h.call_method0("finalize")
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let x509_module = py.import("cryptography.x509")?;
        x509_module.call_method1(
            "ObjectIdentifier",
            (self.raw.borrow_value().signature_algorithm.oid.to_string(),),
        )
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let oid = self.signature_algorithm_oid(py)?;
        let oid_module = py.import("cryptography.hazmat._oid")?;
        let exceptions_module = py.import("cryptography.exceptions")?;
        match oid_module.getattr("_SIG_OIDS_TO_HASH")?.get_item(oid) {
            Ok(v) => Ok(v),
            Err(_) => Err(pyo3::PyErr::from_instance(exceptions_module.call_method1(
                "UnsupportedAlgorithm",
                (format!(
                    "Signature algorithm OID:{} not recognized",
                    self.raw.borrow_value().signature_algorithm.oid
                ),),
            )?)),
        }
    }

    #[getter]
    fn signature(&self) -> &[u8] {
        self.raw.borrow_value().signature_value.as_bytes()
    }

    #[getter]
    fn tbs_certlist_bytes<'p>(&self, py: pyo3::Python<'p>) -> &'p pyo3::types::PyBytes {
        let b = asn1::write_single(&self.raw.borrow_value().tbs_cert_list);
        pyo3::types::PyBytes::new(py, &b)
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
                    tag: "X509 CRL".to_string(),
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
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        parse_name(py, &self.raw.borrow_value().tbs_cert_list.issuer)
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        match &self.raw.borrow_value().tbs_cert_list.next_update {
            Some(t) => chrono_to_py(py, t.as_chrono()),
            None => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn last_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        chrono_to_py(
            py,
            self.raw
                .borrow_value()
                .tbs_cert_list
                .this_update
                .as_chrono(),
        )
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import("cryptography.x509")?;
        parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_cert_list.crl_extensions,
            |oid, ext_data| {
                if oid == &*CRL_NUMBER_OID {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_asn1_uint_to_py(py, bignum)?;
                    Ok(Some(x509_module.getattr("CRLNumber")?.call1((pynum,))?))
                } else if oid == &*DELTA_CRL_INDICATOR_OID {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_asn1_uint_to_py(py, bignum)?;
                    Ok(Some(
                        x509_module.getattr("DeltaCRLIndicator")?.call1((pynum,))?,
                    ))
                } else if oid == &*ISSUER_ALTERNATIVE_NAME_OID {
                    let gn_seq =
                        asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
                    let ians = parse_general_names(py, gn_seq)?;
                    Ok(Some(
                        x509_module
                            .getattr("IssuerAlternativeName")?
                            .call1((ians,))?,
                    ))
                } else if oid == &*AUTHORITY_INFORMATION_ACCESS_OID {
                    let ads = parse_access_descriptions(py, ext_data)?;
                    Ok(Some(
                        x509_module
                            .getattr("AuthorityInformationAccess")?
                            .call1((ads,))?,
                    ))
                } else if oid == &*AUTHORITY_KEY_IDENTIFIER_OID {
                    Ok(Some(parse_authority_key_identifier(py, ext_data)?))
                } else if oid == &*ISSUING_DISTRIBUTION_POINT_OID {
                    let idp = asn1::parse_single::<IssuingDistributionPoint<'_>>(ext_data)?;
                    let (full_name, relative_name) = match idp.distribution_point {
                        Some(data) => parse_distribution_point_name(py, data)?,
                        None => (py.None(), py.None()),
                    };
                    let reasons = parse_distribution_point_reasons(py, idp.only_some_reasons)?;
                    Ok(Some(
                        x509_module.getattr("IssuingDistributionPoint")?.call1((
                            full_name,
                            relative_name,
                            idp.only_contains_user_certs,
                            idp.only_contains_ca_certs,
                            reasons,
                            idp.indirect_crl,
                            idp.only_contains_attribute_certs,
                        ))?,
                    ))
                } else if oid == &*FRESHEST_CRL_OID {
                    Ok(Some(
                        x509_module
                            .getattr("FreshestCRL")?
                            .call1((parse_distribution_points(py, ext_data)?,))?,
                    ))
                } else {
                    Ok(None)
                }
            },
        )
    }

    fn get_revoked_certificate_by_serial_number(
        &mut self,
        py: pyo3::Python<'_>,
        serial: &pyo3::types::PyLong,
    ) -> pyo3::PyResult<Option<RevokedCertificate>> {
        let serial_bytes = py_uint_to_big_endian_bytes(py, serial)?;
        let owned = OwnedRawRevokedCertificate::try_new(Arc::clone(&self.raw), |v| {
            let certs = match v.borrow_value().tbs_cert_list.revoked_certificates.clone() {
                Some(certs) => certs,
                None => return Err(()),
            };

            // TODO: linear scan. Make a hash or bisect!
            for cert in certs {
                if serial_bytes == cert.user_certificate.as_bytes() {
                    return Ok(cert);
                }
            }
            Err(())
        });
        match owned {
            Ok(o) => Ok(Some(RevokedCertificate {
                raw: o,
                cached_extensions: None,
            })),
            Err(()) => Ok(None),
        }
    }

    fn is_signature_valid<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
        public_key: &'p pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let backend = py
            .import("cryptography.hazmat.backends.openssl.backend")?
            .getattr("backend")?;
        backend.call_method1("_crl_is_signature_valid", (slf, public_key))
    }

    // This getter exists for compatibility with pyOpenSSL and will be removed.
    // DO NOT RELY ON IT. WE WILL BREAK YOU WHEN WE FEEL LIKE IT.
    #[getter]
    fn _x509_crl<'p>(
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
        Ok(backend.call_method1("_crl2ossl", (slf,))?)
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyIterProtocol<'_> for CertificateRevocationList {
    fn __iter__(slf: pyo3::PyRef<'p, Self>) -> CRLIterator {
        CRLIterator {
            contents: OwnedCRLIteratorData::try_new(Arc::clone(&slf.raw), |v| {
                Ok::<_, ()>(v.borrow_value().tbs_cert_list.revoked_certificates.clone())
            })
            .unwrap(),
        }
    }
}

#[ouroboros::self_referencing]
struct OwnedCRLIteratorData {
    data: Arc<OwnedRawCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: Option<asn1::SequenceOf<'this, RawRevokedCertificate<'this>>>,
}

#[pyo3::prelude::pyclass]
struct CRLIterator {
    contents: OwnedCRLIteratorData,
}

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn try_map_arc_data_crl<E>(
    crl: &Arc<OwnedRawCertificateRevocationList>,
    f: impl for<'this> FnOnce(
        &'this OwnedRawCertificateRevocationList,
        &pyo3::once_cell::GILOnceCell<Vec<RawRevokedCertificate<'this>>>,
    ) -> Result<RawRevokedCertificate<'this>, E>,
) -> Result<OwnedRawRevokedCertificate, E> {
    OwnedRawRevokedCertificate::try_new(Arc::clone(crl), |inner_crl| {
        crl.with(|value| {
            f(inner_crl, unsafe {
                std::mem::transmute(value.revoked_certs)
            })
        })
    })
}
fn try_map_arc_data_mut_crl_iterator<E>(
    it: &mut OwnedCRLIteratorData,
    f: impl for<'this> FnOnce(
        &'this OwnedRawCertificateRevocationList,
        &mut Option<asn1::SequenceOf<'this, RawRevokedCertificate<'this>>>,
    ) -> Result<RawRevokedCertificate<'this>, E>,
) -> Result<OwnedRawRevokedCertificate, E> {
    OwnedRawRevokedCertificate::try_new(Arc::clone(it.borrow_data()), |inner_it| {
        it.with_value_mut(|value| f(inner_it, unsafe { std::mem::transmute(value) }))
    })
}

#[pyo3::prelude::pyproto]
impl pyo3::PyIterProtocol<'_> for CRLIterator {
    fn __iter__(slf: pyo3::PyRef<'p, Self>) -> pyo3::PyRef<'p, Self> {
        slf
    }

    fn __next__(mut slf: pyo3::PyRefMut<'p, Self>) -> Option<RevokedCertificate> {
        let revoked = try_map_arc_data_mut_crl_iterator(&mut slf.contents, |_data, v| match v {
            Some(v) => match v.next() {
                Some(revoked) => Ok(revoked),
                None => Err(()),
            },
            None => Err(()),
        })
        .ok()?;
        Some(RevokedCertificate {
            raw: revoked,
            cached_extensions: None,
        })
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PySequenceProtocol<'_> for CRLIterator {
    fn __len__(&self) -> usize {
        self.contents.borrow_value().clone().map_or(0, |v| v.len())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
struct RawCertificateRevocationList<'a> {
    tbs_cert_list: TBSCertList<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature_value: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
struct TBSCertList<'a> {
    version: Option<u8>,
    signature: AlgorithmIdentifier<'a>,
    issuer: Name<'a>,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certificates: Option<asn1::SequenceOf<'a, RawRevokedCertificate<'a>>>,
    #[explicit(0)]
    crl_extensions: Option<Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
struct RawRevokedCertificate<'a> {
    user_certificate: asn1::BigUint<'a>,
    revocation_date: Time,
    crl_entry_extensions: Option<Extensions<'a>>,
}

#[ouroboros::self_referencing]
struct OwnedRawRevokedCertificate {
    data: Arc<OwnedRawCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: RawRevokedCertificate<'this>,
}

#[pyo3::prelude::pyclass]
struct RevokedCertificate {
    raw: OwnedRawRevokedCertificate,
    cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pymethods]
impl RevokedCertificate {
    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        big_asn1_uint_to_py(py, self.raw.borrow_value().user_certificate)
    }

    #[getter]
    fn revocation_date<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        chrono_to_py(py, self.raw.borrow_value().revocation_date.as_chrono())
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().crl_entry_extensions,
            |oid, ext_data| parse_crl_entry_ext(py, oid.clone(), ext_data),
        )
    }
}

pub(crate) fn parse_and_cache_extensions<
    'p,
    F: Fn(&asn1::ObjectIdentifier<'_>, &[u8]) -> Result<Option<&'p pyo3::PyAny>, PyAsn1Error>,
>(
    py: pyo3::Python<'p>,
    cached_extensions: &mut Option<pyo3::PyObject>,
    raw_exts: &Option<Extensions<'_>>,
    parse_ext: F,
) -> pyo3::PyResult<pyo3::PyObject> {
    if let Some(cached) = cached_extensions {
        return Ok(cached.clone_ref(py));
    }

    let x509_module = py.import("cryptography.x509")?;
    let exts = pyo3::types::PyList::empty(py);
    let mut seen_oids = HashSet::new();
    if let Some(raw_exts) = raw_exts {
        for raw_ext in raw_exts.clone() {
            let oid_obj =
                x509_module.call_method1("ObjectIdentifier", (raw_ext.extn_id.to_string(),))?;

            if seen_oids.contains(&raw_ext.extn_id) {
                return Err(pyo3::PyErr::from_instance(x509_module.call_method1(
                    "DuplicateExtension",
                    (
                        format!("Duplicate {} extension found", raw_ext.extn_id),
                        oid_obj,
                    ),
                )?));
            }

            let extn_value = match parse_ext(&raw_ext.extn_id, raw_ext.extn_value)? {
                Some(e) => e,
                None => x509_module
                    .call_method1("UnrecognizedExtension", (oid_obj, raw_ext.extn_value))?,
            };
            let ext_obj =
                x509_module.call_method1("Extension", (oid_obj, raw_ext.critical, extn_value))?;
            exts.append(ext_obj)?;
            seen_oids.insert(raw_ext.extn_id);
        }
    }
    let extensions = x509_module
        .call_method1("Extensions", (exts,))?
        .to_object(py);
    *cached_extensions = Some(extensions.clone_ref(py));
    Ok(extensions)
}

pub(crate) type Extensions<'a> = asn1::SequenceOf<'a, Extension<'a>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub(crate) struct AlgorithmIdentifier<'a> {
    pub(crate) oid: asn1::ObjectIdentifier<'a>,
    pub(crate) _params: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub(crate) struct Extension<'a> {
    pub(crate) extn_id: asn1::ObjectIdentifier<'a>,
    #[default(false)]
    pub(crate) critical: bool,
    pub(crate) extn_value: &'a [u8],
}

#[derive(asn1::Asn1Read)]
struct PolicyInformation<'a> {
    policy_identifier: asn1::ObjectIdentifier<'a>,
    policy_qualifiers: Option<asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct PolicyQualifierInfo<'a> {
    policy_qualifier_id: asn1::ObjectIdentifier<'a>,
    qualifier: Qualifier<'a>,
}

#[derive(asn1::Asn1Read)]
enum Qualifier<'a> {
    CpsUri(asn1::IA5String<'a>),
    UserNotice(UserNotice<'a>),
}

#[derive(asn1::Asn1Read)]
struct UserNotice<'a> {
    notice_ref: Option<NoticeReference<'a>>,
    explicit_text: Option<DisplayText<'a>>,
}

#[derive(asn1::Asn1Read)]
struct NoticeReference<'a> {
    organization: DisplayText<'a>,
    notice_numbers: asn1::SequenceOf<'a, asn1::BigUint<'a>>,
}

// DisplayText also allows BMPString, which we currently do not support.
#[allow(clippy::enum_variant_names)]
#[derive(asn1::Asn1Read)]
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
            for num in data.notice_numbers {
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
    policy_qualifiers: asn1::SequenceOf<'a, PolicyQualifierInfo<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let py_pq = pyo3::types::PyList::empty(py);
    for pqi in policy_qualifiers {
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
            Some(policy_qualifiers) => parse_policy_qualifiers(py, policy_qualifiers)?,
            None => py.None(),
        };
        let pi = x509_module
            .call_method1("PolicyInformation", (pi_oid, py_pqis))?
            .to_object(py);
        certificate_policies.append(pi)?;
    }
    Ok(certificate_policies.to_object(py))
}

pub(crate) fn chrono_to_py<'p>(
    py: pyo3::Python<'p>,
    dt: &chrono::DateTime<chrono::Utc>,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let datetime_module = py.import("datetime")?;
    datetime_module.getattr("datetime")?.call1((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    ))
}

struct UnvalidatedIA5String<'a>(&'a str);

impl<'a> asn1::SimpleAsn1Readable<'a> for UnvalidatedIA5String<'a> {
    const TAG: u8 = 0x16;
    fn parse_data(data: &'a [u8]) -> asn1::ParseResult<Self> {
        Ok(UnvalidatedIA5String(std::str::from_utf8(data).map_err(
            |_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue),
        )?))
    }
}

#[derive(asn1::Asn1Read)]
struct NameConstraints<'a> {
    #[implicit(0)]
    permitted_subtrees: Option<asn1::SequenceOf<'a, GeneralSubtree<'a>>>,

    #[implicit(1)]
    excluded_subtrees: Option<asn1::SequenceOf<'a, GeneralSubtree<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct GeneralSubtree<'a> {
    base: GeneralName<'a>,

    #[implicit(0)]
    #[default(0u64)]
    _minimum: u64,

    #[implicit(1)]
    _maximum: Option<u64>,
}

fn parse_general_subtrees<'a>(
    py: pyo3::Python<'_>,
    subtrees: asn1::SequenceOf<'a, GeneralSubtree<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gs in subtrees {
        gns.append(parse_general_name(py, gs.base)?)?;
    }
    Ok(gns.to_object(py))
}

#[derive(asn1::Asn1Read)]
struct IssuingDistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    #[default(false)]
    only_contains_user_certs: bool,

    #[implicit(2)]
    #[default(false)]
    only_contains_ca_certs: bool,

    #[implicit(3)]
    only_some_reasons: Option<asn1::BitString<'a>>,

    #[implicit(4)]
    #[default(false)]
    indirect_crl: bool,

    #[implicit(5)]
    #[default(false)]
    only_contains_attribute_certs: bool,
}

#[derive(asn1::Asn1Read)]
struct DistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<DistributionPointName<'a>>,

    #[implicit(1)]
    reasons: Option<asn1::BitString<'a>>,

    #[implicit(2)]
    crl_issuer: Option<asn1::SequenceOf<'a, GeneralName<'a>>>,
}

#[derive(asn1::Asn1Read)]
enum DistributionPointName<'a> {
    #[implicit(0)]
    FullName(asn1::SequenceOf<'a, GeneralName<'a>>),

    #[implicit(1)]
    NameRelativeToCRLIssuer(asn1::SetOf<'a, AttributeTypeValue<'a>>),
}

#[derive(asn1::Asn1Read)]
struct AuthorityKeyIdentifier<'a> {
    #[implicit(0)]
    key_identifier: Option<&'a [u8]>,
    #[implicit(1)]
    authority_cert_issuer: Option<asn1::SequenceOf<'a, GeneralName<'a>>>,
    #[implicit(2)]
    authority_cert_serial_number: Option<asn1::BigUint<'a>>,
}

fn parse_distribution_point_name(
    py: pyo3::Python<'_>,
    dp: DistributionPointName<'_>,
) -> Result<(pyo3::PyObject, pyo3::PyObject), PyAsn1Error> {
    Ok(match dp {
        DistributionPointName::FullName(data) => (parse_general_names(py, data)?, py.None()),
        DistributionPointName::NameRelativeToCRLIssuer(data) => (py.None(), parse_rdn(py, data)?),
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
    let reasons = parse_distribution_point_reasons(py, dp.reasons)?;
    let crl_issuer = match dp.crl_issuer {
        Some(aci) => parse_general_names(py, aci)?,
        None => py.None(),
    };
    let x509_module = py.import("cryptography.x509")?;
    Ok(x509_module
        .getattr("DistributionPoint")?
        .call1((full_name, relative_name, reasons, crl_issuer))?
        .to_object(py))
}

fn parse_distribution_points(
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

fn parse_distribution_point_reasons(
    py: pyo3::Python<'_>,
    reasons: Option<asn1::BitString<'_>>,
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

#[derive(asn1::Asn1Read)]
enum GeneralName<'a> {
    #[implicit(0)]
    OtherName(AttributeTypeValue<'a>),

    #[implicit(1)]
    RFC822Name(UnvalidatedIA5String<'a>),

    #[implicit(2)]
    DNSName(UnvalidatedIA5String<'a>),

    #[implicit(3)]
    // unsupported
    X400Address(asn1::Sequence<'a>),

    // Name is explicit per RFC 5280 Appendix A.1.
    #[explicit(4)]
    DirectoryName(Name<'a>),

    #[implicit(5)]
    // unsupported
    EDIPartyName(asn1::Sequence<'a>),

    #[implicit(6)]
    UniformResourceIdentifier(UnvalidatedIA5String<'a>),

    #[implicit(7)]
    IPAddress(&'a [u8]),

    #[implicit(8)]
    RegisteredID(asn1::ObjectIdentifier<'a>),
}

#[derive(asn1::Asn1Read)]
struct BasicConstraints {
    #[default(false)]
    ca: bool,
    path_length: Option<u64>,
}

#[derive(asn1::Asn1Read)]
struct PolicyConstraints {
    #[implicit(0)]
    require_explicit_policy: Option<u64>,
    #[implicit(1)]
    inhibit_policy_mapping: Option<u64>,
}

#[derive(asn1::Asn1Read)]
struct AccessDescription<'a> {
    access_method: asn1::ObjectIdentifier<'a>,
    access_location: GeneralName<'a>,
}

fn parse_authority_key_identifier<'p>(
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
        Some(aci) => parse_general_names(py, aci)?,
        None => py.None(),
    };
    Ok(x509_module.getattr("AuthorityKeyIdentifier")?.call1((
        aki.key_identifier,
        issuer,
        serial,
    ))?)
}

fn parse_name_attribute(
    py: pyo3::Python<'_>,
    attribute: AttributeTypeValue<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let oid = x509_module
        .call_method1("ObjectIdentifier", (attribute.type_id.to_string(),))?
        .to_object(py);
    let tag_enum = py
        .import("cryptography.x509.name")?
        .getattr("_ASN1_TYPE_TO_ENUM")?;
    let py_tag = tag_enum.get_item(attribute.value.tag().to_object(py))?;
    let py_data = std::str::from_utf8(attribute.value.data())
        .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?;
    Ok(x509_module
        .call_method1("NameAttribute", (oid, py_data, py_tag))?
        .to_object(py))
}

fn parse_rdn<'a>(
    py: pyo3::Python<'_>,
    rdn: asn1::SetOf<'a, AttributeTypeValue<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_attrs = pyo3::types::PySet::empty(py)?;
    for attribute in rdn {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.add(na)?;
    }
    Ok(x509_module
        .call_method1("RelativeDistinguishedName", (py_attrs,))?
        .to_object(py))
}

pub(crate) fn parse_name<'p>(
    py: pyo3::Python<'p>,
    name: &Name<'_>,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let x509_module = py.import("cryptography.x509")?;
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name.clone() {
        let py_rdn = parse_rdn(py, rdn)?;
        py_rdns.append(py_rdn)?;
    }
    x509_module.call_method1("Name", (py_rdns,))
}

fn ipv4_netmask(num: u32) -> Result<u32, PyAsn1Error> {
    // we invert and check leading zeros because leading_ones wasn't stabilized
    // until 1.46.0. When we raise our MSRV we should change this
    if (!num).leading_zeros() + num.trailing_zeros() != 32 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask",
        )));
    }
    Ok((!num).leading_zeros())
}

fn ipv6_netmask(num: u128) -> Result<u32, PyAsn1Error> {
    // we invert and check leading zeros because leading_ones wasn't stabilized
    // until 1.46.0. When we raise our MSRV we should change this
    if (!num).leading_zeros() + num.trailing_zeros() != 128 {
        return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            "Invalid netmask",
        )));
    }
    Ok((!num).leading_zeros())
}

fn create_ip_network(py: pyo3::Python<'_>, data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let ip_module = py.import("ipaddress")?;
    let x509_module = py.import("cryptography.x509")?;
    let prefix = match data.len() {
        8 => {
            let num = u32::from_be_bytes(data[4..].try_into().unwrap());
            ipv4_netmask(num)
        }
        32 => {
            let num = u128::from_be_bytes(data[16..].try_into().unwrap());
            ipv6_netmask(num)
        }
        _ => Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
            format!("Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6. Found length: {}", data.len()),
        ))),
    };
    let base = ip_module.call_method1(
        "ip_address",
        (pyo3::types::PyBytes::new(py, &data[..data.len() / 2]),),
    )?;
    let net = format!(
        "{}/{}",
        base.getattr("exploded")?.extract::<&str>()?,
        prefix?
    );
    let addr = ip_module.call_method1("ip_network", (net,))?.to_object(py);
    Ok(x509_module
        .call_method1("IPAddress", (addr,))?
        .to_object(py))
}

fn parse_general_name(
    py: pyo3::Python<'_>,
    gn: GeneralName<'_>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let py_gn = match gn {
        GeneralName::OtherName(data) => {
            let oid = x509_module
                .call_method1("ObjectIdentifier", (data.type_id.to_string(),))?
                .to_object(py);
            x509_module
                .call_method1("OtherName", (oid, data.value.data()))?
                .to_object(py)
        }
        GeneralName::RFC822Name(data) => x509_module
            .getattr("RFC822Name")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::DNSName(data) => x509_module
            .getattr("DNSName")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::DirectoryName(data) => {
            let py_name = parse_name(py, &data)?;
            x509_module
                .call_method1("DirectoryName", (py_name,))?
                .to_object(py)
        }
        GeneralName::UniformResourceIdentifier(data) => x509_module
            .getattr("UniformResourceIdentifier")?
            .call_method1("_init_without_validation", (data.0,))?
            .to_object(py),
        GeneralName::IPAddress(data) => {
            let ip_module = py.import("ipaddress")?;
            if data.len() == 4 || data.len() == 16 {
                let addr = ip_module.call_method1("ip_address", (data,))?.to_object(py);
                x509_module
                    .call_method1("IPAddress", (addr,))?
                    .to_object(py)
            } else {
                // if it's not an IPv4 or IPv6 we assume it's an IPNetwork and
                // verify length in this function.
                create_ip_network(py, data)?
            }
        }
        GeneralName::RegisteredID(data) => {
            let oid = x509_module
                .call_method1("ObjectIdentifier", (data.to_string(),))?
                .to_object(py);
            x509_module
                .call_method1("RegisteredID", (oid,))?
                .to_object(py)
        }
        _ => {
            return Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                x509_module.call_method1(
                    "UnsupportedGeneralNameType",
                    ("x400Address/EDIPartyName are not supported types",),
                )?,
            )))
        }
    };
    Ok(py_gn)
}

fn parse_general_names<'a>(
    py: pyo3::Python<'_>,
    gn_seq: asn1::SequenceOf<'a, GeneralName<'a>>,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in gn_seq {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.to_object(py))
}

fn parse_access_descriptions(
    py: pyo3::Python<'_>,
    ext_data: &[u8],
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let x509_module = py.import("cryptography.x509")?;
    let ads = pyo3::types::PyList::empty(py);
    for access in asn1::parse_single::<asn1::SequenceOf<'_, AccessDescription<'_>>>(ext_data)? {
        let py_oid = x509_module
            .call_method1("ObjectIdentifier", (access.access_method.to_string(),))?
            .to_object(py);
        let gn = parse_general_name(py, access.access_location)?;
        let ad = x509_module
            .getattr("AccessDescription")?
            .call1((py_oid, gn))?
            .to_object(py);
        ads.append(ad)?;
    }
    Ok(ads.to_object(py))
}

struct TLSReader<'a> {
    data: &'a [u8],
}

impl<'a> TLSReader<'a> {
    fn new(data: &'a [u8]) -> TLSReader<'a> {
        TLSReader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn read_byte(&mut self) -> Result<u8, PyAsn1Error> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PyAsn1Error> {
        if length > self.data.len() {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT length",
            )));
        }
        let (result, data) = self.data.split_at(length);
        self.data = data;
        Ok(result)
    }

    fn read_length_prefixed(&mut self) -> Result<TLSReader<'a>, PyAsn1Error> {
        let length = u16::from_be_bytes(self.read_exact(2)?.try_into().unwrap());
        Ok(TLSReader::new(self.read_exact(length.into())?))
    }
}

#[derive(Clone)]
pub(crate) enum LogEntryType {
    Certificate,
    PreCertificate,
}

#[pyo3::prelude::pyclass]
struct Sct {
    log_id: [u8; 32],
    timestamp: u64,
    entry_type: LogEntryType,
    sct_data: Vec<u8>,
}

#[pyo3::prelude::pymethods]
impl Sct {
    #[getter]
    fn version<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        py.import("cryptography.x509.certificate_transparency")?
            .getattr("Version")?
            .getattr("v1")
    }

    #[getter]
    fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    #[getter]
    fn timestamp<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let datetime_class = py.import("datetime")?.getattr("datetime")?;
        datetime_class
            .call_method1("utcfromtimestamp", (self.timestamp / 1000,))?
            .call_method(
                "replace",
                (),
                Some(vec![("microsecond", self.timestamp % 1000 * 1000)].into_py_dict(py)),
            )
    }

    #[getter]
    fn entry_type<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let et_class = py
            .import("cryptography.x509.certificate_transparency")?
            .getattr("LogEntryType")?;
        let attr_name = match self.entry_type {
            LogEntryType::Certificate => "X509_CERTIFICATE",
            LogEntryType::PreCertificate => "PRE_CERTIFICATE",
        };
        et_class.getattr(attr_name)
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyObjectProtocol for Sct {
    fn __richcmp__(
        &self,
        other: pyo3::PyRef<Sct>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.sct_data == other.sct_data),
            pyo3::basic::CompareOp::Ne => Ok(self.sct_data != other.sct_data),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "SCTs cannot be ordered",
            )),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.sct_data.hash(&mut hasher);
        hasher.finish()
    }
}

#[pyo3::prelude::pyfunction]
fn encode_precertificate_signed_certificate_timestamps(
    py: pyo3::Python<'_>,
    extension: &pyo3::PyAny,
) -> pyo3::PyResult<pyo3::PyObject> {
    let mut length = 0;
    for sct in extension.iter()? {
        let sct = sct?.downcast::<pyo3::PyCell<Sct>>()?;
        length += sct.borrow().sct_data.len() + 2;
    }

    let mut result = vec![];
    result.extend_from_slice(&(length as u16).to_be_bytes());
    for sct in extension.iter()? {
        let sct = sct?.downcast::<pyo3::PyCell<Sct>>()?;
        result.extend_from_slice(&(sct.borrow().sct_data.len() as u16).to_be_bytes());
        result.extend_from_slice(&sct.borrow().sct_data);
    }
    Ok(pyo3::types::PyBytes::new(py, &asn1::write_single(&result.as_slice())).to_object(py))
}

pub(crate) fn parse_scts(
    py: pyo3::Python<'_>,
    data: &[u8],
    entry_type: LogEntryType,
) -> Result<pyo3::PyObject, PyAsn1Error> {
    let mut reader = TLSReader::new(data).read_length_prefixed()?;

    let py_scts = pyo3::types::PyList::empty(py);
    while !reader.is_empty() {
        let mut sct_data = reader.read_length_prefixed()?;
        let raw_sct_data = sct_data.data.to_vec();
        let version = sct_data.read_byte()?;
        if version != 0 {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Invalid SCT version",
            )));
        }
        let log_id = sct_data.read_exact(32)?.try_into().unwrap();
        let timestamp = u64::from_be_bytes(sct_data.read_exact(8)?.try_into().unwrap());
        let _extensions = sct_data.read_length_prefixed()?;
        let _sig_alg = sct_data.read_exact(2)?;
        let _signature = sct_data.read_length_prefixed()?;

        let sct = Sct {
            log_id,
            timestamp,
            entry_type: entry_type.clone(),
            sct_data: raw_sct_data,
        };
        py_scts.append(pyo3::PyCell::new(py, sct)?)?;
    }
    Ok(py_scts.to_object(py))
}

pub(crate) type CRLReason = asn1::Enumerated;

pub(crate) fn parse_crl_reason_flags<'p>(
    py: pyo3::Python<'p>,
    reason: &CRLReason,
) -> PyAsn1Result<&'p pyo3::PyAny> {
    let x509_module = py.import("cryptography.x509")?;
    let flag_name = match reason.value() {
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
    Ok(x509_module.getattr("ReasonFlags")?.getattr(flag_name)?)
}

pub fn parse_crl_entry_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier<'_>,
    data: &[u8],
) -> PyAsn1Result<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_REASON_OID {
        let flags = parse_crl_reason_flags(py, &asn1::parse_single::<CRLReason>(data)?)?;
        Ok(Some(x509_module.getattr("CRLReason")?.call1((flags,))?))
    } else if oid == *CERTIFICATE_ISSUER_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(data)?;
        let gns = parse_general_names(py, gn_seq)?;
        Ok(Some(
            x509_module.getattr("CertificateIssuer")?.call1((gns,))?,
        ))
    } else if oid == *INVALIDITY_DATE_OID {
        let time = asn1::parse_single::<asn1::GeneralizedTime>(data)?;
        let py_dt = chrono_to_py(py, time.as_chrono())?;
        Ok(Some(
            x509_module.getattr("InvalidityDate")?.call1((py_dt,))?,
        ))
    } else {
        Ok(None)
    }
}

pub fn parse_cert_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier<'_>,
    ext_data: &[u8],
) -> PyAsn1Result<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import("cryptography.x509")?;
    if oid == *SUBJECT_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let sans = parse_general_names(py, gn_seq)?;
        Ok(Some(
            x509_module
                .getattr("SubjectAlternativeName")?
                .call1((sans,))?,
        ))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, GeneralName<'_>>>(ext_data)?;
        let ians = parse_general_names(py, gn_seq)?;
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

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "x509")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_certificate))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_certificate))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_crl))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_crl))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_csr))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_csr))?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(
        encode_precertificate_signed_certificate_timestamps
    ))?;

    submod.add_class::<Certificate>()?;
    submod.add_class::<CertificateRevocationList>()?;
    submod.add_class::<RevokedCertificate>()?;
    submod.add_class::<CertificateSigningRequest>()?;
    submod.add_class::<Sct>()?;

    Ok(submod)
}
