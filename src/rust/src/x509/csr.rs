// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{PyAsn1Error, PyAsn1Result};
use crate::x509;
use crate::x509::certificate;
use asn1::SimpleAsn1Readable;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

lazy_static::lazy_static! {
    static ref MS_EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.311.2.1.14").unwrap();
    static ref EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.9.14").unwrap();
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RawCsr<'a> {
    csr_info: CertificationRequestInfo<'a>,
    signature_alg: x509::AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct CertificationRequestInfo<'a> {
    version: u8,
    subject: x509::Name<'a>,
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
    fn get_extension_attribute<'a>(&'a self) -> Result<Option<x509::Extensions<'a>>, PyAsn1Error> {
        for attribute in self.attributes.clone() {
            if attribute.type_id == *EXTENSION_REQUEST || attribute.type_id == *MS_EXTENSION_REQUEST
            {
                check_attribute_length(attribute.values.clone())?;
                let val = attribute.values.clone().next().unwrap();
                let exts = asn1::parse_single::<x509::Extensions<'a>>(val.full_data())?;
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
        x509::parse_name(py, &self.raw.borrow_value().csr_info.subject)
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
        x509::parse_and_cache_extensions(py, &mut self.cached_extensions, &exts, |oid, ext_data| {
            certificate::parse_cert_ext(py, oid.clone(), ext_data)
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
    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L35-L36
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag == "CERTIFICATE REQUEST" || p.tag == "NEW CERTIFICATE REQUEST",
        "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is a CSR?",
        "Valid PEM but multiple BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters.",
    )?;
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

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_csr))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_csr))?;

    module.add_class::<CertificateSigningRequest>()?;

    Ok(())
}
