// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{PyAsn1Error, PyAsn1Result};
use crate::x509;
use crate::x509::{certificate, oid};
use asn1::SimpleAsn1Readable;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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
    spki: certificate::SubjectPublicKeyInfo<'a>,
    #[implicit(0, required)]
    attributes: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SetOf<'a, Attribute<'a>>,
        asn1::SetOfWriter<'a, Attribute<'a>, Vec<Attribute<'a>>>,
    >,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Attribute<'a> {
    type_id: asn1::ObjectIdentifier<'a>,
    values: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SetOf<'a, asn1::Tlv<'a>>,
        asn1::SetOfWriter<'a, x509::common::RawTlv<'a>, [x509::common::RawTlv<'a>; 1]>,
    >,
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

// CsrExtension has same layout as Extension, but doesn't use `#[default]` for
// `critical` so we can avoid erroring on explicitly-encoded defaults.
#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
pub(crate) struct CsrExtension<'a> {
    pub(crate) extn_id: asn1::ObjectIdentifier<'a>,
    pub(crate) critical: Option<bool>,
    pub(crate) extn_value: &'a [u8],
}

impl CertificationRequestInfo<'_> {
    fn get_extension_attribute(
        &self,
    ) -> Result<Option<asn1::SequenceOf<'_, CsrExtension<'_>>>, PyAsn1Error> {
        for attribute in self.attributes.unwrap_read().clone() {
            if attribute.type_id == *oid::EXTENSION_REQUEST
                || attribute.type_id == *oid::MS_EXTENSION_REQUEST
            {
                check_attribute_length(attribute.values.unwrap_read().clone())?;
                let val = attribute.values.unwrap_read().clone().next().unwrap();
                let exts = asn1::parse_single(val.full_data())?;
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
                        self.raw.borrow_value().signature_alg.oid
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
        let cryptography_warning = py.import("cryptography.utils")?.getattr("DeprecatedIn36")?;
        let warnings = py.import("warnings")?;
        warnings.call_method1(
            "warn",
            (
                "CertificateSigningRequest.get_attribute_for_oid has been deprecated. Please switch to request.attributes.get_attribute_for_oid.",
                cryptography_warning,
            ),
        )?;
        let oid_str = oid.getattr("dotted_string")?.extract::<&str>()?;
        let rust_oid = asn1::ObjectIdentifier::from_string(oid_str).unwrap();
        for attribute in self
            .raw
            .borrow_value()
            .csr_info
            .attributes
            .unwrap_read()
            .clone()
        {
            if rust_oid == attribute.type_id {
                check_attribute_length(attribute.values.unwrap_read().clone())?;
                let val = attribute.values.unwrap_read().clone().next().unwrap();
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
    fn attributes<'p>(&mut self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let pyattrs = pyo3::types::PyList::empty(py);
        for attribute in self
            .raw
            .borrow_value()
            .csr_info
            .attributes
            .unwrap_read()
            .clone()
        {
            check_attribute_length(attribute.values.unwrap_read().clone())?;
            let oid = py
                .import("cryptography.x509")?
                .call_method1("ObjectIdentifier", (attribute.type_id.to_string(),))?;
            let val = attribute.values.unwrap_read().clone().next().unwrap();
            let serialized = pyo3::types::PyBytes::new(py, val.data());
            let pyattr = py
                .import("cryptography.x509")?
                .call_method1("Attribute", (oid, serialized, val.tag()))?;
            pyattrs.append(pyattr)?;
        }
        py.import("cryptography.x509")?
            .call_method1("Attributes", (pyattrs,))
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let csr_exts = self.raw.borrow_value().csr_info.get_extension_attribute()?;
        let data;
        // This is all very inefficient, to temporarily allow accepting
        // extensions with `critical` having an explicit default encoding.
        let exts = if let Some(v) = csr_exts {
            // Raise a warning if there's an explicitly encoded false
            for e in v.clone() {
                if e.critical == Some(false) {
                    let cryptography_warning =
                        py.import("cryptography.utils")?.getattr("DeprecatedIn36")?;
                    let warnings = py.import("warnings")?;
                    warnings.call_method1(
                        "warn",
                        (
                            "This CSR contains an improperly encoded default value. Support for this will be removed in an upcoming cryptography release.",
                            cryptography_warning,
                        ),
                    )?;
                }
            }
            let x509_exts: Vec<x509::common::Extension<'_>> = v
                .map(|e| x509::common::Extension {
                    extn_id: e.extn_id,
                    critical: e.critical.unwrap_or_default(),
                    extn_value: e.extn_value,
                })
                .collect();
            data = asn1::write_single(&asn1::SequenceOfWriter::new(x509_exts));
            Some(x509::Asn1ReadableOrWritable::new_read(
                asn1::parse_single(&data).unwrap(),
            ))
        } else {
            None
        };

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

#[pyo3::prelude::pyfunction]
fn create_x509_csr(
    py: pyo3::Python<'_>,
    builder: &pyo3::PyAny,
    private_key: &pyo3::PyAny,
    hash_algorithm: &pyo3::PyAny,
) -> PyAsn1Result<CertificateSigningRequest> {
    let sigalg = x509::sign::compute_signature_algorithm(py, private_key, hash_algorithm)?;
    let serialization_mod = py.import("cryptography.hazmat.primitives.serialization")?;
    let der_encoding = serialization_mod.getattr("Encoding")?.getattr("DER")?;
    let spki_format = serialization_mod
        .getattr("PublicFormat")?
        .getattr("SubjectPublicKeyInfo")?;

    let spki_bytes = private_key
        .call_method0("public_key")?
        .call_method1("public_bytes", (der_encoding, spki_format))?
        .extract::<&[u8]>()?;

    let mut attrs = vec![];
    let ext_bytes;
    if let Some(exts) = x509::common::encode_extensions(
        py,
        builder.getattr("_extensions")?,
        x509::extensions::encode_extension,
    )? {
        ext_bytes = asn1::write_single(&exts);
        attrs.push(Attribute {
            type_id: (*oid::EXTENSION_REQUEST).clone(),
            values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                asn1::parse_single(&ext_bytes)?,
            ])),
        })
    }

    for py_attr in builder.getattr("_attributes")?.iter()? {
        let (py_oid, value): (&pyo3::PyAny, &[u8]) = py_attr?.extract()?;
        let oid = asn1::ObjectIdentifier::from_string(
            py_oid.getattr("dotted_string")?.extract::<&str>()?,
        )
        .unwrap();
        let tag = if std::str::from_utf8(value).is_ok() {
            asn1::Utf8String::TAG
        } else {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "Attribute values must be valid utf-8.",
            )));
        };
        attrs.push(Attribute {
            type_id: oid,
            values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                x509::common::RawTlv::new(tag, value),
            ])),
        })
    }

    let csr_info = CertificationRequestInfo {
        version: 0,
        subject: x509::common::encode_name(py, builder.getattr("_subject_name")?)?,
        spki: asn1::parse_single(spki_bytes)?,
        attributes: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(attrs)),
    };

    let tbs_bytes = asn1::write_single(&csr_info);
    let signature = x509::sign::sign_data(py, private_key, hash_algorithm, &tbs_bytes)?;
    let data = asn1::write_single(&RawCsr {
        csr_info,
        signature_alg: sigalg,
        signature: asn1::BitString::new(signature, 0).unwrap(),
    });
    // TODO: extra copy as we round-trip through a slice
    load_der_x509_csr(py, &data)
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_csr))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_csr))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(create_x509_csr))?;

    module.add_class::<CertificateSigningRequest>()?;

    Ok(())
}
