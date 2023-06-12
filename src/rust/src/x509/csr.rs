// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{encode_der_data, oid_to_py_oid, py_oid_to_oid};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::{certificate, sign};
use crate::{exceptions, x509};
use asn1::SimpleAsn1Readable;
use cryptography_x509::csr::{check_attribute_length, Attribute, CertificationRequestInfo, Csr};
use cryptography_x509::{common, oid};
use pyo3::IntoPy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

self_cell::self_cell!(
    struct OwnedCsr {
        owner: pyo3::Py<pyo3::types::PyBytes>,

        #[covariant]
        dependent: Csr,
    }
);

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
struct CertificateSigningRequest {
    raw: OwnedCsr,
    cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pymethods]
impl CertificateSigningRequest {
    fn __hash__(&self, py: pyo3::Python<'_>) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_owner().as_bytes(py).hash(&mut hasher);
        hasher.finish()
    }

    fn __richcmp__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, CertificateSigningRequest>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => {
                Ok(self.raw.borrow_owner().as_bytes(py) == other.raw.borrow_owner().as_bytes(py))
            }
            pyo3::basic::CompareOp::Ne => {
                Ok(self.raw.borrow_owner().as_bytes(py) != other.raw.borrow_owner().as_bytes(py))
            }
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "CSRs cannot be ordered",
            )),
        }
    }

    fn public_key<'p>(&self, py: pyo3::Python<'p>) -> CryptographyResult<&'p pyo3::PyAny> {
        // This makes an unnecessary copy. It'd be nice to get rid of it.
        let serialized = pyo3::types::PyBytes::new(
            py,
            &asn1::write_single(&self.raw.borrow_dependent().csr_info.spki)?,
        );
        Ok(py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "load_der_public_key"))?
            .call1((serialized,))?)
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        Ok(x509::parse_name(
            py,
            &self.raw.borrow_dependent().csr_info.subject,
        )?)
    }

    #[getter]
    fn tbs_certrequest_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = asn1::write_single(&self.raw.borrow_dependent().csr_info)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> &'p pyo3::types::PyBytes {
        pyo3::types::PyBytes::new(py, self.raw.borrow_dependent().signature.as_bytes())
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
            Err(_) => Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err(format!(
                    "Signature algorithm OID: {} not recognized",
                    self.raw.borrow_dependent().signature_alg.oid()
                )),
            )),
        }
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        oid_to_py_oid(py, self.raw.borrow_dependent().signature_alg.oid())
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &'p pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = asn1::write_single(self.raw.borrow_dependent())?;

        encode_der_data(py, "CERTIFICATE REQUEST".to_string(), result, encoding)
    }

    fn get_attribute_for_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
        oid: &pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let cryptography_warning = py
            .import(pyo3::intern!(py, "cryptography.utils"))?
            .getattr(pyo3::intern!(py, "DeprecatedIn36"))?;
        pyo3::PyErr::warn(
            py,
            cryptography_warning,
            "CertificateSigningRequest.get_attribute_for_oid has been deprecated. Please switch to request.attributes.get_attribute_for_oid.",
            1,
        )?;
        let rust_oid = py_oid_to_oid(oid)?;
        for attribute in self
            .raw
            .borrow_dependent()
            .csr_info
            .attributes
            .unwrap_read()
            .clone()
        {
            if rust_oid == attribute.type_id {
                check_attribute_length(attribute.values.unwrap_read().clone()).map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err(
                        "Only single-valued attributes are supported",
                    )
                })?;
                let val = attribute.values.unwrap_read().clone().next().unwrap();
                // We allow utf8string, printablestring, and ia5string at this time
                if val.tag() == asn1::Utf8String::TAG
                    || val.tag() == asn1::PrintableString::TAG
                    || val.tag() == asn1::IA5String::TAG
                {
                    return Ok(pyo3::types::PyBytes::new(py, val.data()));
                }
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "OID {} has a disallowed ASN.1 type: {:?}",
                    oid,
                    val.tag()
                )));
            }
        }
        Err(exceptions::AttributeNotFound::new_err((
            format!("No {} attribute was found", oid),
            oid.into_py(py),
        )))
    }

    #[getter]
    fn attributes<'p>(&mut self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let pyattrs = pyo3::types::PyList::empty(py);
        for attribute in self
            .raw
            .borrow_dependent()
            .csr_info
            .attributes
            .unwrap_read()
            .clone()
        {
            check_attribute_length(attribute.values.unwrap_read().clone()).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Only single-valued attributes are supported",
                )
            })?;
            let oid = oid_to_py_oid(py, &attribute.type_id)?;
            let val = attribute.values.unwrap_read().clone().next().unwrap();
            let serialized = pyo3::types::PyBytes::new(py, val.data());
            let tag = val.tag().as_u8().ok_or_else(|| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Long-form tags are not supported in CSR attribute values",
                ))
            })?;
            let pyattr = py
                .import(pyo3::intern!(py, "cryptography.x509"))?
                .call_method1(pyo3::intern!(py, "Attribute"), (oid, serialized, tag))?;
            pyattrs.append(pyattr)?;
        }
        py.import(pyo3::intern!(py, "cryptography.x509"))?
            .call_method1(pyo3::intern!(py, "Attributes"), (pyattrs,))
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let raw_exts = self
            .raw
            .borrow_dependent()
            .csr_info
            .get_extension_attribute()
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Only single-valued attributes are supported",
                )
            })?;

        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &raw_exts,
            |oid, ext_data| certificate::parse_cert_ext(py, oid.clone(), ext_data),
        )
    }

    #[getter]
    fn is_signature_valid(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<bool> {
        let public_key = slf.public_key(py)?;
        Ok(sign::verify_signature_with_signature_algorithm(
            py,
            public_key,
            &slf.raw.borrow_dependent().signature_alg,
            slf.raw.borrow_dependent().signature.as_bytes(),
            &asn1::write_single(&slf.raw.borrow_dependent().csr_info)?,
        )
        .is_ok())
    }
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_csr(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> CryptographyResult<CertificateSigningRequest> {
    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L35-L36
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag == "CERTIFICATE REQUEST" || p.tag == "NEW CERTIFICATE REQUEST",
        "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is a CSR?",
    )?;
    load_der_x509_csr(
        py,
        pyo3::types::PyBytes::new(py, &parsed.contents).into_py(py),
    )
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_csr(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> CryptographyResult<CertificateSigningRequest> {
    let raw = OwnedCsr::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;

    let version = raw.borrow_dependent().csr_info.version;
    if version != 0 {
        return Err(CryptographyError::from(
            exceptions::InvalidVersion::new_err((
                format!("{} is not a valid CSR version", version),
                version,
            )),
        ));
    }

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
) -> CryptographyResult<CertificateSigningRequest> {
    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key,
        hash_algorithm,
        py.None().into_ref(py),
    )?;
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

    let spki_bytes = private_key
        .call_method0(pyo3::intern!(py, "public_key"))?
        .call_method1(
            pyo3::intern!(py, "public_bytes"),
            (der_encoding, spki_format),
        )?
        .extract::<&[u8]>()?;

    let mut attrs = vec![];
    let ext_bytes;
    if let Some(exts) = x509::common::encode_extensions(
        py,
        builder.getattr(pyo3::intern!(py, "_extensions"))?,
        x509::extensions::encode_extension,
    )? {
        ext_bytes = asn1::write_single(&exts)?;
        attrs.push(Attribute {
            type_id: (oid::EXTENSION_REQUEST).clone(),
            values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                asn1::parse_single(&ext_bytes)?,
            ])),
        })
    }

    for py_attr in builder.getattr(pyo3::intern!(py, "_attributes"))?.iter()? {
        let (py_oid, value, tag): (&pyo3::PyAny, &[u8], Option<u8>) = py_attr?.extract()?;
        let oid = py_oid_to_oid(py_oid)?;
        let tag = if let Some(tag) = tag {
            asn1::Tag::from_bytes(&[tag])?.0
        } else {
            if std::str::from_utf8(value).is_err() {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "Attribute values must be valid utf-8.",
                    ),
                ));
            }
            asn1::Utf8String::TAG
        };

        attrs.push(Attribute {
            type_id: oid,
            values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                common::RawTlv::new(tag, value),
            ])),
        })
    }

    let py_subject_name = builder.getattr(pyo3::intern!(py, "_subject_name"))?;

    let csr_info = CertificationRequestInfo {
        version: 0,
        subject: x509::common::encode_name(py, py_subject_name)?,
        spki: asn1::parse_single(spki_bytes)?,
        attributes: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(attrs)),
    };

    let tbs_bytes = asn1::write_single(&csr_info)?;
    let signature = x509::sign::sign_data(
        py,
        private_key,
        hash_algorithm,
        py.None().into_ref(py),
        &tbs_bytes,
    )?;
    let data = asn1::write_single(&Csr {
        csr_info,
        signature_alg: sigalg,
        signature: asn1::BitString::new(signature, 0).unwrap(),
    })?;
    load_der_x509_csr(py, pyo3::types::PyBytes::new(py, &data).into_py(py))
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(load_der_x509_csr, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(load_pem_x509_csr, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(create_x509_csr, module)?)?;

    module.add_class::<CertificateSigningRequest>()?;

    Ok(())
}
