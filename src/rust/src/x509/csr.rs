// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use asn1::SimpleAsn1Readable;
use cryptography_x509::csr::{check_attribute_length, Attribute, CertificationRequestInfo, Csr};
use cryptography_x509::{common, oid};
use pyo3::types::{PyAnyMethods, PyListMethods};
use pyo3::IntoPy;

use crate::asn1::{encode_der_data, oid_to_py_oid, py_oid_to_oid};
use crate::backend::keys;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::{certificate, sign};
use crate::{exceptions, types, x509};

self_cell::self_cell!(
    struct OwnedCsr {
        owner: pyo3::Py<pyo3::types::PyBytes>,

        #[covariant]
        dependent: Csr,
    }
);

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.x509")]
pub(crate) struct CertificateSigningRequest {
    raw: OwnedCsr,
    cached_extensions: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

#[pyo3::pymethods]
impl CertificateSigningRequest {
    fn __hash__(&self, py: pyo3::Python<'_>) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.raw.borrow_owner().as_bytes(py).hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, CertificateSigningRequest>,
    ) -> bool {
        self.raw.borrow_owner().as_bytes(py) == other.raw.borrow_owner().as_bytes(py)
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> CryptographyResult<pyo3::PyObject> {
        keys::load_der_public_key_bytes(
            py,
            self.raw.borrow_dependent().csr_info.spki.tlv().full_data(),
        )
    }

    #[getter]
    fn public_key_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        oid_to_py_oid(
            py,
            self.raw.borrow_dependent().csr_info.spki.algorithm.oid(),
        )
    }

    #[getter]
    fn subject<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        Ok(x509::parse_name(
            py,
            self.raw.borrow_dependent().csr_info.subject.unwrap_read(),
        )?)
    }

    #[getter]
    fn tbs_certrequest_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(&self.raw.borrow_dependent().csr_info)?;
        Ok(pyo3::types::PyBytes::new_bound(py, &result))
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new_bound(py, self.raw.borrow_dependent().signature.as_bytes())
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        sign::identify_signature_hash_algorithm(py, &self.raw.borrow_dependent().signature_alg)
    }

    #[getter]
    fn signature_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        oid_to_py_oid(py, self.raw.borrow_dependent().signature_alg.oid())
    }

    #[getter]
    fn signature_algorithm_parameters<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        sign::identify_signature_algorithm_parameters(
            py,
            &self.raw.borrow_dependent().signature_alg,
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(self.raw.borrow_dependent())?;

        encode_der_data(py, "CERTIFICATE REQUEST".to_string(), result, encoding)
    }

    fn get_attribute_for_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
        oid: pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_36.get(py)?;
        let warning_msg = "CertificateSigningRequest.get_attribute_for_oid has been deprecated. Please switch to request.attributes.get_attribute_for_oid.";
        pyo3::PyErr::warn_bound(py, &warning_cls, warning_msg, 1)?;

        let rust_oid = py_oid_to_oid(oid.clone())?;
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
                    return Ok(pyo3::types::PyBytes::new_bound(py, val.data()).into_any());
                }
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "OID {} has a disallowed ASN.1 type: {:?}",
                    oid,
                    val.tag()
                )));
            }
        }
        Err(exceptions::AttributeNotFound::new_err((
            format!("No {oid} attribute was found"),
            oid.into_py(py),
        )))
    }

    #[getter]
    fn attributes<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let pyattrs = pyo3::types::PyList::empty_bound(py);
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
            let serialized = pyo3::types::PyBytes::new_bound(py, val.data());
            let tag = val.tag().as_u8().ok_or_else(|| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Long-form tags are not supported in CSR attribute values",
                ))
            })?;
            let pyattr = types::ATTRIBUTE.get(py)?.call1((oid, serialized, tag))?;
            pyattrs.append(pyattr)?;
        }
        types::ATTRIBUTES.get(py)?.call1((pyattrs,))
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
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

        x509::parse_and_cache_extensions(py, &self.cached_extensions, &raw_exts, |ext| {
            certificate::parse_cert_ext(py, ext)
        })
    }

    #[getter]
    fn is_signature_valid(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<bool> {
        let public_key = slf.public_key(py)?;
        Ok(sign::verify_signature_with_signature_algorithm(
            py,
            public_key.bind(py).clone(),
            &slf.raw.borrow_dependent().signature_alg,
            slf.raw.borrow_dependent().signature.as_bytes(),
            &asn1::write_single(&slf.raw.borrow_dependent().csr_info)?,
        )
        .is_ok())
    }
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_pem_x509_csr(
    py: pyo3::Python<'_>,
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<CertificateSigningRequest> {
    let _ = backend;

    // We support both PEM header strings that OpenSSL does
    // https://github.com/openssl/openssl/blob/5e2d22d53ed322a7124e26a4fbd116a8210eb77a/include/openssl/pem.h#L35-L36
    let parsed = x509::find_in_pem(
        data,
        |p| p.tag() == "CERTIFICATE REQUEST" || p.tag() == "NEW CERTIFICATE REQUEST",
        "Valid PEM but no BEGIN CERTIFICATE REQUEST/END CERTIFICATE REQUEST delimiters. Are you sure this is a CSR?",
    )?;
    load_der_x509_csr(
        py,
        pyo3::types::PyBytes::new_bound(py, parsed.contents()).unbind(),
        None,
    )
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_der_x509_csr(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<CertificateSigningRequest> {
    let _ = backend;

    let raw = OwnedCsr::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;

    let version = raw.borrow_dependent().csr_info.version;
    if version != 0 {
        return Err(CryptographyError::from(
            exceptions::InvalidVersion::new_err((
                format!("{version} is not a valid CSR version"),
                version,
            )),
        ));
    }

    Ok(CertificateSigningRequest {
        raw,
        cached_extensions: pyo3::sync::GILOnceCell::new(),
    })
}

#[pyo3::pyfunction]
pub(crate) fn create_x509_csr(
    py: pyo3::Python<'_>,
    builder: &pyo3::Bound<'_, pyo3::PyAny>,
    private_key: &pyo3::Bound<'_, pyo3::PyAny>,
    hash_algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    rsa_padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<CertificateSigningRequest> {
    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        rsa_padding.clone(),
    )?;

    let der = types::ENCODING_DER.get(py)?;
    let spki = types::PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO.get(py)?;
    let spki_bytes = private_key
        .call_method0(pyo3::intern!(py, "public_key"))?
        .call_method1(pyo3::intern!(py, "public_bytes"), (der, spki))?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;

    let ka_vec = cryptography_keepalive::KeepAlive::new();
    let ka_bytes = cryptography_keepalive::KeepAlive::new();

    let mut attrs = vec![];
    let ext_bytes;
    if let Some(exts) = x509::common::encode_extensions(
        py,
        &ka_vec,
        &ka_bytes,
        &builder.getattr(pyo3::intern!(py, "_extensions"))?,
        x509::extensions::encode_extension,
    )? {
        ext_bytes = asn1::write_single(&exts)?;
        attrs.push(Attribute {
            type_id: (oid::EXTENSION_REQUEST).clone(),
            values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                asn1::parse_single(&ext_bytes)?,
            ])),
        });
    }

    let mut attr_values = vec![];
    for py_attr in builder.getattr(pyo3::intern!(py, "_attributes"))?.iter()? {
        let (py_oid, value, tag): (
            pyo3::Bound<'_, pyo3::PyAny>,
            pyo3::pybacked::PyBackedBytes,
            Option<u8>,
        ) = py_attr?.extract()?;
        let oid = py_oid_to_oid(py_oid)?;
        let tag = if let Some(tag) = tag {
            asn1::Tag::from_bytes(&[tag])?.0
        } else {
            if std::str::from_utf8(&value).is_err() {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "Attribute values must be valid utf-8.",
                    ),
                ));
            }
            asn1::Utf8String::TAG
        };

        attr_values.push((oid, tag, value));
    }

    for (oid, tag, value) in &attr_values {
        attrs.push(Attribute {
            type_id: oid.clone(),
            values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                common::RawTlv::new(*tag, value),
            ])),
        });
    }

    let py_subject_name = builder.getattr(pyo3::intern!(py, "_subject_name"))?;

    let ka = cryptography_keepalive::KeepAlive::new();

    let csr_info = CertificationRequestInfo {
        version: 0,
        subject: x509::common::encode_name(py, &ka, &py_subject_name)?,
        spki: asn1::parse_single(&spki_bytes)?,
        attributes: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(attrs)),
    };

    let tbs_bytes = asn1::write_single(&csr_info)?;
    let signature = x509::sign::sign_data(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        rsa_padding.clone(),
        &tbs_bytes,
    )?;
    let data = asn1::write_single(&Csr {
        csr_info,
        signature_alg: sigalg,
        signature: asn1::BitString::new(&signature, 0).unwrap(),
    })?;
    load_der_x509_csr(
        py,
        pyo3::types::PyBytes::new_bound(py, &data).clone().unbind(),
        None,
    )
}
