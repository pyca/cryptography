// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_byte_slice_to_py_int, oid_to_py_oid, py_uint_to_big_endian_bytes};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::{extensions, ocsp};
use crate::{exceptions, x509};
use cryptography_x509::{
    common,
    ocsp_req::{self, OCSPRequest as RawOCSPRequest},
    oid,
};
use pyo3::IntoPy;

self_cell::self_cell!(
    struct OwnedOCSPRequest {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawOCSPRequest,
    }
);

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_request(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> CryptographyResult<OCSPRequest> {
    let raw = OwnedOCSPRequest::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;

    if raw
        .borrow_dependent()
        .tbs_request
        .request_list
        .unwrap_read()
        .len()
        != 1
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyNotImplementedError::new_err(
                "OCSP request contains more than one request",
            ),
        ));
    }

    Ok(OCSPRequest {
        raw,
        cached_extensions: pyo3::once_cell::GILOnceCell::new(),
    })
}

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.ocsp")]
struct OCSPRequest {
    raw: OwnedOCSPRequest,

    cached_extensions: pyo3::once_cell::GILOnceCell<pyo3::PyObject>,
}

impl OCSPRequest {
    fn cert_id(&self) -> ocsp_req::CertID<'_> {
        self.raw
            .borrow_dependent()
            .tbs_request
            .request_list
            .unwrap_read()
            .clone()
            .next()
            .unwrap()
            .req_cert
    }
}

#[pyo3::prelude::pymethods]
impl OCSPRequest {
    #[getter]
    fn issuer_name_hash(&self) -> &[u8] {
        self.cert_id().issuer_name_hash
    }

    #[getter]
    fn issuer_key_hash(&self) -> &[u8] {
        self.cert_id().issuer_key_hash
    }

    #[getter]
    fn hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, CryptographyError> {
        let cert_id = self.cert_id();

        let hashes = py.import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?;
        match ocsp::ALGORITHM_PARAMETERS_TO_HASH.get(&cert_id.hash_algorithm.params) {
            Some(alg_name) => Ok(hashes.getattr(*alg_name)?.call0()?),
            None => Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err(format!(
                    "Signature algorithm OID: {} not recognized",
                    cert_id.hash_algorithm.oid()
                )),
            )),
        }
    }

    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, CryptographyError> {
        let bytes = self.cert_id().serial_number.as_bytes();
        Ok(big_byte_slice_to_py_int(py, bytes)?)
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let tbs_request = &self.raw.borrow_dependent().tbs_request;

        let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
        x509::parse_and_cache_extensions(
            py,
            &self.cached_extensions,
            &tbs_request.raw_request_extensions,
            |ext| {
                match ext.extn_id {
                    oid::NONCE_OID => {
                        // This is a disaster. RFC 2560 says that the contents of the nonce is
                        // just the raw extension value. This is nonsense, since they're always
                        // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                        // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                        // the nonce. So we try parsing as a TLV and fall back to just using
                        // the raw value.
                        let nonce = ext.value::<&[u8]>().unwrap_or(ext.extn_value);
                        Ok(Some(
                            x509_module.call_method1(pyo3::intern!(py, "OCSPNonce"), (nonce,))?,
                        ))
                    }
                    oid::ACCEPTABLE_RESPONSES_OID => {
                        let oids = ext.value::<asn1::SequenceOf<'_, asn1::ObjectIdentifier>>()?;
                        let py_oids = pyo3::types::PyList::empty(py);
                        for oid in oids {
                            py_oids.append(oid_to_py_oid(py, &oid)?)?;
                        }

                        Ok(Some(x509_module.call_method1(
                            pyo3::intern!(py, "OCSPAcceptableResponses"),
                            (py_oids,),
                        )?))
                    }
                    _ => Ok(None),
                }
            },
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let der = py
            .import(pyo3::intern!(
                py,
                "cryptography.hazmat.primitives.serialization"
            ))?
            .getattr(pyo3::intern!(py, "Encoding"))?
            .getattr(pyo3::intern!(py, "DER"))?;
        if !encoding.is(der) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            )
            .into());
        }
        let result = asn1::write_single(self.raw.borrow_dependent())?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

#[pyo3::prelude::pyfunction]
fn create_ocsp_request(
    py: pyo3::Python<'_>,
    builder: &pyo3::PyAny,
) -> CryptographyResult<OCSPRequest> {
    let builder_request = builder.getattr(pyo3::intern!(py, "_request"))?;

    // Declare outside the if-block so the lifetimes are right.
    let (py_cert, py_issuer, py_hash): (
        pyo3::PyRef<'_, x509::certificate::Certificate>,
        pyo3::PyRef<'_, x509::certificate::Certificate>,
        &pyo3::PyAny,
    );
    let req_cert = if !builder_request.is_none() {
        let tuple = builder_request.extract::<(
            pyo3::PyRef<'_, x509::certificate::Certificate>,
            pyo3::PyRef<'_, x509::certificate::Certificate>,
            &pyo3::PyAny,
        )>()?;
        py_cert = tuple.0;
        py_issuer = tuple.1;
        py_hash = tuple.2;
        ocsp::certid_new(py, &py_cert, &py_issuer, py_hash)?
    } else {
        let (issuer_name_hash, issuer_key_hash, py_serial, py_hash): (
            &[u8],
            &[u8],
            &pyo3::types::PyLong,
            &pyo3::PyAny,
        ) = builder
            .getattr(pyo3::intern!(py, "_request_hash"))?
            .extract()?;
        let serial_number = asn1::BigInt::new(py_uint_to_big_endian_bytes(py, py_serial)?).unwrap();
        ocsp::certid_new_from_hash(
            py,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
            py_hash,
        )?
    };

    let extensions = x509::common::encode_extensions(
        py,
        builder.getattr(pyo3::intern!(py, "_extensions"))?,
        extensions::encode_extension,
    )?;
    let reqs = [ocsp_req::Request {
        req_cert,
        single_request_extensions: None,
    }];
    let ocsp_req = ocsp_req::OCSPRequest {
        tbs_request: ocsp_req::TBSRequest {
            version: 0,
            requestor_name: None,
            request_list: common::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
                &reqs,
            )),
            raw_request_extensions: extensions,
        },
        optional_signature: None,
    };
    let data = asn1::write_single(&ocsp_req)?;
    load_der_ocsp_request(py, pyo3::types::PyBytes::new(py, &data).into_py(py))
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(load_der_ocsp_request, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(create_ocsp_request, module)?)?;

    Ok(())
}
