// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{
    big_byte_slice_to_py_int, py_uint_to_big_endian_bytes, PyAsn1Error, PyAsn1Result,
};
use crate::x509;
use crate::x509::{extensions, ocsp, oid};
use std::sync::Arc;

#[ouroboros::self_referencing]
struct OwnedRawOCSPRequest {
    data: Arc<[u8]>,
    #[borrows(data)]
    #[covariant]
    value: RawOCSPRequest<'this>,
}

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_request(_py: pyo3::Python<'_>, data: &[u8]) -> PyAsn1Result<OCSPRequest> {
    let raw = OwnedRawOCSPRequest::try_new(Arc::from(data), |data| asn1::parse_single(data))?;

    if raw
        .borrow_value()
        .tbs_request
        .request_list
        .unwrap_read()
        .len()
        != 1
    {
        return Err(PyAsn1Error::from(
            pyo3::exceptions::PyNotImplementedError::new_err(
                "OCSP request contains more than one request",
            ),
        ));
    }

    Ok(OCSPRequest {
        raw,
        cached_extensions: None,
    })
}

#[pyo3::prelude::pyclass]
struct OCSPRequest {
    raw: OwnedRawOCSPRequest,

    cached_extensions: Option<pyo3::PyObject>,
}

impl OCSPRequest {
    fn cert_id(&self) -> ocsp::CertID<'_> {
        self.raw
            .borrow_value()
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
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let cert_id = self.cert_id();

        let hashes = py.import("cryptography.hazmat.primitives.hashes")?;
        match ocsp::OIDS_TO_HASH.get(&cert_id.hash_algorithm.oid) {
            Some(alg_name) => Ok(hashes.getattr(alg_name)?.call0()?),
            None => {
                let exceptions = py.import("cryptography.exceptions")?;
                Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    exceptions
                        .getattr(crate::intern!(py, "UnsupportedAlgorithm"))?
                        .call1((format!(
                            "Signature algorithm OID: {} not recognized",
                            cert_id.hash_algorithm.oid
                        ),))?,
                )))
            }
        }
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let bytes = self.cert_id().serial_number.as_bytes();
        Ok(big_byte_slice_to_py_int(py, bytes)?)
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_request.request_extensions,
            |oid, value| {
                match oid {
                    &oid::NONCE_OID => {
                        // This is a disaster. RFC 2560 says that the contents of the nonce is
                        // just the raw extension value. This is nonsense, since they're always
                        // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                        // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                        // the nonce. So we try parsing as a TLV and fall back to just using
                        // the raw value.
                        let nonce = asn1::parse_single::<&[u8]>(value).unwrap_or(value);
                        Ok(Some(x509_module.call_method1("OCSPNonce", (nonce,))?))
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
    ) -> PyAsn1Result<&'p pyo3::types::PyBytes> {
        let der = py
            .import("cryptography.hazmat.primitives.serialization")?
            .getattr(crate::intern!(py, "Encoding"))?
            .getattr(crate::intern!(py, "DER"))?;
        if encoding != der {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            )
            .into());
        }
        let result = asn1::write_single(self.raw.borrow_value())?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RawOCSPRequest<'a> {
    tbs_request: TBSRequest<'a>,
    // Parsing out the full structure, which includes the entirety of a
    // certificate is more trouble than it's worth, since it's not in the
    // Python API.
    #[explicit(0)]
    optional_signature: Option<asn1::Sequence<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct TBSRequest<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    #[explicit(1)]
    requestor_name: Option<x509::GeneralName<'a>>,
    request_list: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, Request<'a>>,
        asn1::SequenceOfWriter<'a, Request<'a>>,
    >,
    #[explicit(2)]
    request_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Request<'a> {
    req_cert: ocsp::CertID<'a>,
    #[explicit(0)]
    single_request_extensions: Option<x509::Extensions<'a>>,
}

#[pyo3::prelude::pyfunction]
fn create_ocsp_request(py: pyo3::Python<'_>, builder: &pyo3::PyAny) -> PyAsn1Result<OCSPRequest> {
    let builder_request = builder.getattr(crate::intern!(py, "_request"))?;

    // Declare outside the if-block so the lifetimes are right.
    let (py_cert, py_issuer, py_hash): (
        pyo3::PyRef<'_, x509::Certificate>,
        pyo3::PyRef<'_, x509::Certificate>,
        &pyo3::PyAny,
    );
    let req_cert = if !builder_request.is_none() {
        let tuple = builder_request.extract::<(
            pyo3::PyRef<'_, x509::Certificate>,
            pyo3::PyRef<'_, x509::Certificate>,
            &pyo3::PyAny,
        )>()?;
        py_cert = tuple.0;
        py_issuer = tuple.1;
        py_hash = tuple.2;
        ocsp::CertID::new(py, &py_cert, &py_issuer, py_hash)?
    } else {
        let (issuer_name_hash, issuer_key_hash, py_serial, py_hash): (
            &[u8],
            &[u8],
            &pyo3::types::PyLong,
            &pyo3::PyAny,
        ) = builder
            .getattr(crate::intern!(py, "_request_hash"))?
            .extract()?;
        let serial_number = asn1::BigInt::new(py_uint_to_big_endian_bytes(py, py_serial)?).unwrap();
        ocsp::CertID::new_from_hash(
            py,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
            py_hash,
        )?
    };

    let extensions = x509::common::encode_extensions(
        py,
        builder.getattr(crate::intern!(py, "_extensions"))?,
        extensions::encode_extension,
    )?;
    let reqs = [Request {
        req_cert,
        single_request_extensions: None,
    }];
    let ocsp_req = RawOCSPRequest {
        tbs_request: TBSRequest {
            version: 0,
            requestor_name: None,
            request_list: x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
                &reqs,
            )),
            request_extensions: extensions,
        },
        optional_signature: None,
    };
    let data = asn1::write_single(&ocsp_req)?;
    // TODO: extra copy as we round-trip through a slice
    load_der_ocsp_request(py, &data)
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_request))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(create_ocsp_request))?;

    Ok(())
}
