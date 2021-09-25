// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, PyAsn1Error, PyAsn1Result};
use crate::x509;
use pyo3::exceptions;
use std::collections::HashMap;
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    static ref SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    static ref SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    static ref SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    static ref SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();

    static ref OIDS_TO_HASH: HashMap<&'static asn1::ObjectIdentifier<'static>, &'static str> = {
        let mut h = HashMap::new();
        h.insert(&*SHA1_OID, "SHA1");
        h.insert(&*SHA224_OID, "SHA224");
        h.insert(&*SHA256_OID, "SHA256");
        h.insert(&*SHA384_OID, "SHA384");
        h.insert(&*SHA512_OID, "SHA512");
        h
    };

    static ref NONCE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.2").unwrap();
    static ref SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.5").unwrap();

    static ref BASIC_RESPONSE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.1").unwrap();
}

#[ouroboros::self_referencing]
struct OwnedRawOCSPRequest {
    data: Arc<[u8]>,
    #[borrows(data)]
    #[covariant]
    value: RawOCSPRequest<'this>,
}

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_request(_py: pyo3::Python<'_>, data: &[u8]) -> Result<OCSPRequest, PyAsn1Error> {
    let raw = OwnedRawOCSPRequest::try_new(Arc::from(data), |data| asn1::parse_single(data))?;

    if raw.borrow_value().tbs_request.request_list.len() != 1 {
        return Err(PyAsn1Error::from(
            exceptions::PyNotImplementedError::new_err(
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
    fn cert_id(&self) -> Result<CertID<'_>, PyAsn1Error> {
        Ok(self
            .raw
            .borrow_value()
            .tbs_request
            .request_list
            .clone()
            .next()
            .unwrap()
            .req_cert)
    }
}

#[pyo3::prelude::pymethods]
impl OCSPRequest {
    #[getter]
    fn issuer_name_hash(&self) -> Result<&[u8], PyAsn1Error> {
        Ok(self.cert_id()?.issuer_name_hash)
    }

    #[getter]
    fn issuer_key_hash(&self) -> Result<&[u8], PyAsn1Error> {
        Ok(self.cert_id()?.issuer_key_hash)
    }

    #[getter]
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let cert_id = self.cert_id()?;

        let hashes = py.import("cryptography.hazmat.primitives.hashes")?;
        match OIDS_TO_HASH.get(&cert_id.hash_algorithm.oid) {
            Some(alg_name) => Ok(hashes.getattr(alg_name)?.call0()?),
            None => {
                let exceptions = py.import("cryptography.exceptions")?;
                Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    exceptions.getattr("UnsupportedAlgorithm")?.call1((format!(
                        "Signature algorithm OID: {} not recognized",
                        cert_id.hash_algorithm.oid
                    ),))?,
                )))
            }
        }
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        Ok(big_asn1_uint_to_py(py, self.cert_id()?.serial_number)?)
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_request.request_extensions,
            |oid, value| {
                if oid == &*NONCE_OID {
                    // This is a disaster. RFC 2560 says that the contents of the nonce is
                    // just the raw extension value. This is nonsense, since they're always
                    // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                    // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                    // the nonce. For now we just implement the old behavior, even though
                    // it's deranged.
                    Ok(Some(x509_module.call_method1("OCSPNonce", (value,))?))
                } else {
                    Ok(None)
                }
            },
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
        let der = py
            .import("cryptography.hazmat.primitives.serialization")?
            .getattr("Encoding")?
            .getattr("DER")?;
        if encoding != der {
            return Err(exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            ));
        }
        let result = asn1::write_single(self.raw.borrow_value());
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
    _optional_signature: Option<asn1::Sequence<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct TBSRequest<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    // This is virtually unused, not supported until GeneralName is implemented
    // and used elsewhere.
    // #[explicit(1)]
    // _requestor_name: Option<GeneralName<'a>>,
    request_list: asn1::SequenceOf<'a, Request<'a>>,
    #[explicit(2)]
    request_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct Request<'a> {
    req_cert: CertID<'a>,
    #[explicit(0)]
    _single_request_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct CertID<'a> {
    hash_algorithm: x509::AlgorithmIdentifier<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    serial_number: asn1::BigUint<'a>,
}

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_response(_py: pyo3::Python<'_>, data: &[u8]) -> Result<OCSPResponse, PyAsn1Error> {
    let raw = OwnedRawOCSPResponse::try_new(
        Arc::from(data),
        |data| Ok(asn1::parse_single(data)?),
        |_data, response| match response.response_status.value() {
            SUCCESSFUL_RESPONSE => match response.response_bytes {
                Some(ref bytes) => {
                    if bytes.response_type == *BASIC_RESPONSE_OID {
                        Ok(asn1::parse_single(bytes.response)?)
                    } else {
                        Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                            "Successful OCSP response does not contain a BasicResponse",
                        )))
                    }
                }
                None => Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                    "Successful OCSP response does not contain a BasicResponse",
                ))),
            },
            MALFORMED_REQUEST_RESPOSNE
            | INTERNAL_ERROR_RESPONSE
            | TRY_LATER_RESPONSE
            | SIG_REQUIRED_RESPONSE
            | UNAUTHORIZED_RESPONSE => Ok(None),
            _ => Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "OCSP response has an unknown status code",
            ))),
        },
    )?;

    if let Some(basic_response) = raw.borrow_basic_response() {
        let num_responses = basic_response.tbs_response_data.responses.len();
        if num_responses != 1 {
            return Err(PyAsn1Error::from(
                exceptions::PyValueError::new_err(format!(
                    "OCSP response contains more than one SINGLERESP structure, which this library does not support. {} found",
                    num_responses
                ))
            ));
        }
    }

    Ok(OCSPResponse {
        raw,
        cached_extensions: None,
        cached_single_extensions: None,
    })
}

#[ouroboros::self_referencing]
struct OwnedRawOCSPResponse {
    data: Arc<[u8]>,
    #[borrows(data)]
    #[covariant]
    value: RawOCSPResponse<'this>,

    #[borrows(data, value)]
    #[covariant]
    basic_response: Option<BasicOCSPResponse<'this>>,
}

#[pyo3::prelude::pyclass]
struct OCSPResponse {
    raw: OwnedRawOCSPResponse,

    cached_extensions: Option<pyo3::PyObject>,
    cached_single_extensions: Option<pyo3::PyObject>,
}

impl OCSPResponse {
    fn requires_successful_response(&self) -> pyo3::PyResult<&BasicOCSPResponse<'_>> {
        match self.raw.borrow_basic_response() {
            Some(b) => Ok(b),
            None => Err(exceptions::PyValueError::new_err(
                "OCSP response status is not successful so the property has no value",
            )),
        }
    }
}

const SUCCESSFUL_RESPONSE: u32 = 0;
const MALFORMED_REQUEST_RESPOSNE: u32 = 1;
const INTERNAL_ERROR_RESPONSE: u32 = 2;
const TRY_LATER_RESPONSE: u32 = 3;
// 4 is unused
const SIG_REQUIRED_RESPONSE: u32 = 5;
const UNAUTHORIZED_RESPONSE: u32 = 6;

#[pyo3::prelude::pymethods]
impl OCSPResponse {
    #[getter]
    fn response_status<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let status = self.raw.borrow_value().response_status.value();
        let attr = if status == SUCCESSFUL_RESPONSE {
            "SUCCESSFUL"
        } else if status == MALFORMED_REQUEST_RESPOSNE {
            "MALFORMED_REQUEST"
        } else if status == INTERNAL_ERROR_RESPONSE {
            "INTERNAL_ERROR"
        } else if status == TRY_LATER_RESPONSE {
            "TRY_LATER"
        } else if status == SIG_REQUIRED_RESPONSE {
            "SIG_REQUIRED"
        } else {
            assert_eq!(status, UNAUTHORIZED_RESPONSE);
            "UNAUTHORIZED"
        };
        py.import("cryptography.x509.ocsp")?
            .getattr("OCSPResponseStatus")?
            .getattr(attr)
    }

    #[getter]
    fn responder_name<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        match resp.tbs_response_data.responder_id {
            ResponderId::ByName(ref name) => x509::parse_name(py, name),
            ResponderId::ByKey(_) => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn responder_key_hash<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        match resp.tbs_response_data.responder_id {
            ResponderId::ByKey(key_hash) => Ok(pyo3::types::PyBytes::new(py, key_hash).as_ref()),
            ResponderId::ByName(_) => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn produced_at<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        x509::chrono_to_py(py, resp.tbs_response_data.produced_at.as_chrono())
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        py.import("cryptography.x509")?.call_method1(
            "ObjectIdentifier",
            (resp.signature_algorithm.oid.to_string(),),
        )
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
            Err(_) => {
                let exc_messsage = format!(
                    "Signature algorithm OID: {} not recognized",
                    self.requires_successful_response()?
                        .signature_algorithm
                        .oid
                        .to_string()
                );
                Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    py.import("cryptography.exceptions")?
                        .call_method1("UnsupportedAlgorithm", (exc_messsage,))?,
                )))
            }
        }
    }

    #[getter]
    fn signature<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
        let resp = self.requires_successful_response()?;
        Ok(pyo3::types::PyBytes::new(py, resp.signature.as_bytes()))
    }

    #[getter]
    fn tbs_response_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::types::PyBytes, PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let result = asn1::write_single(&resp.tbs_response_data);
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn certificates<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let py_certs = pyo3::types::PyList::empty(py);
        let certs = match &resp.certs {
            Some(certs) => certs,
            None => return Ok(py_certs),
        };
        for i in 0..certs.len() {
            // TODO: O(n^2), don't have too many certificates!
            let raw_cert = map_arc_data_ocsp_response(&self.raw, |_data, _resp, basic_response| {
                basic_response
                    .as_ref()
                    .unwrap()
                    .certs
                    .as_ref()
                    .unwrap()
                    .clone()
                    .nth(i)
                    .unwrap()
            });
            py_certs.append(pyo3::PyCell::new(
                py,
                x509::Certificate {
                    raw: raw_cert,
                    cached_extensions: None,
                },
            )?)?;
        }
        Ok(py_certs)
    }

    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        big_asn1_uint_to_py(py, single_resp.cert_id.serial_number)
    }

    #[getter]
    fn issuer_key_hash(&self) -> Result<&[u8], PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        Ok(single_resp.cert_id.issuer_key_hash)
    }

    #[getter]
    fn issuer_name_hash(&self) -> Result<&[u8], PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        Ok(single_resp.cert_id.issuer_name_hash)
    }

    #[getter]
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();

        let hashes = py.import("cryptography.hazmat.primitives.hashes")?;
        match OIDS_TO_HASH.get(&single_resp.cert_id.hash_algorithm.oid) {
            Some(alg_name) => Ok(hashes.getattr(alg_name)?.call0()?),
            None => {
                let exceptions = py.import("cryptography.exceptions")?;
                Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    exceptions.getattr("UnsupportedAlgorithm")?.call1((format!(
                        "Signature algorithm OID: {} not recognized",
                        single_resp.cert_id.hash_algorithm.oid
                    ),))?,
                )))
            }
        }
    }

    #[getter]
    fn certificate_status<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        let attr = match single_resp.cert_status {
            CertStatus::Good(_) => "GOOD",
            CertStatus::Revoked(_) => "REVOKED",
            CertStatus::Unknown(_) => "UNKNOWN",
        };
        py.import("cryptography.x509.ocsp")?
            .getattr("OCSPCertStatus")?
            .getattr(attr)
    }

    #[getter]
    fn revocation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        match single_resp.cert_status {
            CertStatus::Revoked(revoked_info) => {
                x509::chrono_to_py(py, revoked_info.revocation_time.as_chrono())
            }
            CertStatus::Good(_) | CertStatus::Unknown(_) => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn revocation_reason<'p>(&self, py: pyo3::Python<'p>) -> PyAsn1Result<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        match single_resp.cert_status {
            CertStatus::Revoked(revoked_info) => match revoked_info.revocation_reason {
                Some(ref v) => x509::parse_crl_reason_flags(py, v),
                None => Ok(py.None().into_ref(py)),
            },
            CertStatus::Good(_) | CertStatus::Unknown(_) => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn this_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        x509::chrono_to_py(py, single_resp.this_update.as_chrono())
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response();
        match single_resp.next_update {
            Some(v) => x509::chrono_to_py(py, v.as_chrono()),
            None => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        self.requires_successful_response()?;
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self
                .raw
                .borrow_basic_response()
                .as_ref()
                .unwrap()
                .tbs_response_data
                .response_extensions,
            |oid, ext_data| {
                if oid == &*NONCE_OID {
                    // This is a disaster. RFC 2560 says that the contents of the nonce is
                    // just the raw extension value. This is nonsense, since they're always
                    // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                    // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                    // the nonce. For now we just implement the old behavior, even though
                    // it's deranged.
                    Ok(Some(x509_module.call_method1("OCSPNonce", (ext_data,))?))
                } else {
                    Ok(None)
                }
            },
        )
    }

    #[getter]
    fn single_extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        self.requires_successful_response()?;
        let single_resp = self
            .raw
            .borrow_basic_response()
            .as_ref()
            .unwrap()
            .single_response();
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_single_extensions,
            &single_resp.single_extensions,
            |oid, ext_data| {
                if oid == &*SIGNED_CERTIFICATE_TIMESTAMPS_OID {
                    let contents = asn1::parse_single::<&[u8]>(ext_data)?;
                    let scts = x509::parse_scts(py, contents, x509::LogEntryType::Certificate)?;
                    Ok(Some(
                        x509_module
                            .getattr("SignedCertificateTimestamps")?
                            .call1((scts,))?,
                    ))
                } else {
                    x509::parse_crl_entry_ext(py, oid.clone(), ext_data)
                }
            },
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
        let der = py
            .import("cryptography.hazmat.primitives.serialization")?
            .getattr("Encoding")?
            .getattr("DER")?;
        if encoding != der {
            return Err(exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            ));
        }
        let result = asn1::write_single(self.raw.borrow_value());
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn map_arc_data_ocsp_response(
    it: &OwnedRawOCSPResponse,
    f: impl for<'this> FnOnce(
        &'this [u8],
        &RawOCSPResponse<'this>,
        &Option<BasicOCSPResponse<'this>>,
    ) -> x509::RawCertificate<'this>,
) -> x509::OwnedRawCertificate {
    x509::OwnedRawCertificate::new_public(Arc::clone(it.borrow_data()), |inner_it| {
        it.with(|value| {
            f(
                inner_it,
                unsafe { std::mem::transmute(value.value) },
                unsafe { std::mem::transmute(value.basic_response) },
            )
        })
    })
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RawOCSPResponse<'a> {
    response_status: asn1::Enumerated,
    #[explicit(0)]
    response_bytes: Option<ResponseBytes<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct ResponseBytes<'a> {
    response_type: asn1::ObjectIdentifier<'a>,
    response: &'a [u8],
}

#[derive(asn1::Asn1Read)]
struct BasicOCSPResponse<'a> {
    tbs_response_data: ResponseData<'a>,
    signature_algorithm: x509::AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
    #[explicit(0)]
    certs: Option<asn1::SequenceOf<'a, x509::RawCertificate<'a>>>,
}

impl BasicOCSPResponse<'_> {
    fn single_response(&self) -> SingleResponse<'_> {
        self.tbs_response_data.responses.clone().next().unwrap()
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct ResponseData<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    responder_id: ResponderId<'a>,
    produced_at: asn1::GeneralizedTime,
    responses: asn1::SequenceOf<'a, SingleResponse<'a>>,
    #[explicit(1)]
    response_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
enum ResponderId<'a> {
    #[explicit(1)]
    ByName(x509::Name<'a>),
    #[explicit(2)]
    ByKey(&'a [u8]),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct SingleResponse<'a> {
    cert_id: CertID<'a>,
    cert_status: CertStatus,
    this_update: asn1::GeneralizedTime,
    #[explicit(0)]
    next_update: Option<asn1::GeneralizedTime>,
    #[explicit(1)]
    single_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
enum CertStatus {
    #[implicit(0)]
    Good(()),
    #[implicit(1)]
    Revoked(RevokedInfo),
    #[implicit(2)]
    Unknown(()),
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct RevokedInfo {
    revocation_time: asn1::GeneralizedTime,
    #[explicit(0)]
    revocation_reason: Option<x509::CRLReason>,
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "ocsp")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_request))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_response))?;

    Ok(submod)
}
