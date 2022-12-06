// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_byte_slice_to_py_int, oid_to_py_oid, PyAsn1Error, PyAsn1Result};
use crate::x509;
use crate::x509::{certificate, crl, extensions, ocsp, oid, py_to_chrono, sct};
use chrono::Timelike;
use std::sync::Arc;

const BASIC_RESPONSE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 1);

#[pyo3::prelude::pyfunction]
fn load_der_ocsp_response(_py: pyo3::Python<'_>, data: &[u8]) -> Result<OCSPResponse, PyAsn1Error> {
    let raw = OwnedRawOCSPResponse::try_new(Arc::from(data), |data| asn1::parse_single(data))?;

    let response = raw.borrow_value();
    match response.response_status.value() {
        SUCCESSFUL_RESPONSE => match response.response_bytes {
            Some(ref bytes) => {
                if bytes.response_type != BASIC_RESPONSE_OID {
                    return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                        "Successful OCSP response does not contain a BasicResponse",
                    )));
                }
            }
            None => {
                return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                    "Successful OCSP response does not contain a BasicResponse",
                )))
            }
        },
        MALFORMED_REQUEST_RESPOSNE
        | INTERNAL_ERROR_RESPONSE
        | TRY_LATER_RESPONSE
        | SIG_REQUIRED_RESPONSE
        | UNAUTHORIZED_RESPONSE => {}
        _ => {
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                "OCSP response has an unknown status code",
            )))
        }
    };
    Ok(OCSPResponse {
        raw: Arc::new(raw),
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
}

#[pyo3::prelude::pyclass]
struct OCSPResponse {
    raw: Arc<OwnedRawOCSPResponse>,

    cached_extensions: Option<pyo3::PyObject>,
    cached_single_extensions: Option<pyo3::PyObject>,
}

impl OCSPResponse {
    fn requires_successful_response(&self) -> pyo3::PyResult<&BasicOCSPResponse<'_>> {
        match self.raw.borrow_value().response_bytes.as_ref() {
            Some(b) => Ok(b.response.get()),
            None => Err(pyo3::exceptions::PyValueError::new_err(
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
    fn responses(&self) -> Result<OCSPResponseIterator, PyAsn1Error> {
        self.requires_successful_response()?;
        Ok(OCSPResponseIterator {
            contents: OwnedOCSPResponseIteratorData::try_new(Arc::clone(&self.raw), |v| {
                Ok::<_, ()>(
                    v.borrow_value()
                        .response_bytes
                        .as_ref()
                        .unwrap()
                        .response
                        .get()
                        .tbs_response_data
                        .responses
                        .unwrap_read()
                        .clone(),
                )
            })
            .unwrap(),
        })
    }

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
            .getattr(crate::intern!(py, "OCSPResponseStatus"))?
            .getattr(attr)
    }

    #[getter]
    fn responder_name<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        match resp.tbs_response_data.responder_id {
            ResponderId::ByName(ref name) => Ok(x509::parse_name(py, name)?),
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
        oid_to_py_oid(py, &resp.signature_algorithm.oid)
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let sig_oids_to_hash = py
            .import("cryptography.hazmat._oid")?
            .getattr(crate::intern!(py, "_SIG_OIDS_TO_HASH"))?;
        let hash_alg = sig_oids_to_hash.get_item(self.signature_algorithm_oid(py)?);
        match hash_alg {
            Ok(data) => Ok(data),
            Err(_) => {
                let exc_messsage = format!(
                    "Signature algorithm OID: {} not recognized",
                    self.requires_successful_response()?.signature_algorithm.oid
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
    ) -> PyAsn1Result<&'p pyo3::types::PyBytes> {
        let resp = self.requires_successful_response()?;
        let result = asn1::write_single(&resp.tbs_response_data)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn certificates<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let py_certs = pyo3::types::PyList::empty(py);
        let certs = match &resp.certs {
            Some(certs) => certs.unwrap_read(),
            None => return Ok(py_certs),
        };
        for i in 0..certs.len() {
            // TODO: O(n^2), don't have too many certificates!
            let raw_cert = map_arc_data_ocsp_response(&self.raw, |_data, resp| {
                resp.response_bytes
                    .as_ref()
                    .unwrap()
                    .response
                    .get()
                    .certs
                    .as_ref()
                    .unwrap()
                    .unwrap_read()
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
        let single_resp = resp.single_response()?;
        single_resp.py_serial_number(py)
    }

    #[getter]
    fn issuer_key_hash(&self) -> Result<&[u8], PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        Ok(single_resp.cert_id.issuer_key_hash)
    }

    #[getter]
    fn issuer_name_hash(&self) -> Result<&[u8], PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        Ok(single_resp.cert_id.issuer_name_hash)
    }

    #[getter]
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        single_resp.py_hash_algorithm(py)
    }

    #[getter]
    fn certificate_status<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        resp.single_response()?.py_certificate_status(py)
    }

    #[getter]
    fn revocation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        single_resp.py_revocation_time(py)
    }

    #[getter]
    fn revocation_reason<'p>(&self, py: pyo3::Python<'p>) -> PyAsn1Result<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        single_resp.py_revocation_reason(py)
    }

    #[getter]
    fn this_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        single_resp.py_this_update(py)
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let resp = self.requires_successful_response()?;
        let single_resp = resp.single_response()?;
        single_resp.py_next_update(py)
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
                .borrow_value()
                .response_bytes
                .as_ref()
                .unwrap()
                .response
                .get()
                .tbs_response_data
                .response_extensions,
            |oid, ext_data| {
                match oid {
                    &oid::NONCE_OID => {
                        // This is a disaster. RFC 2560 says that the contents of the nonce is
                        // just the raw extension value. This is nonsense, since they're always
                        // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                        // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                        // the nonce. So we try parsing as a TLV and fall back to just using
                        // the raw value.
                        let nonce = asn1::parse_single::<&[u8]>(ext_data).unwrap_or(ext_data);
                        Ok(Some(x509_module.call_method1("OCSPNonce", (nonce,))?))
                    }
                    _ => Ok(None),
                }
            },
        )
    }

    #[getter]
    fn single_extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        self.requires_successful_response()?;
        let single_resp = self
            .raw
            .borrow_value()
            .response_bytes
            .as_ref()
            .unwrap()
            .response
            .get()
            .single_response()?;
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_single_extensions,
            &single_resp.single_extensions,
            |oid, ext_data| match oid {
                &oid::SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
                    let contents = asn1::parse_single::<&[u8]>(ext_data)?;
                    let scts = sct::parse_scts(py, contents, sct::LogEntryType::Certificate)?;
                    Ok(Some(
                        x509_module
                            .getattr(crate::intern!(py, "SignedCertificateTimestamps"))?
                            .call1((scts,))?,
                    ))
                }
                _ => crl::parse_crl_entry_ext(py, oid.clone(), ext_data),
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

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn map_arc_data_ocsp_response(
    it: &OwnedRawOCSPResponse,
    f: impl for<'this> FnOnce(
        &'this [u8],
        &RawOCSPResponse<'this>,
    ) -> certificate::RawCertificate<'this>,
) -> certificate::OwnedRawCertificate {
    certificate::OwnedRawCertificate::new_public(Arc::clone(it.borrow_data()), |inner_it| {
        it.with(|value| f(inner_it, unsafe { std::mem::transmute(value.value) }))
    })
}
fn try_map_arc_data_mut_ocsp_response_iterator<E>(
    it: &mut OwnedOCSPResponseIteratorData,
    f: impl for<'this> FnOnce(
        &'this OwnedRawOCSPResponse,
        &mut asn1::SequenceOf<'this, SingleResponse<'this>>,
    ) -> Result<SingleResponse<'this>, E>,
) -> Result<OwnedSingleResponse, E> {
    OwnedSingleResponse::try_new(Arc::clone(it.borrow_data()), |inner_it| {
        it.with_value_mut(|value| f(inner_it, unsafe { std::mem::transmute(value) }))
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
    response_type: asn1::ObjectIdentifier,
    response: asn1::OctetStringEncoded<BasicOCSPResponse<'a>>,
}

type OCSPCerts<'a> = Option<
    x509::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, certificate::RawCertificate<'a>>,
        asn1::SequenceOfWriter<
            'a,
            certificate::RawCertificate<'a>,
            Vec<certificate::RawCertificate<'a>>,
        >,
    >,
>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct BasicOCSPResponse<'a> {
    tbs_response_data: ResponseData<'a>,
    signature_algorithm: x509::AlgorithmIdentifier<'a>,
    signature: asn1::BitString<'a>,
    #[explicit(0)]
    certs: OCSPCerts<'a>,
}

impl BasicOCSPResponse<'_> {
    fn single_response(&self) -> Result<SingleResponse<'_>, PyAsn1Error> {
        let responses = self.tbs_response_data.responses.unwrap_read();
        let num_responses = responses.len();

        if num_responses != 1 {
            return Err(PyAsn1Error::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "OCSP response contains {} SINGLERESP structures.  Use .response_iter to iterate through them",
                    num_responses
                ))
            ));
        }

        Ok(responses.clone().next().unwrap())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct ResponseData<'a> {
    #[explicit(0)]
    #[default(0)]
    version: u8,
    responder_id: ResponderId<'a>,
    produced_at: asn1::GeneralizedTime,
    responses: x509::Asn1ReadableOrWritable<
        'a,
        asn1::SequenceOf<'a, SingleResponse<'a>>,
        asn1::SequenceOfWriter<'a, SingleResponse<'a>, Vec<SingleResponse<'a>>>,
    >,
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
    cert_id: ocsp::CertID<'a>,
    cert_status: CertStatus,
    this_update: asn1::GeneralizedTime,
    #[explicit(0)]
    next_update: Option<asn1::GeneralizedTime>,
    #[explicit(1)]
    single_extensions: Option<x509::Extensions<'a>>,
}

impl SingleResponse<'_> {
    fn py_serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        big_byte_slice_to_py_int(py, self.cert_id.serial_number.as_bytes())
    }

    fn py_certificate_status<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let attr = match self.cert_status {
            CertStatus::Good(_) => "GOOD",
            CertStatus::Revoked(_) => "REVOKED",
            CertStatus::Unknown(_) => "UNKNOWN",
        };
        py.import("cryptography.x509.ocsp")?
            .getattr(crate::intern!(py, "OCSPCertStatus"))?
            .getattr(attr)
    }

    fn py_hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        let hashes = py.import("cryptography.hazmat.primitives.hashes")?;
        match ocsp::OIDS_TO_HASH.get(&self.cert_id.hash_algorithm.oid) {
            Some(alg_name) => Ok(hashes.getattr(alg_name)?.call0()?),
            None => {
                let exceptions = py.import("cryptography.exceptions")?;
                Err(PyAsn1Error::from(pyo3::PyErr::from_instance(
                    exceptions
                        .getattr(crate::intern!(py, "UnsupportedAlgorithm"))?
                        .call1((format!(
                            "Signature algorithm OID: {} not recognized",
                            self.cert_id.hash_algorithm.oid
                        ),))?,
                )))
            }
        }
    }

    fn py_this_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::chrono_to_py(py, self.this_update.as_chrono())
    }

    fn py_next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        match &self.next_update {
            Some(v) => x509::chrono_to_py(py, v.as_chrono()),
            None => Ok(py.None().into_ref(py)),
        }
    }

    fn py_revocation_reason<'p>(&self, py: pyo3::Python<'p>) -> PyAsn1Result<&'p pyo3::PyAny> {
        match &self.cert_status {
            CertStatus::Revoked(revoked_info) => match revoked_info.revocation_reason {
                Some(ref v) => crl::parse_crl_reason_flags(py, v),
                None => Ok(py.None().into_ref(py)),
            },
            CertStatus::Good(_) | CertStatus::Unknown(_) => Ok(py.None().into_ref(py)),
        }
    }

    fn py_revocation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        match &self.cert_status {
            CertStatus::Revoked(revoked_info) => {
                x509::chrono_to_py(py, revoked_info.revocation_time.as_chrono())
            }
            CertStatus::Good(_) | CertStatus::Unknown(_) => Ok(py.None().into_ref(py)),
        }
    }
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
    revocation_reason: Option<crl::CRLReason>,
}

#[pyo3::prelude::pyfunction]
fn create_ocsp_response(
    py: pyo3::Python<'_>,
    status: &pyo3::PyAny,
    builder: &pyo3::PyAny,
    private_key: &pyo3::PyAny,
    hash_algorithm: &pyo3::PyAny,
) -> PyAsn1Result<OCSPResponse> {
    let response_status = status
        .getattr(crate::intern!(py, "value"))?
        .extract::<u32>()?;

    let py_cert: pyo3::PyRef<'_, x509::Certificate>;
    let py_issuer: pyo3::PyRef<'_, x509::Certificate>;
    let borrowed_cert;
    let py_certs: Option<Vec<pyo3::PyRef<'_, x509::Certificate>>>;
    let response_bytes = if response_status == SUCCESSFUL_RESPONSE {
        let ocsp_mod = py.import("cryptography.x509.ocsp")?;

        let py_single_resp = builder.getattr(crate::intern!(py, "_response"))?;
        py_cert = py_single_resp
            .getattr(crate::intern!(py, "_cert"))?
            .extract()?;
        py_issuer = py_single_resp
            .getattr(crate::intern!(py, "_issuer"))?
            .extract()?;
        let py_cert_hash_algorithm = py_single_resp.getattr(crate::intern!(py, "_algorithm"))?;
        let (responder_cert, responder_encoding): (&pyo3::PyCell<x509::Certificate>, &pyo3::PyAny) =
            builder
                .getattr(crate::intern!(py, "_responder_id"))?
                .extract()?;

        let py_cert_status = py_single_resp.getattr(crate::intern!(py, "_cert_status"))?;
        let cert_status = if py_cert_status
            == ocsp_mod
                .getattr(crate::intern!(py, "OCSPCertStatus"))?
                .getattr(crate::intern!(py, "GOOD"))?
        {
            CertStatus::Good(())
        } else if py_cert_status
            == ocsp_mod
                .getattr(crate::intern!(py, "OCSPCertStatus"))?
                .getattr(crate::intern!(py, "UNKNOWN"))?
        {
            CertStatus::Unknown(())
        } else {
            let revocation_reason = if !py_single_resp
                .getattr(crate::intern!(py, "_revocation_reason"))?
                .is_none()
            {
                let value = py
                    .import("cryptography.hazmat.backends.openssl.decode_asn1")?
                    .getattr(crate::intern!(py, "_CRL_ENTRY_REASON_ENUM_TO_CODE"))?
                    .get_item(py_single_resp.getattr(crate::intern!(py, "_revocation_reason"))?)?
                    .extract::<u32>()?;
                Some(asn1::Enumerated::new(value))
            } else {
                None
            };
            // REVOKED
            let py_revocation_time =
                py_single_resp.getattr(crate::intern!(py, "_revocation_time"))?;
            let revocation_time =
                asn1::GeneralizedTime::new(py_to_chrono(py, py_revocation_time)?)?;
            CertStatus::Revoked(RevokedInfo {
                revocation_time,
                revocation_reason,
            })
        };
        let next_update = if !py_single_resp
            .getattr(crate::intern!(py, "_next_update"))?
            .is_none()
        {
            let py_next_update = py_single_resp.getattr(crate::intern!(py, "_next_update"))?;
            Some(asn1::GeneralizedTime::new(py_to_chrono(
                py,
                py_next_update,
            )?)?)
        } else {
            None
        };
        let py_this_update = py_single_resp.getattr(crate::intern!(py, "_this_update"))?;
        let this_update = asn1::GeneralizedTime::new(py_to_chrono(py, py_this_update)?)?;

        let responses = vec![SingleResponse {
            cert_id: ocsp::CertID::new(py, &py_cert, &py_issuer, py_cert_hash_algorithm)?,
            cert_status,
            next_update,
            this_update,
            single_extensions: None,
        }];

        borrowed_cert = responder_cert.borrow();
        let responder_id = if responder_encoding
            == ocsp_mod
                .getattr(crate::intern!(py, "OCSPResponderEncoding"))?
                .getattr(crate::intern!(py, "HASH"))?
        {
            let sha1 = py
                .import("cryptography.hazmat.primitives.hashes")?
                .getattr(crate::intern!(py, "SHA1"))?
                .call0()?;
            ResponderId::ByKey(ocsp::hash_data(
                py,
                sha1,
                borrowed_cert
                    .raw
                    .borrow_value_public()
                    .tbs_cert
                    .spki
                    .subject_public_key
                    .as_bytes(),
            )?)
        } else {
            ResponderId::ByName(
                borrowed_cert
                    .raw
                    .borrow_value_public()
                    .tbs_cert
                    .subject
                    .clone(),
            )
        };

        let tbs_response_data = ResponseData {
            version: 0,
            produced_at: asn1::GeneralizedTime::new(
                chrono::Utc::now().with_nanosecond(0).unwrap(),
            )?,
            responder_id,
            responses: x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
                responses,
            )),
            response_extensions: x509::common::encode_extensions(
                py,
                builder.getattr(crate::intern!(py, "_extensions"))?,
                extensions::encode_extension,
            )?,
        };

        let sigalg = x509::sign::compute_signature_algorithm(py, private_key, hash_algorithm)?;
        let tbs_bytes = asn1::write_single(&tbs_response_data)?;
        let signature = x509::sign::sign_data(py, private_key, hash_algorithm, &tbs_bytes)?;

        py.import("cryptography.hazmat.backends.openssl.backend")?
            .getattr(crate::intern!(py, "backend"))?
            .call_method1(
                "_check_keys_correspond",
                (
                    responder_cert.call_method0("public_key")?,
                    private_key.call_method0("public_key")?,
                ),
            )?;

        py_certs = builder.getattr(crate::intern!(py, "_certs"))?.extract()?;
        let certs = py_certs.as_ref().map(|py_certs| {
            x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
                py_certs
                    .iter()
                    .map(|c| c.raw.borrow_value_public().clone())
                    .collect(),
            ))
        });

        let basic_resp = BasicOCSPResponse {
            tbs_response_data,
            signature: asn1::BitString::new(signature, 0).unwrap(),
            signature_algorithm: sigalg,
            certs,
        };
        Some(ResponseBytes {
            response_type: (BASIC_RESPONSE_OID).clone(),
            response: asn1::OctetStringEncoded::new(basic_resp),
        })
    } else {
        None
    };

    let resp = RawOCSPResponse {
        response_status: asn1::Enumerated::new(response_status),
        response_bytes,
    };
    let data = asn1::write_single(&resp)?;
    // TODO: extra copy as we round-trip through a slice
    load_der_ocsp_response(py, &data)
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_ocsp_response))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(create_ocsp_response))?;

    Ok(())
}

#[ouroboros::self_referencing]
struct OwnedOCSPResponseIteratorData {
    data: Arc<OwnedRawOCSPResponse>,
    #[borrows(data)]
    #[covariant]
    value: asn1::SequenceOf<'this, SingleResponse<'this>>,
}

#[pyo3::prelude::pyclass]
struct OCSPResponseIterator {
    contents: OwnedOCSPResponseIteratorData,
}

#[pyo3::prelude::pyproto]
impl pyo3::PyIterProtocol<'_> for OCSPResponseIterator {
    fn __iter__(slf: pyo3::PyRef<'p, Self>) -> pyo3::PyRef<'p, Self> {
        slf
    }

    fn __next__(mut slf: pyo3::PyRefMut<'p, Self>) -> Option<OCSPSingleResponse> {
        let single_resp =
            try_map_arc_data_mut_ocsp_response_iterator(&mut slf.contents, |_data, v| {
                match v.next() {
                    Some(single_resp) => Ok(single_resp),
                    None => Err(()),
                }
            })
            .ok()?;
        Some(OCSPSingleResponse { raw: single_resp })
    }
}

#[ouroboros::self_referencing]
struct OwnedSingleResponse {
    data: Arc<OwnedRawOCSPResponse>,
    #[borrows(data)]
    #[covariant]
    value: SingleResponse<'this>,
}

#[pyo3::prelude::pyclass]
struct OCSPSingleResponse {
    raw: OwnedSingleResponse,
}

impl OCSPSingleResponse {
    fn single_response(&self) -> &SingleResponse<'_> {
        self.raw.borrow_value()
    }
}

#[pyo3::prelude::pymethods]
impl OCSPSingleResponse {
    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.single_response().py_serial_number(py)
    }

    #[getter]
    fn issuer_key_hash(&self) -> &[u8] {
        let single_resp = self.single_response();
        single_resp.cert_id.issuer_key_hash
    }

    #[getter]
    fn issuer_name_hash(&self) -> &[u8] {
        let single_resp = self.single_response();
        single_resp.cert_id.issuer_name_hash
    }

    #[getter]
    fn hash_algorithm<'p>(&self, py: pyo3::Python<'p>) -> Result<&'p pyo3::PyAny, PyAsn1Error> {
        self.single_response().py_hash_algorithm(py)
    }

    #[getter]
    fn certificate_status<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.single_response().py_certificate_status(py)
    }

    #[getter]
    fn revocation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.single_response().py_revocation_time(py)
    }

    #[getter]
    fn revocation_reason<'p>(&self, py: pyo3::Python<'p>) -> PyAsn1Result<&'p pyo3::PyAny> {
        self.single_response().py_revocation_reason(py)
    }

    #[getter]
    fn this_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.single_response().py_this_update(py)
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        self.single_response().py_next_update(py)
    }
}
