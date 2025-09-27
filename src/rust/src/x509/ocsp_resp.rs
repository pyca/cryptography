// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::sync::Arc;

use cryptography_x509::ocsp_resp::{
    self, OCSPResponse as RawOCSPResponse, SingleResponse, SingleResponse as RawSingleResponse,
};
use cryptography_x509::{common, oid};
use pyo3::types::{PyAnyMethods, PyBytesMethods, PyListMethods};

use crate::asn1::{big_byte_slice_to_py_int, oid_to_py_oid, py_uint_to_big_endian_bytes};
use crate::error::{CryptographyError, CryptographyResult};
use crate::utils::cstr_from_literal;
use crate::x509::{certificate, crl, extensions, ocsp, py_to_datetime, sct};
use crate::{exceptions, types, x509};

const BASIC_RESPONSE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 1);

#[pyo3::pyfunction]
pub(crate) fn load_der_ocsp_response(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> Result<OCSPResponse, CryptographyError> {
    let raw = OwnedOCSPResponse::try_new(data, |data| asn1::parse_single(data.as_bytes(py)))?;

    let response = raw.borrow_dependent();
    match response.response_status.value() {
        SUCCESSFUL_RESPONSE => match response.response_bytes {
            Some(ref bytes) => {
                if bytes.response_type != BASIC_RESPONSE_OID {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Successful OCSP response does not contain a BasicResponse",
                        ),
                    ));
                }
            }
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "Successful OCSP response does not contain a BasicResponse",
                    ),
                ))
            }
        },
        MALFORMED_REQUEST_RESPONSE
        | INTERNAL_ERROR_RESPONSE
        | TRY_LATER_RESPONSE
        | SIG_REQUIRED_RESPONSE
        | UNAUTHORIZED_RESPONSE => {}
        _ => {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("OCSP response has an unknown status code"),
            ))
        }
    };
    Ok(OCSPResponse {
        raw: Arc::new(raw),
        cached_extensions: pyo3::sync::PyOnceLock::new(),
        cached_single_extensions: pyo3::sync::PyOnceLock::new(),
    })
}

self_cell::self_cell!(
    struct OwnedOCSPResponse {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawOCSPResponse,
    }
);

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.ocsp")]
pub(crate) struct OCSPResponse {
    raw: Arc<OwnedOCSPResponse>,

    cached_extensions: pyo3::sync::PyOnceLock<pyo3::Py<pyo3::PyAny>>,
    cached_single_extensions: pyo3::sync::PyOnceLock<pyo3::Py<pyo3::PyAny>>,
}

impl OCSPResponse {
    fn requires_successful_response(&self) -> pyo3::PyResult<&ocsp_resp::BasicOCSPResponse<'_>> {
        match self.raw.borrow_dependent().response_bytes.as_ref() {
            Some(b) => Ok(b.response.get()),
            None => Err(pyo3::exceptions::PyValueError::new_err(
                "OCSP response status is not successful so the property has no value",
            )),
        }
    }
}

const SUCCESSFUL_RESPONSE: u32 = 0;
const MALFORMED_REQUEST_RESPONSE: u32 = 1;
const INTERNAL_ERROR_RESPONSE: u32 = 2;
const TRY_LATER_RESPONSE: u32 = 3;
// 4 is unused
const SIG_REQUIRED_RESPONSE: u32 = 5;
const UNAUTHORIZED_RESPONSE: u32 = 6;

#[pyo3::pymethods]
impl OCSPResponse {
    #[getter]
    fn responses(&self) -> Result<OCSPResponseIterator, CryptographyError> {
        self.requires_successful_response()?;
        Ok(OCSPResponseIterator {
            contents: OwnedOCSPResponseIteratorData::try_new(Arc::clone(&self.raw), |v| {
                Ok::<_, ()>(
                    v.borrow_dependent()
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
    fn response_status<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let status = self.raw.borrow_dependent().response_status.value();
        let attr = if status == SUCCESSFUL_RESPONSE {
            "SUCCESSFUL"
        } else if status == MALFORMED_REQUEST_RESPONSE {
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
        types::OCSP_RESPONSE_STATUS.get(py)?.getattr(attr)
    }

    #[getter]
    fn responder_name<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        match resp.tbs_response_data.responder_id {
            ocsp_resp::ResponderId::ByName(ref name) => {
                Ok(x509::parse_name(py, name.unwrap_read())?)
            }
            ocsp_resp::ResponderId::ByKey(_) => Ok(py.None().into_bound(py)),
        }
    }

    #[getter]
    fn responder_key_hash<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        match resp.tbs_response_data.responder_id {
            ocsp_resp::ResponderId::ByKey(key_hash) => {
                Ok(pyo3::types::PyBytes::new(py, key_hash).into_any())
            }
            ocsp_resp::ResponderId::ByName(_) => Ok(py.None().into_bound(py)),
        }
    }

    #[getter]
    fn produced_at<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to produced_at_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let resp = self.requires_successful_response()?;
        x509::datetime_to_py(py, resp.tbs_response_data.produced_at.as_datetime())
    }

    #[getter]
    fn produced_at_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        x509::datetime_to_py_utc(py, resp.tbs_response_data.produced_at.as_datetime())
    }

    #[getter]
    fn signature_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        oid_to_py_oid(py, resp.signature_algorithm.oid())
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        let hash_alg = types::SIG_OIDS_TO_HASH
            .get(py)?
            .get_item(self.signature_algorithm_oid(py)?);
        match hash_alg {
            Ok(data) => Ok(data),
            Err(_) => {
                let exc_message = format!(
                    "Signature algorithm OID: {} not recognized",
                    self.requires_successful_response()?
                        .signature_algorithm
                        .oid()
                );
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err(exc_message),
                ))
            }
        }
    }

    #[getter]
    fn signature<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let resp = self.requires_successful_response()?;
        Ok(pyo3::types::PyBytes::new(py, resp.signature.as_bytes()))
    }

    #[getter]
    fn tbs_response_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let resp = self.requires_successful_response()?;
        let result = asn1::write_single(&resp.tbs_response_data)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }

    #[getter]
    fn certificates<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyList>> {
        let resp = self.requires_successful_response()?;
        let py_certs = pyo3::types::PyList::empty(py);
        let certs = match &resp.certs {
            Some(certs) => certs.unwrap_read(),
            None => return Ok(py_certs),
        };
        for i in 0..certs.len() {
            // TODO: O(n^2), don't have too many certificates!
            let raw_cert = map_arc_data_ocsp_response(py, &self.raw, |_data, resp| {
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
            py_certs.append(pyo3::Bound::new(
                py,
                x509::certificate::Certificate {
                    raw: raw_cert,
                    cached_extensions: pyo3::sync::PyOnceLock::new(),
                },
            )?)?;
        }
        Ok(py_certs)
    }

    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_serial_number(&single_resp, py)
    }

    #[getter]
    fn issuer_key_hash(&self) -> Result<&[u8], CryptographyError> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        Ok(single_resp.cert_id.issuer_key_hash)
    }

    #[getter]
    fn issuer_name_hash(&self) -> Result<&[u8], CryptographyError> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        Ok(single_resp.cert_id.issuer_name_hash)
    }

    #[getter]
    fn hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_hash_algorithm(&single_resp, py)
    }

    #[getter]
    fn certificate_status<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_certificate_status(&single_resp, py)
    }

    #[getter]
    fn revocation_time<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to revocation_time_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_revocation_time(&single_resp, py)
    }

    #[getter]
    fn revocation_time_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_revocation_time_utc(&single_resp, py)
    }

    #[getter]
    fn revocation_reason<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_revocation_reason(&single_resp, py)
    }

    #[getter]
    fn this_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to this_update_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_this_update(&single_resp, py)
    }

    #[getter]
    fn this_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_this_update_utc(&single_resp, py)
    }

    #[getter]
    fn next_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to next_update_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_next_update(&single_resp, py)
    }

    #[getter]
    fn next_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let resp = self.requires_successful_response()?;
        let single_resp = single_response(resp)?;
        singleresp_py_next_update_utc(&single_resp, py)
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
        self.requires_successful_response()?;

        let response_data = &self
            .raw
            .borrow_dependent()
            .response_bytes
            .as_ref()
            .unwrap()
            .response
            .get()
            .tbs_response_data;

        x509::parse_and_cache_extensions(
            py,
            &self.cached_extensions,
            &response_data.raw_response_extensions,
            |ext| {
                match &ext.extn_id {
                    &oid::NONCE_OID => {
                        // This is a disaster. RFC 2560 says that the contents of the nonce is
                        // just the raw extension value. This is nonsense, since they're always
                        // supposed to be ASN.1 TLVs. RFC 6960 correctly specifies that the
                        // nonce is an OCTET STRING, and so you should unwrap the TLV to get
                        // the nonce. So we try parsing as a TLV and fall back to just using
                        // the raw value.
                        let nonce = ext.value::<&[u8]>().unwrap_or(ext.extn_value);
                        Ok(Some(types::OCSP_NONCE.get(py)?.call1((nonce,))?))
                    }
                    _ => Ok(None),
                }
            },
        )
    }

    #[getter]
    fn single_extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
        self.requires_successful_response()?;
        let single_resp = single_response(
            self.raw
                .borrow_dependent()
                .response_bytes
                .as_ref()
                .unwrap()
                .response
                .get(),
        )?;

        x509::parse_and_cache_extensions(
            py,
            &self.cached_single_extensions,
            &single_resp.raw_single_extensions,
            |ext| match &ext.extn_id {
                &oid::SIGNED_CERTIFICATE_TIMESTAMPS_OID => {
                    let contents = ext.value::<&[u8]>()?;
                    let scts = sct::parse_scts(py, contents, sct::LogEntryType::Certificate)?;
                    Ok(Some(
                        types::SIGNED_CERTIFICATE_TIMESTAMPS
                            .get(py)?
                            .call1((scts,))?,
                    ))
                }
                _ => crl::parse_crl_entry_ext(py, ext),
            },
        )
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !encoding.is(&types::ENCODING_DER.get(py)?) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "The only allowed encoding value is Encoding.DER",
            )
            .into());
        }
        let result = asn1::write_single(self.raw.borrow_dependent())?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn map_arc_data_ocsp_response(
    py: pyo3::Python<'_>,
    it: &OwnedOCSPResponse,
    f: impl for<'this> FnOnce(
        &'this [u8],
        &ocsp_resp::OCSPResponse<'this>,
    ) -> cryptography_x509::certificate::Certificate<'this>,
) -> certificate::OwnedCertificate {
    certificate::OwnedCertificate::new(it.borrow_owner().clone_ref(py), |inner_it| {
        it.with_dependent(|_, value| {
            // SAFETY: This is safe because `Arc::clone` ensures the data is
            // alive, but Rust doesn't understand the lifetime relationship it
            // produces. Open-coded implementation of the API discussed in
            // https://github.com/joshua-maros/ouroboros/issues/38
            f(inner_it.as_bytes(py), unsafe {
                std::mem::transmute::<&ocsp_resp::OCSPResponse<'_>, &ocsp_resp::OCSPResponse<'_>>(
                    value,
                )
            })
        })
    })
}
fn try_map_arc_data_mut_ocsp_response_iterator<E>(
    it: &mut OwnedOCSPResponseIteratorData,
    f: impl for<'this> FnOnce(
        &'this OwnedOCSPResponse,
        &mut asn1::SequenceOf<'this, ocsp_resp::SingleResponse<'this>>,
    ) -> Result<ocsp_resp::SingleResponse<'this>, E>,
) -> Result<OwnedSingleResponse, E> {
    OwnedSingleResponse::try_new(Arc::clone(it.borrow_owner()), |inner_it| {
        it.with_dependent_mut(|_, value| {
            // SAFETY: This is safe because `Arc::clone` ensures the data is
            // alive, but Rust doesn't understand the lifetime relationship it
            // produces. Open-coded implementation of the API discussed in
            // https://github.com/joshua-maros/ouroboros/issues/38
            f(inner_it, unsafe {
                std::mem::transmute::<
                    &mut asn1::SequenceOf<'_, ocsp_resp::SingleResponse<'_>>,
                    &mut asn1::SequenceOf<'_, ocsp_resp::SingleResponse<'_>>,
                >(value)
            })
        })
    })
}

fn single_response<'a>(
    resp: &ocsp_resp::BasicOCSPResponse<'a>,
) -> Result<ocsp_resp::SingleResponse<'a>, CryptographyError> {
    let responses = resp.tbs_response_data.responses.unwrap_read();
    let num_responses = responses.len();

    if num_responses != 1 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "OCSP response contains {num_responses} SINGLERESP structures.  Use .response_iter to iterate through them"
            ))
        ));
    }

    Ok(responses.clone().next().unwrap())
}

fn singleresp_py_serial_number<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    big_byte_slice_to_py_int(py, resp.cert_id.serial_number.as_bytes())
}

fn singleresp_py_certificate_status<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let attr = match resp.cert_status {
        ocsp_resp::CertStatus::Good(_) => pyo3::intern!(py, "GOOD"),
        ocsp_resp::CertStatus::Revoked(_) => pyo3::intern!(py, "REVOKED"),
        ocsp_resp::CertStatus::Unknown(_) => pyo3::intern!(py, "UNKNOWN"),
    };
    types::OCSP_CERT_STATUS.get(py)?.getattr(attr)
}

fn singleresp_py_hash_algorithm<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
    match ocsp::ALGORITHM_PARAMETERS_TO_HASH.get(&resp.cert_id.hash_algorithm.params) {
        Some(alg_name) => Ok(types::HASHES_MODULE.get(py)?.getattr(*alg_name)?.call0()?),
        None => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err(format!(
                "Signature algorithm OID: {} not recognized",
                resp.cert_id.hash_algorithm.oid()
            )),
        )),
    }
}

fn singleresp_py_this_update<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    x509::datetime_to_py(py, resp.this_update.as_datetime())
}

fn singleresp_py_this_update_utc<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    x509::datetime_to_py_utc(py, resp.this_update.as_datetime())
}

fn singleresp_py_next_update<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match &resp.next_update {
        Some(v) => x509::datetime_to_py(py, v.as_datetime()),
        None => Ok(py.None().into_bound(py)),
    }
}

fn singleresp_py_next_update_utc<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match &resp.next_update {
        Some(v) => x509::datetime_to_py_utc(py, v.as_datetime()),
        None => Ok(py.None().into_bound(py)),
    }
}

fn singleresp_py_revocation_reason<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match &resp.cert_status {
        ocsp_resp::CertStatus::Revoked(revoked_info) => match revoked_info.revocation_reason {
            Some(ref v) => Ok(crl::parse_crl_reason_flags(py, v)?),
            None => Ok(py.None().into_bound(py)),
        },
        ocsp_resp::CertStatus::Good(_) | ocsp_resp::CertStatus::Unknown(_) => {
            Ok(py.None().into_bound(py))
        }
    }
}

fn singleresp_py_revocation_time<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match &resp.cert_status {
        ocsp_resp::CertStatus::Revoked(revoked_info) => {
            x509::datetime_to_py(py, revoked_info.revocation_time.as_datetime())
        }
        ocsp_resp::CertStatus::Good(_) | ocsp_resp::CertStatus::Unknown(_) => {
            Ok(py.None().into_bound(py))
        }
    }
}

fn singleresp_py_revocation_time_utc<'p>(
    resp: &ocsp_resp::SingleResponse<'_>,
    py: pyo3::Python<'p>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    match &resp.cert_status {
        ocsp_resp::CertStatus::Revoked(revoked_info) => {
            x509::datetime_to_py_utc(py, revoked_info.revocation_time.as_datetime())
        }
        ocsp_resp::CertStatus::Good(_) | ocsp_resp::CertStatus::Unknown(_) => {
            Ok(py.None().into_bound(py))
        }
    }
}

#[pyo3::pyfunction]
pub(crate) fn create_ocsp_response(
    py: pyo3::Python<'_>,
    status: &pyo3::Bound<'_, pyo3::PyAny>,
    builder: &pyo3::Bound<'_, pyo3::PyAny>,
    private_key: &pyo3::Bound<'_, pyo3::PyAny>,
    hash_algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<OCSPResponse> {
    let response_status = status
        .getattr(pyo3::intern!(py, "value"))?
        .extract::<u32>()?;

    let borrowed_cert;
    let py_certs: Option<Vec<pyo3::PyRef<'_, x509::certificate::Certificate>>>;
    if response_status != SUCCESSFUL_RESPONSE {
        let resp = ocsp_resp::OCSPResponse {
            response_status: asn1::Enumerated::new(response_status),
            response_bytes: None,
        };
        let data = asn1::write_single(&resp)?;
        return load_der_ocsp_response(py, pyo3::types::PyBytes::new(py, &data).unbind());
    }

    let py_single_resp = builder.getattr(pyo3::intern!(py, "_response"))?;
    let py_cert_hash_algorithm = py_single_resp.getattr(pyo3::intern!(py, "_algorithm"))?;
    let (responder_cert, responder_encoding): (
        pyo3::Bound<'_, x509::certificate::Certificate>,
        pyo3::Bound<'_, pyo3::PyAny>,
    ) = builder
        .getattr(pyo3::intern!(py, "_responder_id"))?
        .extract()?;

    let py_cert_status = py_single_resp.getattr(pyo3::intern!(py, "_cert_status"))?;
    let cert_status = if py_cert_status.is(&types::OCSP_CERT_STATUS_GOOD.get(py)?) {
        ocsp_resp::CertStatus::Good(())
    } else if py_cert_status.is(&types::OCSP_CERT_STATUS_UNKNOWN.get(py)?) {
        ocsp_resp::CertStatus::Unknown(())
    } else {
        let revocation_reason = if !py_single_resp
            .getattr(pyo3::intern!(py, "_revocation_reason"))?
            .is_none()
        {
            let value = types::CRL_ENTRY_REASON_ENUM_TO_CODE
                .get(py)?
                .get_item(py_single_resp.getattr(pyo3::intern!(py, "_revocation_reason"))?)?
                .extract::<u32>()?;
            Some(asn1::Enumerated::new(value))
        } else {
            None
        };
        // REVOKED
        let py_revocation_time = py_single_resp
            .getattr(pyo3::intern!(py, "_revocation_time"))?
            .extract()?;
        let revocation_time =
            asn1::X509GeneralizedTime::new(py_to_datetime(py, py_revocation_time)?)?;
        ocsp_resp::CertStatus::Revoked(ocsp_resp::RevokedInfo {
            revocation_time,
            revocation_reason,
        })
    };
    let next_update = if !py_single_resp
        .getattr(pyo3::intern!(py, "_next_update"))?
        .is_none()
    {
        let py_next_update = py_single_resp
            .getattr(pyo3::intern!(py, "_next_update"))?
            .extract()?;
        Some(asn1::X509GeneralizedTime::new(py_to_datetime(
            py,
            py_next_update,
        )?)?)
    } else {
        None
    };
    let py_this_update = py_single_resp
        .getattr(pyo3::intern!(py, "_this_update"))?
        .extract()?;
    let this_update = asn1::X509GeneralizedTime::new(py_to_datetime(py, py_this_update)?)?;

    let ka_vec = cryptography_keepalive::KeepAlive::new();
    let ka_bytes = cryptography_keepalive::KeepAlive::new();

    // Declare outside the if-block so the lifetimes are right.
    let (py_cert, py_issuer, issuer_name_hash, issuer_key_hash, serial_number_bytes): (
        pyo3::PyRef<'_, x509::certificate::Certificate>,
        pyo3::PyRef<'_, x509::certificate::Certificate>,
        pyo3::pybacked::PyBackedBytes,
        pyo3::pybacked::PyBackedBytes,
        pyo3::pybacked::PyBackedBytes,
    );
    let single_resp_resp = py_single_resp.getattr(pyo3::intern!(py, "_resp"))?;
    let cert_id = if !single_resp_resp.is_none() {
        (py_cert, py_issuer) = single_resp_resp.extract()?;
        ocsp::certid_new(py, &ka_bytes, &py_cert, &py_issuer, &py_cert_hash_algorithm)?
    } else {
        let py_serial: pyo3::Bound<'_, pyo3::types::PyInt>;
        (issuer_name_hash, issuer_key_hash, py_serial) = py_single_resp
            .getattr(pyo3::intern!(py, "_resp_hash"))?
            .extract()?;
        serial_number_bytes = py_uint_to_big_endian_bytes(py, py_serial)?;
        let serial_number = asn1::BigInt::new(&serial_number_bytes).unwrap();
        ocsp::certid_new_from_hash(
            py,
            &issuer_name_hash,
            &issuer_key_hash,
            serial_number,
            py_cert_hash_algorithm,
        )?
    };

    let responses = vec![SingleResponse {
        cert_id,
        cert_status,
        next_update,
        this_update,
        raw_single_extensions: None,
    }];

    borrowed_cert = responder_cert.borrow();
    let by_key_hash;
    let responder_id = if responder_encoding.is(&types::OCSP_RESPONDER_ENCODING_HASH.get(py)?) {
        let sha1 = types::SHA1.get(py)?.call0()?;
        by_key_hash = ocsp::hash_data(
            py,
            &sha1,
            borrowed_cert
                .raw
                .borrow_dependent()
                .tbs_cert
                .spki
                .subject_public_key
                .as_bytes(),
        )?;
        ocsp_resp::ResponderId::ByKey(by_key_hash.as_bytes())
    } else {
        ocsp_resp::ResponderId::ByName(
            borrowed_cert
                .raw
                .borrow_dependent()
                .tbs_cert
                .subject
                .clone(),
        )
    };

    let tbs_response_data = ocsp_resp::ResponseData {
        version: 0,
        produced_at: asn1::X509GeneralizedTime::new(x509::common::datetime_now(py)?)?,
        responder_id,
        responses: common::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
            responses,
        )),
        raw_response_extensions: x509::common::encode_extensions(
            py,
            &ka_vec,
            &ka_bytes,
            &builder.getattr(pyo3::intern!(py, "_extensions"))?,
            extensions::encode_extension,
        )?,
    };

    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        py.None().into_bound(py),
    )?;
    let tbs_bytes = asn1::write_single(&tbs_response_data)?;
    let signature = x509::sign::sign_data(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        py.None().into_bound(py),
        None,
        &tbs_bytes,
    )?;

    if !responder_cert
        .call_method0(pyo3::intern!(py, "public_key"))?
        .eq(private_key.call_method0(pyo3::intern!(py, "public_key"))?)?
    {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Certificate public key and provided private key do not match",
            ),
        ));
    }

    py_certs = builder.getattr(pyo3::intern!(py, "_certs"))?.extract()?;
    let certs = py_certs.as_ref().map(|py_certs| {
        common::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(
            py_certs
                .iter()
                .map(|c| c.raw.borrow_dependent().clone())
                .collect(),
        ))
    });

    let basic_resp = ocsp_resp::BasicOCSPResponse {
        tbs_response_data,
        signature: asn1::BitString::new(&signature, 0).unwrap(),
        signature_algorithm: sigalg,
        certs,
    };
    let response_bytes = Some(ocsp_resp::ResponseBytes {
        response_type: (BASIC_RESPONSE_OID).clone(),
        response: asn1::OctetStringEncoded::new(basic_resp),
    });

    let resp = ocsp_resp::OCSPResponse {
        response_status: asn1::Enumerated::new(SUCCESSFUL_RESPONSE),
        response_bytes,
    };
    let data = asn1::write_single(&resp)?;
    load_der_ocsp_response(py, pyo3::types::PyBytes::new(py, &data).unbind())
}

type RawOCSPResponseIterator<'a> = asn1::SequenceOf<'a, SingleResponse<'a>>;

self_cell::self_cell!(
    struct OwnedOCSPResponseIteratorData {
        owner: Arc<OwnedOCSPResponse>,
        #[covariant]
        dependent: RawOCSPResponseIterator,
    }
);

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.ocsp")]
struct OCSPResponseIterator {
    contents: OwnedOCSPResponseIteratorData,
}

#[pyo3::pymethods]
impl OCSPResponseIterator {
    fn __iter__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<OCSPSingleResponse> {
        let single_resp =
            try_map_arc_data_mut_ocsp_response_iterator(&mut self.contents, |_data, v| {
                match v.next() {
                    Some(single_resp) => Ok(single_resp),
                    None => Err(()),
                }
            })
            .ok()?;
        Some(OCSPSingleResponse { raw: single_resp })
    }
}

self_cell::self_cell!(
    struct OwnedSingleResponse {
        owner: Arc<OwnedOCSPResponse>,
        #[covariant]
        dependent: RawSingleResponse,
    }
);

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.ocsp")]
pub(crate) struct OCSPSingleResponse {
    raw: OwnedSingleResponse,
}

impl OCSPSingleResponse {
    fn single_response(&self) -> &SingleResponse<'_> {
        self.raw.borrow_dependent()
    }
}

#[pyo3::pymethods]
impl OCSPSingleResponse {
    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        singleresp_py_serial_number(self.single_response(), py)
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
    fn hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> Result<pyo3::Bound<'p, pyo3::PyAny>, CryptographyError> {
        let single_resp = self.single_response();
        singleresp_py_hash_algorithm(single_resp, py)
    }

    #[getter]
    fn certificate_status<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let single_resp = self.single_response();
        singleresp_py_certificate_status(single_resp, py)
    }

    #[getter]
    fn revocation_time<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to revocation_time_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let single_resp = self.single_response();
        singleresp_py_revocation_time(single_resp, py)
    }

    #[getter]
    fn revocation_time_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let single_resp = self.single_response();
        singleresp_py_revocation_time_utc(single_resp, py)
    }

    #[getter]
    fn revocation_reason<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let single_resp = self.single_response();
        singleresp_py_revocation_reason(single_resp, py)
    }

    #[getter]
    fn this_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to revocation_time_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let single_resp = self.single_response();
        singleresp_py_this_update(single_resp, py)
    }

    #[getter]
    fn this_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let single_resp = self.single_response();
        singleresp_py_this_update_utc(single_resp, py)
    }

    #[getter]
    fn next_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_43.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to next_update_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        let single_resp = self.single_response();
        singleresp_py_next_update(single_resp, py)
    }

    #[getter]
    fn next_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let single_resp = self.single_response();
        singleresp_py_next_update_utc(single_resp, py)
    }
}
