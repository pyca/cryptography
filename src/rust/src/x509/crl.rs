// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::sync::Arc;

use cryptography_x509::common::{self, Asn1Read};
use cryptography_x509::crl::{
    self, CertificateRevocationList as RawCertificateRevocationList,
    RevokedCertificate as RawRevokedCertificate,
};
use cryptography_x509::extensions::{Extension, IssuerAlternativeName};
use cryptography_x509::{name, oid};
use pyo3::types::{PyAnyMethods, PyListMethods, PySliceMethods};

use crate::asn1::{
    big_byte_slice_to_py_int, encode_der_data, oid_to_py_oid, py_uint_to_big_endian_bytes,
};
use crate::backend::hashes::Hash;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::cstr_from_literal;
use crate::x509::{certificate, extensions, sign};
use crate::{exceptions, types, x509};

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_der_x509_crl(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> Result<CertificateRevocationList, CryptographyError> {
    let _ = backend;

    let owned = OwnedCertificateRevocationList::try_new(data, |data| {
        asn1::parse_single(data.as_bytes(py))
    })?;

    let version = owned.borrow_dependent().tbs_cert_list.version.unwrap_or(1);
    if version != 1 {
        return Err(CryptographyError::from(
            exceptions::InvalidVersion::new_err((
                format!("{version} is not a valid CRL version"),
                version,
            )),
        ));
    }

    Ok(CertificateRevocationList {
        owned: Arc::new(owned),
        revoked_certs: pyo3::sync::GILOnceCell::new(),
        cached_extensions: pyo3::sync::GILOnceCell::new(),
    })
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, backend=None))]
pub(crate) fn load_pem_x509_crl(
    py: pyo3::Python<'_>,
    data: &[u8],
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> Result<CertificateRevocationList, CryptographyError> {
    let _ = backend;

    let block = x509::find_in_pem(
        data,
        |p| p.tag() == "X509 CRL",
        "Valid PEM but no BEGIN X509 CRL/END X509 delimiters. Are you sure this is a CRL?",
    )?;
    load_der_x509_crl(
        py,
        pyo3::types::PyBytes::new(py, block.contents()).unbind(),
        None,
    )
}

self_cell::self_cell!(
    struct OwnedCertificateRevocationList {
        owner: pyo3::Py<pyo3::types::PyBytes>,
        #[covariant]
        dependent: RawCertificateRevocationList,
    }
);

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.x509")]
pub(crate) struct CertificateRevocationList {
    owned: Arc<OwnedCertificateRevocationList>,

    revoked_certs: pyo3::sync::GILOnceCell<Vec<OwnedRevokedCertificate>>,
    cached_extensions: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

impl CertificateRevocationList {
    fn public_bytes_der(&self) -> CryptographyResult<Vec<u8>> {
        Ok(asn1::write_single(self.owned.borrow_dependent())?)
    }

    fn revoked_cert(&self, py: pyo3::Python<'_>, idx: usize) -> RevokedCertificate {
        RevokedCertificate {
            owned: self.revoked_certs.get(py).unwrap()[idx].clone(),
            cached_extensions: pyo3::sync::GILOnceCell::new(),
        }
    }

    fn len(&self) -> usize {
        self.owned
            .borrow_dependent()
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .map_or(0, |v| v.unwrap_read().len())
    }
}

#[pyo3::pymethods]
impl CertificateRevocationList {
    fn __eq__(&self, other: pyo3::PyRef<'_, CertificateRevocationList>) -> bool {
        self.owned.borrow_dependent() == other.owned.borrow_dependent()
    }

    fn __len__(&self) -> usize {
        self.len()
    }

    fn __iter__(&self) -> CRLIterator {
        CRLIterator {
            contents: OwnedCRLIteratorData::try_new(Arc::clone(&self.owned), |v| {
                Ok::<_, ()>(
                    v.borrow_dependent()
                        .tbs_cert_list
                        .revoked_certificates
                        .as_ref()
                        .map(|v| v.unwrap_read().clone()),
                )
            })
            .unwrap(),
        }
    }

    fn __getitem__<'p>(
        &self,
        py: pyo3::Python<'p>,
        idx: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.revoked_certs.get_or_init(py, || {
            let mut revoked_certs = vec![];
            let mut it = self.__iter__();
            while let Some(c) = it.__next__() {
                revoked_certs.push(c.owned);
            }
            revoked_certs
        });

        if idx.is_instance_of::<pyo3::types::PySlice>() {
            let indices = idx
                .downcast::<pyo3::types::PySlice>()?
                .indices(self.len().try_into().unwrap())?;
            let result = pyo3::types::PyList::empty(py);
            for i in (indices.start..indices.stop).step_by(indices.step.try_into().unwrap()) {
                let revoked_cert = pyo3::Bound::new(py, self.revoked_cert(py, i as usize))?;
                result.append(revoked_cert)?;
            }
            Ok(result.into_any())
        } else {
            let mut idx = idx.extract::<isize>()?;
            if idx < 0 {
                idx += self.len() as isize;
            }
            if idx >= (self.len() as isize) || idx < 0 {
                return Err(pyo3::exceptions::PyIndexError::new_err(()));
            }
            Ok(pyo3::Bound::new(py, self.revoked_cert(py, idx as usize))?.into_any())
        }
    }

    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = self.public_bytes_der()?;

        let mut h = Hash::new(py, &algorithm, None)?;
        h.update_bytes(&data)?;
        Ok(h.finalize(py)?)
    }

    #[getter]
    fn signature_algorithm_oid<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        oid_to_py_oid(py, self.owned.borrow_dependent().signature_algorithm.oid())
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let oid = self.signature_algorithm_oid(py)?;
        match types::SIG_OIDS_TO_HASH.get(py)?.get_item(oid) {
            Ok(v) => Ok(v),
            Err(_) => Err(exceptions::UnsupportedAlgorithm::new_err(format!(
                "Signature algorithm OID: {} not recognized",
                self.owned.borrow_dependent().signature_algorithm.oid()
            ))),
        }
    }

    #[getter]
    fn signature_algorithm_parameters<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        sign::identify_signature_algorithm_parameters(
            py,
            &self.owned.borrow_dependent().signature_algorithm,
        )
    }

    #[getter]
    fn signature(&self) -> &[u8] {
        self.owned.borrow_dependent().signature_value.as_bytes()
    }

    #[getter]
    fn tbs_certlist_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let b = asn1::write_single(&self.owned.borrow_dependent().tbs_cert_list)?;
        Ok(pyo3::types::PyBytes::new(py, &b))
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let result = asn1::write_single(self.owned.borrow_dependent())?;

        encode_der_data(py, "X509 CRL".to_string(), result, &encoding)
    }

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        Ok(x509::parse_name(
            py,
            self.owned
                .borrow_dependent()
                .tbs_cert_list
                .issuer
                .unwrap_read(),
        )?)
    }

    #[getter]
    fn next_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_42.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to next_update_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        match &self.owned.borrow_dependent().tbs_cert_list.next_update {
            Some(t) => x509::datetime_to_py(py, t.as_datetime()),
            None => Ok(py.None().into_bound(py)),
        }
    }

    #[getter]
    fn next_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match &self.owned.borrow_dependent().tbs_cert_list.next_update {
            Some(t) => x509::datetime_to_py_utc(py, t.as_datetime()),
            None => Ok(py.None().into_bound(py)),
        }
    }

    #[getter]
    fn last_update<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_42.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to last_update_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        x509::datetime_to_py(
            py,
            self.owned
                .borrow_dependent()
                .tbs_cert_list
                .this_update
                .as_datetime(),
        )
    }

    #[getter]
    fn last_update_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        x509::datetime_to_py_utc(
            py,
            self.owned
                .borrow_dependent()
                .tbs_cert_list
                .this_update
                .as_datetime(),
        )
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let tbs_cert_list = &self.owned.borrow_dependent().tbs_cert_list;

        x509::parse_and_cache_extensions(
            py,
            &self.cached_extensions,
            &tbs_cert_list.raw_crl_extensions,
            |ext| match ext.extn_id {
                oid::CRL_NUMBER_OID => {
                    let bignum = ext.value::<asn1::BigUint<'_>>()?;
                    let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
                    Ok(Some(types::CRL_NUMBER.get(py)?.call1((pynum,))?))
                }
                oid::DELTA_CRL_INDICATOR_OID => {
                    let bignum = ext.value::<asn1::BigUint<'_>>()?;
                    let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
                    Ok(Some(types::DELTA_CRL_INDICATOR.get(py)?.call1((pynum,))?))
                }
                oid::ISSUER_ALTERNATIVE_NAME_OID => {
                    let gn_seq = ext.value::<IssuerAlternativeName<'_>>()?;
                    let ians = x509::parse_general_names(py, &gn_seq)?;
                    Ok(Some(
                        types::ISSUER_ALTERNATIVE_NAME.get(py)?.call1((ians,))?,
                    ))
                }
                oid::AUTHORITY_INFORMATION_ACCESS_OID => {
                    let ads = certificate::parse_access_descriptions(py, ext)?;
                    Ok(Some(
                        types::AUTHORITY_INFORMATION_ACCESS.get(py)?.call1((ads,))?,
                    ))
                }
                oid::AUTHORITY_KEY_IDENTIFIER_OID => {
                    Ok(Some(certificate::parse_authority_key_identifier(py, ext)?))
                }
                oid::ISSUING_DISTRIBUTION_POINT_OID => {
                    let idp = ext.value::<crl::IssuingDistributionPoint<'_, Asn1Read>>()?;
                    let (full_name, relative_name) = match idp.distribution_point {
                        Some(data) => certificate::parse_distribution_point_name(py, data)?,
                        None => (py.None().into_bound(py), py.None().into_bound(py)),
                    };
                    let py_reasons = if let Some(reasons) = idp.only_some_reasons {
                        certificate::parse_distribution_point_reasons(py, Some(&reasons))?
                    } else {
                        py.None().into_bound(py)
                    };
                    Ok(Some(types::ISSUING_DISTRIBUTION_POINT.get(py)?.call1((
                        full_name,
                        relative_name,
                        idp.only_contains_user_certs,
                        idp.only_contains_ca_certs,
                        py_reasons,
                        idp.indirect_crl,
                        idp.only_contains_attribute_certs,
                    ))?))
                }
                oid::FRESHEST_CRL_OID => {
                    let dp = certificate::parse_distribution_points(py, ext)?;
                    Ok(Some(types::FRESHEST_CRL.get(py)?.call1((dp,))?))
                }
                _ => Ok(None),
            },
        )
    }

    fn get_revoked_certificate_by_serial_number(
        &self,
        py: pyo3::Python<'_>,
        serial: pyo3::Bound<'_, pyo3::types::PyInt>,
    ) -> pyo3::PyResult<Option<RevokedCertificate>> {
        let serial_bytes = py_uint_to_big_endian_bytes(py, serial)?;
        let owned = OwnedRevokedCertificate::try_new(Arc::clone(&self.owned), |v| {
            let certs = match &v.borrow_dependent().tbs_cert_list.revoked_certificates {
                Some(certs) => certs.unwrap_read().clone(),
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
                owned: o,
                cached_extensions: pyo3::sync::GILOnceCell::new(),
            })),
            Err(()) => Ok(None),
        }
    }

    fn is_signature_valid<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
        public_key: pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<bool> {
        if slf.owned.borrow_dependent().tbs_cert_list.signature
            != slf.owned.borrow_dependent().signature_algorithm
        {
            return Ok(false);
        };

        // Error on invalid public key -- below we treat any error as just
        // being an invalid signature.
        sign::identify_public_key_type(py, public_key.clone())?;

        Ok(sign::verify_signature_with_signature_algorithm(
            py,
            public_key,
            &slf.owned.borrow_dependent().signature_algorithm,
            slf.owned.borrow_dependent().signature_value.as_bytes(),
            &asn1::write_single(&slf.owned.borrow_dependent().tbs_cert_list)?,
        )
        .is_ok())
    }
}

type RawCRLIterator<'a> = Option<asn1::SequenceOf<'a, crl::RevokedCertificate<'a>>>;
self_cell::self_cell!(
    struct OwnedCRLIteratorData {
        owner: Arc<OwnedCertificateRevocationList>,

        #[covariant]
        dependent: RawCRLIterator,
    }
);

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
struct CRLIterator {
    contents: OwnedCRLIteratorData,
}

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn try_map_arc_data_mut_crl_iterator<E>(
    it: &mut OwnedCRLIteratorData,
    f: impl for<'this> FnOnce(
        &'this OwnedCertificateRevocationList,
        &mut Option<asn1::SequenceOf<'this, crl::RevokedCertificate<'this>>>,
    ) -> Result<crl::RevokedCertificate<'this>, E>,
) -> Result<OwnedRevokedCertificate, E> {
    OwnedRevokedCertificate::try_new(Arc::clone(it.borrow_owner()), |inner_it| {
        it.with_dependent_mut(|_, value| {
            // SAFETY: This is safe because `Arc::clone` ensures the data is
            // alive, but Rust doesn't understand the lifetime relationship it
            // produces. Open-coded implementation of the API discussed in
            // https://github.com/joshua-maros/ouroboros/issues/38
            f(inner_it, unsafe {
                std::mem::transmute::<
                    &mut Option<asn1::SequenceOf<'_, crl::RevokedCertificate<'_>>>,
                    &mut Option<asn1::SequenceOf<'_, crl::RevokedCertificate<'_>>>,
                >(value)
            })
        })
    })
}

#[pyo3::pymethods]
impl CRLIterator {
    fn __len__(&self) -> usize {
        self.contents
            .borrow_dependent()
            .clone()
            .map_or(0, |v| v.len())
    }

    fn __iter__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<RevokedCertificate> {
        let revoked = try_map_arc_data_mut_crl_iterator(&mut self.contents, |_data, v| match v {
            Some(v) => match v.next() {
                Some(revoked) => Ok(revoked),
                None => Err(()),
            },
            None => Err(()),
        })
        .ok()?;
        Some(RevokedCertificate {
            owned: revoked,
            cached_extensions: pyo3::sync::GILOnceCell::new(),
        })
    }
}

self_cell::self_cell!(
    struct OwnedRevokedCertificate {
        owner: Arc<OwnedCertificateRevocationList>,
        #[covariant]
        dependent: RawRevokedCertificate,
    }
);

impl Clone for OwnedRevokedCertificate {
    fn clone(&self) -> OwnedRevokedCertificate {
        // SAFETY: This is safe because `Arc::clone` ensures the data is
        // alive, but Rust doesn't understand the lifetime relationship it
        // produces. Open-coded implementation of the API discussed in
        // https://github.com/joshua-maros/ouroboros/issues/38
        OwnedRevokedCertificate::new(Arc::clone(self.borrow_owner()), |_| unsafe {
            std::mem::transmute(self.borrow_dependent().clone())
        })
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.x509")]
pub(crate) struct RevokedCertificate {
    owned: OwnedRevokedCertificate,
    cached_extensions: pyo3::sync::GILOnceCell<pyo3::PyObject>,
}

#[pyo3::pymethods]
impl RevokedCertificate {
    #[getter]
    fn serial_number<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        big_byte_slice_to_py_int(
            py,
            self.owned.borrow_dependent().user_certificate.as_bytes(),
        )
    }

    #[getter]
    fn revocation_date<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        let warning_cls = types::DEPRECATED_IN_42.get(py)?;
        let message = cstr_from_literal!("Properties that return a naïve datetime object have been deprecated. Please switch to revocation_date_utc.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
        x509::datetime_to_py(
            py,
            self.owned.borrow_dependent().revocation_date.as_datetime(),
        )
    }

    #[getter]
    fn revocation_date_utc<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        x509::datetime_to_py_utc(
            py,
            self.owned.borrow_dependent().revocation_date.as_datetime(),
        )
    }

    #[getter]
    fn extensions(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        x509::parse_and_cache_extensions(
            py,
            &self.cached_extensions,
            &self.owned.borrow_dependent().raw_crl_entry_extensions,
            |ext| parse_crl_entry_ext(py, ext),
        )
    }
}

pub(crate) fn parse_crl_reason_flags<'p>(
    py: pyo3::Python<'p>,
    reason: &crl::CRLReason,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
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
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Unsupported reason code: {value}"
                )),
            ))
        }
    };
    Ok(types::REASON_FLAGS.get(py)?.getattr(flag_name)?)
}

pub fn parse_crl_entry_ext<'p>(
    py: pyo3::Python<'p>,
    ext: &Extension<'p>,
) -> CryptographyResult<Option<pyo3::Bound<'p, pyo3::PyAny>>> {
    match ext.extn_id {
        oid::CRL_REASON_OID => {
            let flags = parse_crl_reason_flags(py, &ext.value::<crl::CRLReason>()?)?;
            Ok(Some(types::CRL_REASON.get(py)?.call1((flags,))?))
        }
        oid::CERTIFICATE_ISSUER_OID => {
            let gn_seq = ext.value::<asn1::SequenceOf<'_, name::GeneralName<'_>>>()?;
            let gns = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(types::CERTIFICATE_ISSUER.get(py)?.call1((gns,))?))
        }
        oid::INVALIDITY_DATE_OID => {
            let time = ext.value::<asn1::GeneralizedTime>()?;
            let py_dt = x509::datetime_to_py(py, time.as_datetime())?;
            Ok(Some(types::INVALIDITY_DATE.get(py)?.call1((py_dt,))?))
        }
        _ => Ok(None),
    }
}

#[pyo3::pyfunction]
pub(crate) fn create_x509_crl(
    py: pyo3::Python<'_>,
    builder: &pyo3::Bound<'_, pyo3::PyAny>,
    private_key: &pyo3::Bound<'_, pyo3::PyAny>,
    hash_algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    rsa_padding: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<CertificateRevocationList> {
    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key.to_owned(),
        hash_algorithm.to_owned(),
        rsa_padding.to_owned(),
    )?;
    let mut revoked_certs = vec![];
    let ka_vec = cryptography_keepalive::KeepAlive::new();
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    for py_revoked_cert in builder
        .getattr(pyo3::intern!(py, "_revoked_certificates"))?
        .try_iter()?
    {
        let py_revoked_cert = py_revoked_cert?;
        let serial_number = py_revoked_cert
            .getattr(pyo3::intern!(py, "serial_number"))?
            .extract()?;
        let py_revocation_date =
            py_revoked_cert.getattr(pyo3::intern!(py, "revocation_date_utc"))?;
        let serial_bytes = ka_bytes.add(py_uint_to_big_endian_bytes(py, serial_number)?);
        revoked_certs.push(crl::RevokedCertificate {
            user_certificate: asn1::BigUint::new(serial_bytes).unwrap(),
            revocation_date: x509::certificate::time_from_py(py, &py_revocation_date)?,
            raw_crl_entry_extensions: x509::common::encode_extensions(
                py,
                &ka_vec,
                &ka_bytes,
                &py_revoked_cert.getattr(pyo3::intern!(py, "extensions"))?,
                extensions::encode_extension,
            )?,
        });
    }

    let ka = cryptography_keepalive::KeepAlive::new();

    let py_issuer_name = builder.getattr(pyo3::intern!(py, "_issuer_name"))?;
    let py_this_update = builder.getattr(pyo3::intern!(py, "_last_update"))?;
    let py_next_update = builder.getattr(pyo3::intern!(py, "_next_update"))?;
    let tbs_cert_list = crl::TBSCertList {
        version: Some(1),
        signature: sigalg.clone(),
        issuer: x509::common::encode_name(py, &ka, &py_issuer_name)?,
        this_update: x509::certificate::time_from_py(py, &py_this_update)?,
        next_update: Some(x509::certificate::time_from_py(py, &py_next_update)?),
        revoked_certificates: if revoked_certs.is_empty() {
            None
        } else {
            Some(common::Asn1ReadableOrWritable::new_write(
                asn1::SequenceOfWriter::new(revoked_certs),
            ))
        },
        raw_crl_extensions: x509::common::encode_extensions(
            py,
            &ka_vec,
            &ka_bytes,
            &builder.getattr(pyo3::intern!(py, "_extensions"))?,
            extensions::encode_extension,
        )?,
    };

    let tbs_bytes = asn1::write_single(&tbs_cert_list)?;
    let signature = x509::sign::sign_data(
        py,
        private_key.clone(),
        hash_algorithm.clone(),
        rsa_padding.clone(),
        &tbs_bytes,
    )?;
    let data = asn1::write_single(&crl::CertificateRevocationList {
        tbs_cert_list,
        signature_algorithm: sigalg,
        signature_value: asn1::BitString::new(&signature, 0).unwrap(),
    })?;
    load_der_x509_crl(py, pyo3::types::PyBytes::new(py, &data).unbind(), None)
}
