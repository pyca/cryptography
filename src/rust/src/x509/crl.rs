// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{
    big_byte_slice_to_py_int, encode_der_data, oid_to_py_oid, py_uint_to_big_endian_bytes,
};
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::{certificate, extensions, sign};
use crate::{exceptions, x509};
use cryptography_x509::{common, crl, name, oid};
use pyo3::{IntoPy, ToPyObject};
use std::sync::Arc;

#[pyo3::prelude::pyfunction]
fn load_der_x509_crl(
    py: pyo3::Python<'_>,
    data: pyo3::Py<pyo3::types::PyBytes>,
) -> Result<CertificateRevocationList, CryptographyError> {
    let owned = OwnedCertificateRevocationList::try_new(data, |data| {
        asn1::parse_single(data.as_bytes(py))
    })?;

    let version = owned.borrow_value().tbs_cert_list.version.unwrap_or(1);
    if version != 1 {
        return Err(CryptographyError::from(
            exceptions::InvalidVersion::new_err((
                format!("{} is not a valid CRL version", version),
                version,
            )),
        ));
    }

    Ok(CertificateRevocationList {
        owned: Arc::new(owned),
        revoked_certs: pyo3::once_cell::GILOnceCell::new(),
        cached_extensions: None,
    })
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_crl(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<CertificateRevocationList, CryptographyError> {
    let block = x509::find_in_pem(
        data,
        |p| p.tag == "X509 CRL",
        "Valid PEM but no BEGIN X509 CRL/END X509 delimiters. Are you sure this is a CRL?",
    )?;
    load_der_x509_crl(
        py,
        pyo3::types::PyBytes::new(py, &block.contents).into_py(py),
    )
}

#[ouroboros::self_referencing]
struct OwnedCertificateRevocationList {
    data: pyo3::Py<pyo3::types::PyBytes>,
    #[borrows(data)]
    #[covariant]
    value: crl::CertificateRevocationList<'this>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
struct CertificateRevocationList {
    owned: Arc<OwnedCertificateRevocationList>,

    revoked_certs: pyo3::once_cell::GILOnceCell<Vec<OwnedRevokedCertificate>>,
    cached_extensions: Option<pyo3::PyObject>,
}

impl CertificateRevocationList {
    fn public_bytes_der(&self) -> CryptographyResult<Vec<u8>> {
        Ok(asn1::write_single(self.owned.borrow_value())?)
    }

    fn revoked_cert(&self, py: pyo3::Python<'_>, idx: usize) -> RevokedCertificate {
        RevokedCertificate {
            owned: self.revoked_certs.get(py).unwrap()[idx].clone(),
            cached_extensions: None,
        }
    }

    fn len(&self) -> usize {
        self.owned
            .borrow_value()
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .map_or(0, |v| v.unwrap_read().len())
    }
}

#[pyo3::prelude::pymethods]
impl CertificateRevocationList {
    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, CertificateRevocationList>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => {
                Ok(self.owned.borrow_value() == other.owned.borrow_value())
            }
            pyo3::basic::CompareOp::Ne => {
                Ok(self.owned.borrow_value() != other.owned.borrow_value())
            }
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "CRLs cannot be ordered",
            )),
        }
    }

    fn __len__(&self) -> usize {
        self.len()
    }

    fn __iter__(&self) -> CRLIterator {
        CRLIterator {
            contents: OwnedCRLIteratorData::try_new(Arc::clone(&self.owned), |v| {
                Ok::<_, ()>(
                    v.borrow_value()
                        .tbs_cert_list
                        .revoked_certificates
                        .as_ref()
                        .map(|v| v.unwrap_read().clone()),
                )
            })
            .unwrap(),
        }
    }

    fn __getitem__(
        &self,
        py: pyo3::Python<'_>,
        idx: &pyo3::PyAny,
    ) -> pyo3::PyResult<pyo3::PyObject> {
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
                let revoked_cert = pyo3::PyCell::new(py, self.revoked_cert(py, i as usize))?;
                result.append(revoked_cert)?;
            }
            Ok(result.to_object(py))
        } else {
            let mut idx = idx.extract::<isize>()?;
            if idx < 0 {
                idx += self.len() as isize;
            }
            if idx >= (self.len() as isize) || idx < 0 {
                return Err(pyo3::exceptions::PyIndexError::new_err(()));
            }
            Ok(pyo3::PyCell::new(py, self.revoked_cert(py, idx as usize))?.to_object(py))
        }
    }

    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::PyObject,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let hashes_mod = py.import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?;
        let h = hashes_mod
            .getattr(pyo3::intern!(py, "Hash"))?
            .call1((algorithm,))?;

        let data = self.public_bytes_der()?;
        h.call_method1(pyo3::intern!(py, "update"), (data.as_slice(),))?;
        h.call_method0(pyo3::intern!(py, "finalize"))
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        oid_to_py_oid(py, self.owned.borrow_value().signature_algorithm.oid())
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let oid = self.signature_algorithm_oid(py)?;
        let oid_module = py.import(pyo3::intern!(py, "cryptography.hazmat._oid"))?;
        match oid_module
            .getattr(pyo3::intern!(py, "_SIG_OIDS_TO_HASH"))?
            .get_item(oid)
        {
            Ok(v) => Ok(v),
            Err(_) => Err(exceptions::UnsupportedAlgorithm::new_err(format!(
                "Signature algorithm OID: {} not recognized",
                self.owned.borrow_value().signature_algorithm.oid(),
            ))),
        }
    }

    #[getter]
    fn signature(&self) -> &[u8] {
        self.owned.borrow_value().signature_value.as_bytes()
    }

    #[getter]
    fn tbs_certlist_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let b = asn1::write_single(&self.owned.borrow_value().tbs_cert_list)?;
        Ok(pyo3::types::PyBytes::new(py, &b))
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &'p pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = asn1::write_single(self.owned.borrow_value())?;

        encode_der_data(py, "X509 CRL".to_string(), result, encoding)
    }

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        Ok(x509::parse_name(
            py,
            &self.owned.borrow_value().tbs_cert_list.issuer,
        )?)
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        match &self.owned.borrow_value().tbs_cert_list.next_update {
            Some(t) => x509::datetime_to_py(py, t.as_datetime()),
            None => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn last_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::datetime_to_py(
            py,
            self.owned
                .borrow_value()
                .tbs_cert_list
                .this_update
                .as_datetime(),
        )
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let tbs_cert_list = &self.owned.borrow_value().tbs_cert_list;

        let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &tbs_cert_list.raw_crl_extensions,
            |oid, ext_data| match *oid {
                oid::CRL_NUMBER_OID => {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "CRLNumber"))?
                            .call1((pynum,))?,
                    ))
                }
                oid::DELTA_CRL_INDICATOR_OID => {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_byte_slice_to_py_int(py, bignum.as_bytes())?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "DeltaCRLIndicator"))?
                            .call1((pynum,))?,
                    ))
                }
                oid::ISSUER_ALTERNATIVE_NAME_OID => {
                    let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, name::GeneralName<'_>>>(
                        ext_data,
                    )?;
                    let ians = x509::parse_general_names(py, &gn_seq)?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "IssuerAlternativeName"))?
                            .call1((ians,))?,
                    ))
                }
                oid::AUTHORITY_INFORMATION_ACCESS_OID => {
                    let ads = certificate::parse_access_descriptions(py, ext_data)?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "AuthorityInformationAccess"))?
                            .call1((ads,))?,
                    ))
                }
                oid::AUTHORITY_KEY_IDENTIFIER_OID => Ok(Some(
                    certificate::parse_authority_key_identifier(py, ext_data)?,
                )),
                oid::ISSUING_DISTRIBUTION_POINT_OID => {
                    let idp = asn1::parse_single::<crl::IssuingDistributionPoint<'_>>(ext_data)?;
                    let (full_name, relative_name) = match idp.distribution_point {
                        Some(data) => certificate::parse_distribution_point_name(py, data)?,
                        None => (py.None(), py.None()),
                    };
                    let py_reasons = if let Some(reasons) = idp.only_some_reasons {
                        certificate::parse_distribution_point_reasons(
                            py,
                            Some(reasons.unwrap_read()),
                        )?
                    } else {
                        py.None()
                    };
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "IssuingDistributionPoint"))?
                            .call1((
                                full_name,
                                relative_name,
                                idp.only_contains_user_certs,
                                idp.only_contains_ca_certs,
                                py_reasons,
                                idp.indirect_crl,
                                idp.only_contains_attribute_certs,
                            ))?,
                    ))
                }
                oid::FRESHEST_CRL_OID => {
                    let dp = certificate::parse_distribution_points(py, ext_data)?;
                    Ok(Some(
                        x509_module
                            .getattr(pyo3::intern!(py, "FreshestCRL"))?
                            .call1((dp,))?,
                    ))
                }
                _ => Ok(None),
            },
        )
    }

    fn get_revoked_certificate_by_serial_number(
        &mut self,
        py: pyo3::Python<'_>,
        serial: &pyo3::types::PyLong,
    ) -> pyo3::PyResult<Option<RevokedCertificate>> {
        let serial_bytes = py_uint_to_big_endian_bytes(py, serial)?;
        let owned = OwnedRevokedCertificate::try_new(Arc::clone(&self.owned), |v| {
            let certs = match &v.borrow_value().tbs_cert_list.revoked_certificates {
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
                cached_extensions: None,
            })),
            Err(()) => Ok(None),
        }
    }

    fn is_signature_valid<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
        public_key: &'p pyo3::PyAny,
    ) -> CryptographyResult<bool> {
        if slf.owned.borrow_value().tbs_cert_list.signature
            != slf.owned.borrow_value().signature_algorithm
        {
            return Ok(false);
        };

        // Error on invalid public key -- below we treat any error as just
        // being an invalid signature.
        sign::identify_public_key_type(py, public_key)?;

        Ok(sign::verify_signature_with_signature_algorithm(
            py,
            public_key,
            &slf.owned.borrow_value().signature_algorithm,
            slf.owned.borrow_value().signature_value.as_bytes(),
            &asn1::write_single(&slf.owned.borrow_value().tbs_cert_list)?,
        )
        .is_ok())
    }
}

#[ouroboros::self_referencing]
struct OwnedCRLIteratorData {
    data: Arc<OwnedCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: Option<asn1::SequenceOf<'this, crl::RevokedCertificate<'this>>>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
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
    OwnedRevokedCertificate::try_new(Arc::clone(it.borrow_data()), |inner_it| {
        it.with_value_mut(|value| f(inner_it, unsafe { std::mem::transmute(value) }))
    })
}

#[pyo3::prelude::pymethods]
impl CRLIterator {
    fn __len__(&self) -> usize {
        self.contents.borrow_value().clone().map_or(0, |v| v.len())
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
            cached_extensions: None,
        })
    }
}

#[ouroboros::self_referencing]
struct OwnedRevokedCertificate {
    data: Arc<OwnedCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: crl::RevokedCertificate<'this>,
}

impl Clone for OwnedRevokedCertificate {
    fn clone(&self) -> OwnedRevokedCertificate {
        // This is safe because `Arc::clone` ensures the data is alive, but
        // Rust doesn't understand the lifetime relationship it produces.
        // Open-coded implementation of the API discussed in
        // https://github.com/joshua-maros/ouroboros/issues/38
        OwnedRevokedCertificate::new(Arc::clone(self.borrow_data()), |_| unsafe {
            std::mem::transmute(self.borrow_value().clone())
        })
    }
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.x509")]
struct RevokedCertificate {
    owned: OwnedRevokedCertificate,
    cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pymethods]
impl RevokedCertificate {
    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        big_byte_slice_to_py_int(py, self.owned.borrow_value().user_certificate.as_bytes())
    }

    #[getter]
    fn revocation_date<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::datetime_to_py(py, self.owned.borrow_value().revocation_date.as_datetime())
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.owned.borrow_value().raw_crl_entry_extensions,
            |oid, ext_data| parse_crl_entry_ext(py, oid.clone(), ext_data),
        )
    }
}

pub(crate) fn parse_crl_reason_flags<'p>(
    py: pyo3::Python<'p>,
    reason: &crl::CRLReason,
) -> CryptographyResult<&'p pyo3::PyAny> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
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
                    "Unsupported reason code: {}",
                    value
                )),
            ))
        }
    };
    Ok(x509_module
        .getattr(pyo3::intern!(py, "ReasonFlags"))?
        .getattr(flag_name)?)
}

pub fn parse_crl_entry_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier,
    data: &[u8],
) -> CryptographyResult<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509"))?;
    match oid {
        oid::CRL_REASON_OID => {
            let flags = parse_crl_reason_flags(py, &asn1::parse_single::<crl::CRLReason>(data)?)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "CRLReason"))?
                    .call1((flags,))?,
            ))
        }
        oid::CERTIFICATE_ISSUER_OID => {
            let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, name::GeneralName<'_>>>(data)?;
            let gns = x509::parse_general_names(py, &gn_seq)?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "CertificateIssuer"))?
                    .call1((gns,))?,
            ))
        }
        oid::INVALIDITY_DATE_OID => {
            let time = asn1::parse_single::<asn1::GeneralizedTime>(data)?;
            let py_dt = x509::datetime_to_py(py, time.as_datetime())?;
            Ok(Some(
                x509_module
                    .getattr(pyo3::intern!(py, "InvalidityDate"))?
                    .call1((py_dt,))?,
            ))
        }
        _ => Ok(None),
    }
}

#[pyo3::prelude::pyfunction]
fn create_x509_crl(
    py: pyo3::Python<'_>,
    builder: &pyo3::PyAny,
    private_key: &pyo3::PyAny,
    hash_algorithm: &pyo3::PyAny,
) -> CryptographyResult<CertificateRevocationList> {
    let sigalg = x509::sign::compute_signature_algorithm(
        py,
        private_key,
        hash_algorithm,
        py.None().into_ref(py),
    )?;
    let mut revoked_certs = vec![];
    for py_revoked_cert in builder
        .getattr(pyo3::intern!(py, "_revoked_certificates"))?
        .iter()?
    {
        let py_revoked_cert = py_revoked_cert?;
        let serial_number = py_revoked_cert
            .getattr(pyo3::intern!(py, "serial_number"))?
            .extract()?;
        let py_revocation_date = py_revoked_cert.getattr(pyo3::intern!(py, "revocation_date"))?;
        revoked_certs.push(crl::RevokedCertificate {
            user_certificate: asn1::BigUint::new(py_uint_to_big_endian_bytes(py, serial_number)?)
                .unwrap(),
            revocation_date: x509::certificate::time_from_py(py, py_revocation_date)?,
            raw_crl_entry_extensions: x509::common::encode_extensions(
                py,
                py_revoked_cert.getattr(pyo3::intern!(py, "extensions"))?,
                extensions::encode_extension,
            )?,
        });
    }

    let py_issuer_name = builder.getattr(pyo3::intern!(py, "_issuer_name"))?;
    let py_this_update = builder.getattr(pyo3::intern!(py, "_last_update"))?;
    let py_next_update = builder.getattr(pyo3::intern!(py, "_next_update"))?;
    let tbs_cert_list = crl::TBSCertList {
        version: Some(1),
        signature: sigalg.clone(),
        issuer: x509::common::encode_name(py, py_issuer_name)?,
        this_update: x509::certificate::time_from_py(py, py_this_update)?,
        next_update: Some(x509::certificate::time_from_py(py, py_next_update)?),
        revoked_certificates: if revoked_certs.is_empty() {
            None
        } else {
            Some(common::Asn1ReadableOrWritable::new_write(
                asn1::SequenceOfWriter::new(revoked_certs),
            ))
        },
        raw_crl_extensions: x509::common::encode_extensions(
            py,
            builder.getattr(pyo3::intern!(py, "_extensions"))?,
            extensions::encode_extension,
        )?,
    };

    let tbs_bytes = asn1::write_single(&tbs_cert_list)?;
    let signature = x509::sign::sign_data(
        py,
        private_key,
        hash_algorithm,
        py.None().into_ref(py),
        &tbs_bytes,
    )?;
    let data = asn1::write_single(&crl::CertificateRevocationList {
        tbs_cert_list,
        signature_algorithm: sigalg,
        signature_value: asn1::BitString::new(signature, 0).unwrap(),
    })?;
    load_der_x509_crl(py, pyo3::types::PyBytes::new(py, &data).into_py(py))
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(load_der_x509_crl, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(load_pem_x509_crl, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(create_x509_crl, module)?)?;

    module.add_class::<CertificateRevocationList>()?;
    module.add_class::<RevokedCertificate>()?;

    Ok(())
}
