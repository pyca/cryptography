// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{big_asn1_uint_to_py, py_uint_to_big_endian_bytes, PyAsn1Error, PyAsn1Result};
use crate::x509;
use crate::x509::certificate;
use pyo3::ToPyObject;
use std::convert::TryInto;
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
    static ref ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.18").unwrap();
    static ref AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1").unwrap();
    static ref AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    static ref ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.28").unwrap();
    static ref FRESHEST_CRL_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.46").unwrap();
    static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    static ref CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.29").unwrap();
    static ref INVALIDITY_DATE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.24").unwrap();
}

#[pyo3::prelude::pyfunction]
fn load_der_x509_crl(
    _py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<CertificateRevocationList, PyAsn1Error> {
    let raw = OwnedRawCertificateRevocationList::try_new(
        Arc::from(data),
        |data| asn1::parse_single(data),
        |_| Ok(pyo3::once_cell::GILOnceCell::new()),
    )?;

    Ok(CertificateRevocationList {
        raw: Arc::new(raw),
        cached_extensions: None,
    })
}

#[pyo3::prelude::pyfunction]
fn load_pem_x509_crl(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<CertificateRevocationList, PyAsn1Error> {
    let block = x509::find_in_pem(
        data,
        |p| p.tag == "X509 CRL",
        "Valid PEM but no BEGIN X509 CRL/END X509 delimiters. Are you sure this is a CRL?",
        "Valid PEM but multiple BEGIN X509 CRL/END X509 delimiters.",
    )?;
    // TODO: Produces an extra copy
    load_der_x509_crl(py, &block.contents)
}

#[ouroboros::self_referencing]
struct OwnedRawCertificateRevocationList {
    data: Arc<[u8]>,
    #[borrows(data)]
    #[covariant]
    value: RawCertificateRevocationList<'this>,
    #[borrows(data)]
    #[not_covariant]
    revoked_certs: pyo3::once_cell::GILOnceCell<Vec<RawRevokedCertificate<'this>>>,
}

#[pyo3::prelude::pyclass]
struct CertificateRevocationList {
    raw: Arc<OwnedRawCertificateRevocationList>,

    cached_extensions: Option<pyo3::PyObject>,
}

impl CertificateRevocationList {
    fn public_bytes_der(&self) -> Vec<u8> {
        asn1::write_single(self.raw.borrow_value())
    }

    fn revoked_cert(&self, py: pyo3::Python<'_>, idx: usize) -> pyo3::PyResult<RevokedCertificate> {
        let raw = try_map_arc_data_crl(&self.raw, |_crl, revoked_certs| {
            let revoked_certs = revoked_certs.get(py).unwrap();
            Ok::<_, pyo3::PyErr>(revoked_certs[idx].clone())
        })?;
        Ok(RevokedCertificate {
            raw,
            cached_extensions: None,
        })
    }

    fn len(&self) -> usize {
        self.raw
            .borrow_value()
            .tbs_cert_list
            .revoked_certificates
            .as_ref()
            .map_or(0, |v| v.len())
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyObjectProtocol for CertificateRevocationList {
    fn __richcmp__(
        &self,
        other: pyo3::PyRef<CertificateRevocationList>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.raw.borrow_value() == other.raw.borrow_value()),
            pyo3::basic::CompareOp::Ne => Ok(self.raw.borrow_value() != other.raw.borrow_value()),
            _ => Err(pyo3::exceptions::PyTypeError::new_err(
                "CRLs cannot be ordered",
            )),
        }
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyMappingProtocol for CertificateRevocationList {
    fn __len__(&self) -> usize {
        self.len()
    }

    fn __getitem__(&self, idx: &pyo3::PyAny) -> pyo3::PyResult<pyo3::PyObject> {
        let gil = pyo3::Python::acquire_gil();
        let py = gil.python();

        self.raw.with(|val| {
            val.revoked_certs.get_or_init(py, || {
                match &val.value.tbs_cert_list.revoked_certificates {
                    Some(c) => c.clone().collect(),
                    None => vec![],
                }
            });
        });

        if idx.is_instance::<pyo3::types::PySlice>()? {
            let indices = idx
                .downcast::<pyo3::types::PySlice>()?
                .indices(self.len().try_into().unwrap())?;
            let result = pyo3::types::PyList::empty(py);
            for i in (indices.start..indices.stop).step_by(indices.step.try_into().unwrap()) {
                let revoked_cert = pyo3::PyCell::new(py, self.revoked_cert(py, i as usize)?)?;
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
            Ok(pyo3::PyCell::new(py, self.revoked_cert(py, idx as usize)?)?.to_object(py))
        }
    }
}

#[pyo3::prelude::pymethods]
impl CertificateRevocationList {
    fn fingerprint<'p>(
        &self,
        py: pyo3::Python<'p>,
        algorithm: pyo3::PyObject,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let hashes_mod = py.import("cryptography.hazmat.primitives.hashes")?;
        let h = hashes_mod.getattr("Hash")?.call1((algorithm,))?;
        h.call_method1("update", (self.public_bytes_der().as_slice(),))?;
        h.call_method0("finalize")
    }

    #[getter]
    fn signature_algorithm_oid<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let x509_module = py.import("cryptography.x509")?;
        x509_module.call_method1(
            "ObjectIdentifier",
            (self.raw.borrow_value().signature_algorithm.oid.to_string(),),
        )
    }

    #[getter]
    fn signature_hash_algorithm<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let oid = self.signature_algorithm_oid(py)?;
        let oid_module = py.import("cryptography.hazmat._oid")?;
        let exceptions_module = py.import("cryptography.exceptions")?;
        match oid_module.getattr("_SIG_OIDS_TO_HASH")?.get_item(oid) {
            Ok(v) => Ok(v),
            Err(_) => Err(pyo3::PyErr::from_instance(exceptions_module.call_method1(
                "UnsupportedAlgorithm",
                (format!(
                    "Signature algorithm OID:{} not recognized",
                    self.raw.borrow_value().signature_algorithm.oid
                ),),
            )?)),
        }
    }

    #[getter]
    fn signature(&self) -> &[u8] {
        self.raw.borrow_value().signature_value.as_bytes()
    }

    #[getter]
    fn tbs_certlist_bytes<'p>(&self, py: pyo3::Python<'p>) -> &'p pyo3::types::PyBytes {
        let b = asn1::write_single(&self.raw.borrow_value().tbs_cert_list);
        pyo3::types::PyBytes::new(py, &b)
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
                    tag: "X509 CRL".to_string(),
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

    #[getter]
    fn issuer<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::parse_name(py, &self.raw.borrow_value().tbs_cert_list.issuer)
    }

    #[getter]
    fn next_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        match &self.raw.borrow_value().tbs_cert_list.next_update {
            Some(t) => x509::chrono_to_py(py, t.as_chrono()),
            None => Ok(py.None().into_ref(py)),
        }
    }

    #[getter]
    fn last_update<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::chrono_to_py(
            py,
            self.raw
                .borrow_value()
                .tbs_cert_list
                .this_update
                .as_chrono(),
        )
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let x509_module = py.import("cryptography.x509")?;
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().tbs_cert_list.crl_extensions,
            |oid, ext_data| {
                if oid == &*CRL_NUMBER_OID {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_asn1_uint_to_py(py, bignum)?;
                    Ok(Some(x509_module.getattr("CRLNumber")?.call1((pynum,))?))
                } else if oid == &*DELTA_CRL_INDICATOR_OID {
                    let bignum = asn1::parse_single::<asn1::BigUint<'_>>(ext_data)?;
                    let pynum = big_asn1_uint_to_py(py, bignum)?;
                    Ok(Some(
                        x509_module.getattr("DeltaCRLIndicator")?.call1((pynum,))?,
                    ))
                } else if oid == &*ISSUER_ALTERNATIVE_NAME_OID {
                    let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(
                        ext_data,
                    )?;
                    let ians = x509::parse_general_names(py, &gn_seq)?;
                    Ok(Some(
                        x509_module
                            .getattr("IssuerAlternativeName")?
                            .call1((ians,))?,
                    ))
                } else if oid == &*AUTHORITY_INFORMATION_ACCESS_OID {
                    let ads = certificate::parse_access_descriptions(py, ext_data)?;
                    Ok(Some(
                        x509_module
                            .getattr("AuthorityInformationAccess")?
                            .call1((ads,))?,
                    ))
                } else if oid == &*AUTHORITY_KEY_IDENTIFIER_OID {
                    Ok(Some(certificate::parse_authority_key_identifier(
                        py, ext_data,
                    )?))
                } else if oid == &*ISSUING_DISTRIBUTION_POINT_OID {
                    let idp = asn1::parse_single::<IssuingDistributionPoint<'_>>(ext_data)?;
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
                        x509_module.getattr("IssuingDistributionPoint")?.call1((
                            full_name,
                            relative_name,
                            idp.only_contains_user_certs,
                            idp.only_contains_ca_certs,
                            py_reasons,
                            idp.indirect_crl,
                            idp.only_contains_attribute_certs,
                        ))?,
                    ))
                } else if oid == &*FRESHEST_CRL_OID {
                    let dp = certificate::parse_distribution_points(py, ext_data)?;
                    Ok(Some(x509_module.getattr("FreshestCRL")?.call1((dp,))?))
                } else {
                    Ok(None)
                }
            },
        )
    }

    fn get_revoked_certificate_by_serial_number(
        &mut self,
        py: pyo3::Python<'_>,
        serial: &pyo3::types::PyLong,
    ) -> pyo3::PyResult<Option<RevokedCertificate>> {
        let serial_bytes = py_uint_to_big_endian_bytes(py, serial)?;
        let owned = OwnedRawRevokedCertificate::try_new(Arc::clone(&self.raw), |v| {
            let certs = match v.borrow_value().tbs_cert_list.revoked_certificates.clone() {
                Some(certs) => certs,
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
                raw: o,
                cached_extensions: None,
            })),
            Err(()) => Ok(None),
        }
    }

    fn is_signature_valid<'p>(
        slf: pyo3::PyRef<'_, Self>,
        py: pyo3::Python<'p>,
        public_key: &'p pyo3::PyAny,
    ) -> pyo3::PyResult<&'p pyo3::PyAny> {
        let backend = py
            .import("cryptography.hazmat.backends.openssl.backend")?
            .getattr("backend")?;
        backend.call_method1("_crl_is_signature_valid", (slf, public_key))
    }

    // This getter exists for compatibility with pyOpenSSL and will be removed.
    // DO NOT RELY ON IT. WE WILL BREAK YOU WHEN WE FEEL LIKE IT.
    #[getter]
    fn _x509_crl<'p>(
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
        Ok(backend.call_method1("_crl2ossl", (slf,))?)
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PyIterProtocol<'_> for CertificateRevocationList {
    fn __iter__(slf: pyo3::PyRef<'p, Self>) -> CRLIterator {
        CRLIterator {
            contents: OwnedCRLIteratorData::try_new(Arc::clone(&slf.raw), |v| {
                Ok::<_, ()>(v.borrow_value().tbs_cert_list.revoked_certificates.clone())
            })
            .unwrap(),
        }
    }
}

#[ouroboros::self_referencing]
struct OwnedCRLIteratorData {
    data: Arc<OwnedRawCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: Option<asn1::SequenceOf<'this, RawRevokedCertificate<'this>>>,
}

#[pyo3::prelude::pyclass]
struct CRLIterator {
    contents: OwnedCRLIteratorData,
}

// Open-coded implementation of the API discussed in
// https://github.com/joshua-maros/ouroboros/issues/38
fn try_map_arc_data_crl<E>(
    crl: &Arc<OwnedRawCertificateRevocationList>,
    f: impl for<'this> FnOnce(
        &'this OwnedRawCertificateRevocationList,
        &pyo3::once_cell::GILOnceCell<Vec<RawRevokedCertificate<'this>>>,
    ) -> Result<RawRevokedCertificate<'this>, E>,
) -> Result<OwnedRawRevokedCertificate, E> {
    OwnedRawRevokedCertificate::try_new(Arc::clone(crl), |inner_crl| {
        crl.with(|value| {
            f(inner_crl, unsafe {
                std::mem::transmute(value.revoked_certs)
            })
        })
    })
}
fn try_map_arc_data_mut_crl_iterator<E>(
    it: &mut OwnedCRLIteratorData,
    f: impl for<'this> FnOnce(
        &'this OwnedRawCertificateRevocationList,
        &mut Option<asn1::SequenceOf<'this, RawRevokedCertificate<'this>>>,
    ) -> Result<RawRevokedCertificate<'this>, E>,
) -> Result<OwnedRawRevokedCertificate, E> {
    OwnedRawRevokedCertificate::try_new(Arc::clone(it.borrow_data()), |inner_it| {
        it.with_value_mut(|value| f(inner_it, unsafe { std::mem::transmute(value) }))
    })
}

#[pyo3::prelude::pyproto]
impl pyo3::PyIterProtocol<'_> for CRLIterator {
    fn __iter__(slf: pyo3::PyRef<'p, Self>) -> pyo3::PyRef<'p, Self> {
        slf
    }

    fn __next__(mut slf: pyo3::PyRefMut<'p, Self>) -> Option<RevokedCertificate> {
        let revoked = try_map_arc_data_mut_crl_iterator(&mut slf.contents, |_data, v| match v {
            Some(v) => match v.next() {
                Some(revoked) => Ok(revoked),
                None => Err(()),
            },
            None => Err(()),
        })
        .ok()?;
        Some(RevokedCertificate {
            raw: revoked,
            cached_extensions: None,
        })
    }
}

#[pyo3::prelude::pyproto]
impl pyo3::PySequenceProtocol<'_> for CRLIterator {
    fn __len__(&self) -> usize {
        self.contents.borrow_value().clone().map_or(0, |v| v.len())
    }
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
struct RawCertificateRevocationList<'a> {
    tbs_cert_list: TBSCertList<'a>,
    signature_algorithm: x509::AlgorithmIdentifier<'a>,
    signature_value: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash)]
struct TBSCertList<'a> {
    version: Option<u8>,
    signature: x509::AlgorithmIdentifier<'a>,
    issuer: x509::Name<'a>,
    this_update: x509::Time,
    next_update: Option<x509::Time>,
    revoked_certificates: Option<asn1::SequenceOf<'a, RawRevokedCertificate<'a>>>,
    #[explicit(0)]
    crl_extensions: Option<x509::Extensions<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, PartialEq, Hash, Clone)]
struct RawRevokedCertificate<'a> {
    user_certificate: asn1::BigUint<'a>,
    revocation_date: x509::Time,
    crl_entry_extensions: Option<x509::Extensions<'a>>,
}

#[ouroboros::self_referencing]
struct OwnedRawRevokedCertificate {
    data: Arc<OwnedRawCertificateRevocationList>,
    #[borrows(data)]
    #[covariant]
    value: RawRevokedCertificate<'this>,
}

#[pyo3::prelude::pyclass]
struct RevokedCertificate {
    raw: OwnedRawRevokedCertificate,
    cached_extensions: Option<pyo3::PyObject>,
}

#[pyo3::prelude::pymethods]
impl RevokedCertificate {
    #[getter]
    fn serial_number<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        big_asn1_uint_to_py(py, self.raw.borrow_value().user_certificate)
    }

    #[getter]
    fn revocation_date<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        x509::chrono_to_py(py, self.raw.borrow_value().revocation_date.as_chrono())
    }

    #[getter]
    fn extensions(&mut self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        x509::parse_and_cache_extensions(
            py,
            &mut self.cached_extensions,
            &self.raw.borrow_value().crl_entry_extensions,
            |oid, ext_data| parse_crl_entry_ext(py, oid.clone(), ext_data),
        )
    }
}

pub(crate) type ReasonFlags<'a> =
    Option<x509::Asn1ReadableOrWritable<'a, asn1::BitString<'a>, asn1::OwnedBitString>>;

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct IssuingDistributionPoint<'a> {
    #[explicit(0)]
    distribution_point: Option<certificate::DistributionPointName<'a>>,

    #[implicit(1)]
    #[default(false)]
    only_contains_user_certs: bool,

    #[implicit(2)]
    #[default(false)]
    only_contains_ca_certs: bool,

    #[implicit(3)]
    only_some_reasons: ReasonFlags<'a>,

    #[implicit(4)]
    #[default(false)]
    indirect_crl: bool,

    #[implicit(5)]
    #[default(false)]
    only_contains_attribute_certs: bool,
}

pub(crate) type CRLReason = asn1::Enumerated;

pub(crate) fn parse_crl_reason_flags<'p>(
    py: pyo3::Python<'p>,
    reason: &CRLReason,
) -> PyAsn1Result<&'p pyo3::PyAny> {
    let x509_module = py.import("cryptography.x509")?;
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
            return Err(PyAsn1Error::from(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported reason code: {}", value),
            )))
        }
    };
    Ok(x509_module.getattr("ReasonFlags")?.getattr(flag_name)?)
}

pub fn parse_crl_entry_ext<'p>(
    py: pyo3::Python<'p>,
    oid: asn1::ObjectIdentifier<'_>,
    data: &[u8],
) -> PyAsn1Result<Option<&'p pyo3::PyAny>> {
    let x509_module = py.import("cryptography.x509")?;
    if oid == *CRL_REASON_OID {
        let flags = parse_crl_reason_flags(py, &asn1::parse_single::<CRLReason>(data)?)?;
        Ok(Some(x509_module.getattr("CRLReason")?.call1((flags,))?))
    } else if oid == *CERTIFICATE_ISSUER_OID {
        let gn_seq = asn1::parse_single::<asn1::SequenceOf<'_, x509::GeneralName<'_>>>(data)?;
        let gns = x509::parse_general_names(py, &gn_seq)?;
        Ok(Some(
            x509_module.getattr("CertificateIssuer")?.call1((gns,))?,
        ))
    } else if oid == *INVALIDITY_DATE_OID {
        let time = asn1::parse_single::<asn1::GeneralizedTime>(data)?;
        let py_dt = x509::chrono_to_py(py, time.as_chrono())?;
        Ok(Some(
            x509_module.getattr("InvalidityDate")?.call1((py_dt,))?,
        ))
    } else {
        Ok(None)
    }
}

#[pyo3::prelude::pyfunction]
fn encode_crl_extension<'p>(
    py: pyo3::Python<'p>,
    ext: &pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let oid = asn1::ObjectIdentifier::from_string(
        ext.getattr("oid")?
            .getattr("dotted_string")?
            .extract::<&str>()?,
    )
    .unwrap();
    if oid == *CRL_NUMBER_OID || oid == *DELTA_CRL_INDICATOR_OID {
        let intval = ext
            .getattr("value")?
            .getattr("crl_number")?
            .downcast::<pyo3::types::PyLong>()?;
        let bytes = py_uint_to_big_endian_bytes(py, intval)?;
        let result = asn1::write_single(&asn1::BigUint::new(bytes).unwrap());
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *ISSUING_DISTRIBUTION_POINT_OID {
        let py_idp = ext.getattr("value")?;

        let only_some_reasons = if py_idp.getattr("only_some_reasons")?.is_true()? {
            let py_reasons = py_idp.getattr("only_some_reasons")?;
            let reasons = certificate::encode_distribution_point_reasons(py, py_reasons)?;
            Some(x509::Asn1ReadableOrWritable::new_write(reasons))
        } else {
            None
        };
        let distribution_point = if py_idp.getattr("full_name")?.is_true()? {
            let gns = x509::common::encode_general_names(py, py_idp.getattr("full_name")?)?;
            Some(certificate::DistributionPointName::FullName(
                x509::Asn1ReadableOrWritable::new_write(asn1::SequenceOfWriter::new(gns)),
            ))
        } else if py_idp.getattr("relative_name")?.is_true()? {
            let mut name_entries = vec![];
            for py_name_entry in py_idp.getattr("relative_name")?.iter()? {
                name_entries.push(x509::common::encode_name_entry(py, py_name_entry?)?);
            }
            Some(certificate::DistributionPointName::NameRelativeToCRLIssuer(
                x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(name_entries)),
            ))
        } else {
            None
        };

        let idp = IssuingDistributionPoint {
            distribution_point,
            indirect_crl: py_idp.getattr("indirect_crl")?.extract()?,
            only_contains_attribute_certs: py_idp
                .getattr("only_contains_attribute_certs")?
                .extract()?,
            only_contains_ca_certs: py_idp.getattr("only_contains_ca_certs")?.extract()?,
            only_contains_user_certs: py_idp.getattr("only_contains_user_certs")?.extract()?,
            only_some_reasons,
        };
        let result = asn1::write_single(&idp);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *FRESHEST_CRL_OID {
        let dps = certificate::encode_distribution_points(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(dps));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *AUTHORITY_INFORMATION_ACCESS_OID {
        let py_ads = ext.getattr("value")?;
        let ads = x509::common::encode_access_descriptions(py, py_ads)?;
        let result = asn1::write_single(&ads);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *ISSUER_ALTERNATIVE_NAME_OID {
        let gns = x509::common::encode_general_names(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(gns));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *AUTHORITY_KEY_IDENTIFIER_OID {
        let aki = x509::certificate::encode_authority_key_identifier(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&aki);
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
            "Extension not supported: {}",
            oid
        )))
    }
}

#[pyo3::prelude::pyfunction]
fn encode_crl_entry_extension<'p>(
    py: pyo3::Python<'p>,
    ext: &pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let oid = asn1::ObjectIdentifier::from_string(
        ext.getattr("oid")?
            .getattr("dotted_string")?
            .extract::<&str>()?,
    )
    .unwrap();

    if oid == *CRL_REASON_OID {
        let value = py
            .import("cryptography.hazmat.backends.openssl.decode_asn1")?
            .getattr("_CRL_ENTRY_REASON_ENUM_TO_CODE")?
            .get_item(ext.getattr("value")?.getattr("reason")?)?
            .extract::<u32>()?;
        let result = asn1::write_single(&asn1::Enumerated::new(value));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *CERTIFICATE_ISSUER_OID {
        let gns = x509::common::encode_general_names(py, ext.getattr("value")?)?;
        let result = asn1::write_single(&asn1::SequenceOfWriter::new(gns));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else if oid == *INVALIDITY_DATE_OID {
        let chrono_dt = x509::py_to_chrono(ext.getattr("value")?.getattr("invalidity_date")?)?;
        let result = asn1::write_single(&asn1::GeneralizedTime::new(chrono_dt));
        Ok(pyo3::types::PyBytes::new(py, &result))
    } else {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
            "Extension not supported: {}",
            oid,
        )))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_wrapped(pyo3::wrap_pyfunction!(load_der_x509_crl))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(load_pem_x509_crl))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(encode_crl_extension))?;
    module.add_wrapped(pyo3::wrap_pyfunction!(encode_crl_entry_extension))?;

    module.add_class::<CertificateRevocationList>()?;
    module.add_class::<RevokedCertificate>()?;

    Ok(())
}
