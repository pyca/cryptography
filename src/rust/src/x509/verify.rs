// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509::extensions::SubjectAlternativeName;
use cryptography_x509::oid::SUBJECT_ALTERNATIVE_NAME_OID;
use cryptography_x509_verification::ops::{CryptoOps, VerificationCertificate};
use cryptography_x509_verification::policy::{Policy, Subject};
use cryptography_x509_verification::trust_store::Store;
use cryptography_x509_verification::types::{DNSName, IPAddress};
use pyo3::types::{PyAnyMethods, PyListMethods};

use super::parse_general_names;
use crate::backend::keys;
use crate::error::{CryptographyError, CryptographyResult};
use crate::types;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::common::{datetime_now, datetime_to_py, py_to_datetime};
use crate::x509::sign;

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;
    type Err = CryptographyError;
    type CertificateExtra = pyo3::Py<PyCertificate>;

    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
        pyo3::Python::with_gil(|py| -> Result<Self::Key, Self::Err> {
            Ok(keys::load_der_public_key_bytes(py, cert.tbs_cert.spki.tlv().full_data())?.unbind())
        })
    }

    fn verify_signed_by(&self, cert: &Certificate<'_>, key: &Self::Key) -> Result<(), Self::Err> {
        pyo3::Python::with_gil(|py| -> CryptographyResult<()> {
            sign::verify_signature_with_signature_algorithm(
                py,
                key.bind(py).clone(),
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &asn1::write_single(&cert.tbs_cert)?,
            )
        })
    }

    fn clone_public_key(key: &Self::Key) -> Self::Key {
        pyo3::Python::with_gil(|py| key.clone_ref(py))
    }

    fn clone_extra(extra: &Self::CertificateExtra) -> Self::CertificateExtra {
        pyo3::Python::with_gil(|py| extra.clone_ref(py))
    }
}

pyo3::create_exception!(
    cryptography.hazmat.bindings._rust.x509,
    VerificationError,
    pyo3::exceptions::PyException
);

macro_rules! policy_builder_set_once_check {
    ($self: ident, $property: ident, $human_readable_name: literal) => {
        if $self.$property.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(concat!(
                    "The ",
                    $human_readable_name,
                    " may only be set once."
                )),
            ));
        }
    };
}

#[pyo3::pyclass(frozen, module = "cryptography.x509.verification")]
pub(crate) struct PolicyBuilder {
    time: Option<asn1::DateTime>,
    store: Option<pyo3::Py<PyStore>>,
    max_chain_depth: Option<u8>,
}

impl PolicyBuilder {
    fn py_clone(&self, py: pyo3::Python<'_>) -> PolicyBuilder {
        PolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
        }
    }
}

#[pyo3::pymethods]
impl PolicyBuilder {
    #[new]
    fn new() -> PolicyBuilder {
        PolicyBuilder {
            time: None,
            store: None,
            max_chain_depth: None,
        }
    }

    fn time(
        &self,
        py: pyo3::Python<'_>,
        new_time: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, time, "validation time");

        Ok(PolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            ..self.py_clone(py)
        })
    }

    fn store(
        &self,
        py: pyo3::Python<'_>,
        new_store: pyo3::Py<PyStore>,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, store, "trust store");

        Ok(PolicyBuilder {
            store: Some(new_store),
            ..self.py_clone(py)
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, max_chain_depth, "maximum chain depth");

        Ok(PolicyBuilder {
            max_chain_depth: Some(new_max_chain_depth),
            ..self.py_clone(py)
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        let store = match self.store.as_ref() {
            Some(s) => s.clone_ref(py),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "A client verifier must have a trust store.",
                    ),
                ));
            }
        };

        let time = match self.time.as_ref() {
            Some(t) => t.clone(),
            None => datetime_now(py)?,
        };

        // TODO: Pass extension policies here once implemented in cryptography-x509-verification.
        let policy = Policy::client(PyCryptoOps {}, time, self.max_chain_depth);

        Ok(PyClientVerifier { policy, store })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        let store = match self.store.as_ref() {
            Some(s) => s.clone_ref(py),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "A server verifier must have a trust store.",
                    ),
                ));
            }
        };

        let time = match self.time.as_ref() {
            Some(t) => t.clone(),
            None => datetime_now(py)?,
        };
        let subject_owner = build_subject_owner(py, &subject)?;

        let policy = OwnedPolicy::try_new(subject_owner, |subject_owner| {
            let subject = build_subject(py, subject_owner)?;

            // TODO: Pass extension policies here once implemented in cryptography-x509-verification.
            Ok::<PyCryptoPolicy<'_>, pyo3::PyErr>(Policy::server(
                PyCryptoOps {},
                subject,
                time,
                self.max_chain_depth,
            ))
        })?;

        Ok(PyServerVerifier {
            py_subject: subject,
            policy,
            store,
        })
    }
}

type PyCryptoPolicy<'a> = Policy<'a, PyCryptoOps>;

/// This enum exists solely to provide heterogeneously typed ownership for `OwnedPolicy`.
enum SubjectOwner {
    // TODO: Switch this to `Py<PyString>` once Pyo3's `to_str()` preserves a
    // lifetime relationship between an a `PyString` and its borrowed `&str`
    // reference in all limited API builds. PyO3 can't currently do that in
    // older limited API builds because it needs `PyUnicode_AsUTF8AndSize` to do
    // so, which was only stabilized with 3.10.
    DNSName(String),
    IPAddress(pyo3::Py<pyo3::types::PyBytes>),
}

self_cell::self_cell!(
    struct OwnedPolicy {
        owner: SubjectOwner,

        #[covariant]
        dependent: PyCryptoPolicy,
    }
);

#[pyo3::pyclass(
    frozen,
    name = "VerifiedClient",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
pub(crate) struct PyVerifiedClient {
    #[pyo3(get)]
    subjects: Option<pyo3::Py<pyo3::PyAny>>,
    #[pyo3(get)]
    chain: pyo3::Py<pyo3::types::PyList>,
}

#[pyo3::pyclass(
    frozen,
    name = "ClientVerifier",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
pub(crate) struct PyClientVerifier {
    policy: PyCryptoPolicy<'static>,
    #[pyo3(get)]
    store: pyo3::Py<PyStore>,
}

impl PyClientVerifier {
    fn as_policy(&self) -> &Policy<'_, PyCryptoOps> {
        &self.policy
    }
}

#[pyo3::pymethods]
impl PyClientVerifier {
    #[getter]
    fn validation_time<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        datetime_to_py(py, &self.as_policy().validation_time)
    }

    #[getter]
    fn max_chain_depth(&self) -> u8 {
        self.as_policy().max_chain_depth
    }

    fn verify(
        &self,
        py: pyo3::Python<'_>,
        leaf: pyo3::Py<PyCertificate>,
        intermediates: Vec<pyo3::Py<PyCertificate>>,
    ) -> CryptographyResult<PyVerifiedClient> {
        let policy = self.as_policy();
        let store = self.store.get();

        let intermediates = intermediates
            .iter()
            .map(|i| VerificationCertificate::new(i.get().raw.borrow_dependent(), i.clone_ref(py)))
            .collect::<Vec<_>>();

        let v = VerificationCertificate::new(leaf.get().raw.borrow_dependent(), leaf.clone_ref(py));

        let chain = cryptography_x509_verification::verify(
            &v,
            &intermediates,
            policy,
            store.raw.borrow_dependent(),
        )
        .or_else(|e| handle_validation_error(py, e))?;

        let py_chain = pyo3::types::PyList::empty(py);
        for c in &chain {
            py_chain.append(c.extra())?;
        }

        // NOTE: These `unwrap()`s cannot fail, since the underlying policy
        // enforces the presence of a SAN and the well-formedness of the
        // extension set.
        let leaf_san = &chain[0]
            .certificate()
            .extensions()
            .ok()
            .unwrap()
            .get_extension(&SUBJECT_ALTERNATIVE_NAME_OID)
            .unwrap();

        let leaf_gns = leaf_san.value::<SubjectAlternativeName<'_>>()?;
        let py_gns = parse_general_names(py, &leaf_gns)?;

        Ok(PyVerifiedClient {
            subjects: Some(py_gns.into()),
            chain: py_chain.unbind(),
        })
    }
}

#[pyo3::pyclass(
    frozen,
    name = "ServerVerifier",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
pub(crate) struct PyServerVerifier {
    #[pyo3(get, name = "subject")]
    py_subject: pyo3::Py<pyo3::PyAny>,
    policy: OwnedPolicy,
    #[pyo3(get)]
    store: pyo3::Py<PyStore>,
}

impl PyServerVerifier {
    fn as_policy(&self) -> &Policy<'_, PyCryptoOps> {
        self.policy.borrow_dependent()
    }
}

#[pyo3::pymethods]
impl PyServerVerifier {
    #[getter]
    fn validation_time<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        datetime_to_py(py, &self.as_policy().validation_time)
    }

    #[getter]
    fn max_chain_depth(&self) -> u8 {
        self.as_policy().max_chain_depth
    }

    fn verify<'p>(
        &self,
        py: pyo3::Python<'p>,
        leaf: pyo3::Py<PyCertificate>,
        intermediates: Vec<pyo3::Py<PyCertificate>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyList>> {
        let policy = self.as_policy();
        let store = self.store.get();

        let intermediates = intermediates
            .iter()
            .map(|i| VerificationCertificate::new(i.get().raw.borrow_dependent(), i.clone_ref(py)))
            .collect::<Vec<_>>();

        let v = VerificationCertificate::new(leaf.get().raw.borrow_dependent(), leaf.clone_ref(py));

        let chain = cryptography_x509_verification::verify(
            &v,
            &intermediates,
            policy,
            store.raw.borrow_dependent(),
        )
        .or_else(|e| handle_validation_error(py, e))?;

        let result = pyo3::types::PyList::empty(py);
        for c in chain {
            result.append(c.extra())?;
        }
        Ok(result)
    }
}

fn build_subject_owner(
    py: pyo3::Python<'_>,
    subject: &pyo3::Py<pyo3::PyAny>,
) -> pyo3::PyResult<SubjectOwner> {
    let subject = subject.bind(py);

    if subject.is_instance(&types::DNS_NAME.get(py)?)? {
        let value = subject
            .getattr(pyo3::intern!(py, "value"))?
            // TODO: switch this to borrowing the string (using Bound::to_str) once our
            // minimum Python version is 3.10
            .extract::<String>()?;
        Ok(SubjectOwner::DNSName(value))
    } else if subject.is_instance(&types::IP_ADDRESS.get(py)?)? {
        let value = subject
            .getattr(pyo3::intern!(py, "_packed"))?
            .call0()?
            .downcast::<pyo3::types::PyBytes>()?
            .clone();
        Ok(SubjectOwner::IPAddress(value.unbind()))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "unsupported subject type",
        ))
    }
}

fn build_subject<'a>(
    py: pyo3::Python<'_>,
    subject: &'a SubjectOwner,
) -> pyo3::PyResult<Subject<'a>> {
    match subject {
        SubjectOwner::DNSName(dns_name) => {
            let dns_name = DNSName::new(dns_name)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid domain name"))?;

            Ok(Subject::DNS(dns_name))
        }
        SubjectOwner::IPAddress(ip_addr) => {
            let ip_addr = IPAddress::from_bytes(ip_addr.as_bytes(py))
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid IP address"))?;

            Ok(Subject::IP(ip_addr))
        }
    }
}

fn handle_validation_error<T>(
    py: pyo3::Python<'_>,
    e: cryptography_x509_verification::ValidationError<'_, PyCryptoOps>,
) -> CryptographyResult<T> {
    let mut msg = format!("validation failed: {e}");
    if let Some(cert) = e.certificate() {
        let cert_repr = cert.extra().bind(py).repr()?;
        msg = format!("{msg} (encountered processing {cert_repr})");
    }

    Err(CryptographyError::from(VerificationError::new_err(msg)))
}

type PyCryptoOpsStore<'a> = Store<'a, PyCryptoOps>;

self_cell::self_cell!(
    struct RawPyStore {
        owner: Vec<pyo3::Py<PyCertificate>>,

        #[covariant]
        dependent: PyCryptoOpsStore,
    }
);

#[pyo3::pyclass(
    frozen,
    name = "Store",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
pub(crate) struct PyStore {
    raw: RawPyStore,
}

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new(py: pyo3::Python<'_>, certs: Vec<pyo3::Py<PyCertificate>>) -> pyo3::PyResult<Self> {
        if certs.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty store",
            ));
        }
        Ok(Self {
            raw: RawPyStore::new(certs, |v| {
                Store::new(v.iter().map(|t| {
                    VerificationCertificate::new(t.get().raw.borrow_dependent(), t.clone_ref(py))
                }))
            }),
        })
    }
}
