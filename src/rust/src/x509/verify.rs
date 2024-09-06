// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::{
    certificate::Certificate,
    extensions::SubjectAlternativeName,
    oid::{ALL_EKU_OIDS, SUBJECT_ALTERNATIVE_NAME_OID},
};
use cryptography_x509_verification::{
    ops::{CryptoOps, VerificationCertificate},
    policy::{ExtensionPolicy, Policy, Subject},
    trust_store::Store,
    types::{DNSName, IPAddress},
};
use pyo3::{
    types::{PyAnyMethods, PyListMethods},
    ToPyObject,
};

use crate::error::{CryptographyError, CryptographyResult};
use crate::types;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::common::{datetime_now, datetime_to_py, py_to_datetime};
use crate::x509::sign;
use crate::{asn1::py_oid_to_oid, backend::keys};

use super::parse_general_names;

#[derive(Clone)]
pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;
    type Err = CryptographyError;
    type CertificateExtra = pyo3::Py<PyCertificate>;

    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
        pyo3::Python::with_gil(|py| -> Result<Self::Key, Self::Err> {
            keys::load_der_public_key_bytes(py, cert.tbs_cert.spki.tlv().full_data())
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
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
        })
    }

    fn store(&self, new_store: pyo3::Py<PyStore>) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, store, "trust store");

        Ok(PolicyBuilder {
            time: self.time.clone(),
            store: Some(new_store),
            max_chain_depth: self.max_chain_depth,
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, max_chain_depth, "maximum chain depth");

        Ok(PolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: Some(new_max_chain_depth),
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        build_client_verifier_impl(py, &self.store, &self.time, |time| {
            Policy::client(PyCryptoOps {}, time, self.max_chain_depth)
        })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        build_server_verifier_impl(py, &self.store, &self.time, subject, |subject, time| {
            Policy::server(PyCryptoOps {}, subject, time, self.max_chain_depth)
        })
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.x509.verification")]
pub(crate) struct CustomPolicyBuilder {
    time: Option<asn1::DateTime>,
    store: Option<pyo3::Py<PyStore>>,
    max_chain_depth: Option<u8>,
    eku: Option<asn1::ObjectIdentifier>,
    ca_ext_policy: Option<ExtensionPolicy<PyCryptoOps>>,
    ee_ext_policy: Option<ExtensionPolicy<PyCryptoOps>>,
}

impl CustomPolicyBuilder {
    /// Clones the builder, requires the GIL token to increase
    /// reference count for `self.store`.
    fn py_clone(&self, py: pyo3::Python<'_>) -> CustomPolicyBuilder {
        CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        }
    }
}

#[pyo3::pymethods]
impl CustomPolicyBuilder {
    #[new]
    fn new() -> CustomPolicyBuilder {
        CustomPolicyBuilder {
            time: None,
            store: None,
            max_chain_depth: None,
            eku: None,
            ca_ext_policy: None,
            ee_ext_policy: None,
        }
    }

    fn time(
        &self,
        py: pyo3::Python<'_>,
        new_time: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, time, "validation time");

        Ok(CustomPolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            ..self.py_clone(py)
        })
    }

    fn store(
        &self,
        py: pyo3::Python<'_>,
        new_store: pyo3::Py<PyStore>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, store, "trust store");

        Ok(CustomPolicyBuilder {
            store: Some(new_store),
            ..self.py_clone(py)
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, max_chain_depth, "maximum chain depth");

        Ok(CustomPolicyBuilder {
            max_chain_depth: Some(new_max_chain_depth),
            ..self.py_clone(py)
        })
    }

    fn eku(
        &self,
        py: pyo3::Python<'_>,
        new_eku: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, eku, "EKU");

        let oid = py_oid_to_oid(new_eku)?;

        if !ALL_EKU_OIDS.contains(&oid) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Unknown EKU OID. Only EKUs from x509.ExtendedKeyUsageOID are supported.",
                ),
            ));
        }

        Ok(CustomPolicyBuilder {
            eku: Some(oid),
            ..self.py_clone(py)
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        build_client_verifier_impl(py, &self.store, &self.time, |time| {
            // TODO: Replace with a custom policy once it's implemented in cryptography-x509-verification
            Policy::client(PyCryptoOps {}, time, self.max_chain_depth)
        })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        build_server_verifier_impl(py, &self.store, &self.time, subject, |subject, time| {
            // TODO: Replace with a custom policy once it's implemented in cryptography-x509-verification
            Policy::server(PyCryptoOps {}, subject, time, self.max_chain_depth)
        })
    }
}

/// This is a helper to avoid code duplication between PolicyBuilder and CustomPolicyBuilder.
fn build_server_verifier_impl(
    py: pyo3::Python<'_>,
    store: &Option<pyo3::Py<PyStore>>,
    time: &Option<asn1::DateTime>,
    subject: pyo3::PyObject,
    make_policy: impl Fn(Subject<'_>, asn1::DateTime) -> PyCryptoPolicy<'_>,
) -> CryptographyResult<PyServerVerifier> {
    let store = match store {
        Some(s) => s.clone_ref(py),
        None => {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "A server verifier must have a trust store.",
                ),
            ));
        }
    };

    let time = match time.as_ref() {
        Some(t) => t.clone(),
        None => datetime_now(py)?,
    };
    let subject_owner = build_subject_owner(py, &subject)?;

    let policy = OwnedPolicy::try_new(subject_owner, |subject_owner| {
        let subject = build_subject(py, subject_owner)?;
        Ok::<PyCryptoPolicy<'_>, pyo3::PyErr>(make_policy(subject, time))
    })?;

    Ok(PyServerVerifier {
        py_subject: subject,
        policy,
        store,
    })
}

/// This is a helper to avoid code duplication between PolicyBuilder and CustomPolicyBuilder.
fn build_client_verifier_impl(
    py: pyo3::Python<'_>,
    store: &Option<pyo3::Py<PyStore>>,
    time: &Option<asn1::DateTime>,
    make_policy: impl Fn(asn1::DateTime) -> PyCryptoPolicy<'static>,
) -> CryptographyResult<PyClientVerifier> {
    let store = match store.as_ref() {
        Some(s) => s.clone_ref(py),
        None => {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "A client verifier must have a trust store.",
                ),
            ));
        }
    };

    let time = match time.as_ref() {
        Some(t) => t.clone(),
        None => datetime_now(py)?,
    };

    Ok(PyClientVerifier {
        policy: make_policy(time),
        store,
    })
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
    subject: pyo3::Py<pyo3::PyAny>,
    #[pyo3(get)]
    sans: Option<pyo3::Py<pyo3::PyAny>>,
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
            .map(|i| {
                VerificationCertificate::new(
                    i.get().raw.borrow_dependent().clone(),
                    i.clone_ref(py),
                )
            })
            .collect::<Vec<_>>();
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();

        let v = VerificationCertificate::new(
            leaf.get().raw.borrow_dependent().clone(),
            leaf.clone_ref(py),
        );

        let chain = cryptography_x509_verification::verify(
            &v,
            &intermediate_refs,
            policy,
            store.raw.borrow_dependent(),
        )
        .map_err(|e| VerificationError::new_err(format!("validation failed: {e}")))?;

        let py_chain = pyo3::types::PyList::empty_bound(py);
        for c in &chain {
            py_chain.append(c.extra())?;
        }

        let cert = &chain[0].certificate();

        let py_sans = || -> pyo3::PyResult<Option<pyo3::PyObject>> {
            let leaf_san_ext = cert
                .extensions()
                .ok()
                .unwrap()
                .get_extension(&SUBJECT_ALTERNATIVE_NAME_OID);

            match leaf_san_ext {
                Some(leaf_san) => {
                    let leaf_gns = leaf_san
                        .value::<SubjectAlternativeName<'_>>()
                        .map_err(|e| -> CryptographyError { e.into() })?;
                    let py_gns = parse_general_names(py, &leaf_gns)?;
                    Ok(Some(py_gns))
                }
                None => Ok(None),
            }
        }()?;

        let py_subject = crate::x509::parse_name(py, cert.subject())?;

        Ok(PyVerifiedClient {
            subject: py_subject.to_object(py),
            sans: py_sans,
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
            .map(|i| {
                VerificationCertificate::new(
                    i.get().raw.borrow_dependent().clone(),
                    i.clone_ref(py),
                )
            })
            .collect::<Vec<_>>();
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();

        let v = VerificationCertificate::new(
            leaf.get().raw.borrow_dependent().clone(),
            leaf.clone_ref(py),
        );

        let chain = cryptography_x509_verification::verify(
            &v,
            &intermediate_refs,
            policy,
            store.raw.borrow_dependent(),
        )
        .map_err(|e| VerificationError::new_err(format!("validation failed: {e:?}")))?;

        let result = pyo3::types::PyList::empty_bound(py);
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
                    VerificationCertificate::new(
                        t.get().raw.borrow_dependent().clone(),
                        t.clone_ref(py),
                    )
                }))
            }),
        })
    }
}
