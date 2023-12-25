// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509_verification::{
    ops::CryptoOps,
    policy::{Policy, Subject},
    trust_store::Store,
    types::{DNSName, IPAddress},
};

use crate::types;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::common::{datetime_now, datetime_to_py, py_to_datetime};
use crate::x509::sign;
use crate::{
    error::{CryptographyError, CryptographyResult},
    exceptions::VerificationError,
};

use super::certificate::OwnedCertificate;

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;
    type Err = CryptographyError;

    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
        pyo3::Python::with_gil(|py| -> Result<Self::Key, Self::Err> {
            // This makes an unnecessary copy. It'd be nice to get rid of it.
            let spki_der = pyo3::types::PyBytes::new(py, cert.tbs_cert.spki.tlv().full_data());

            Ok(types::LOAD_DER_PUBLIC_KEY
                .get(py)?
                .call1((spki_der,))?
                .into())
        })
    }

    fn verify_signed_by(&self, cert: &Certificate<'_>, key: Self::Key) -> Result<(), Self::Err> {
        pyo3::Python::with_gil(|py| -> CryptographyResult<()> {
            sign::verify_signature_with_signature_algorithm(
                py,
                key.as_ref(py),
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &asn1::write_single(&cert.tbs_cert)?,
            )
        })
    }
}

struct PyCryptoPolicy<'a>(Policy<'a, PyCryptoOps>);

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
    name = "ServerVerifier",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyServerVerifier {
    #[pyo3(get, name = "subject")]
    py_subject: pyo3::Py<pyo3::PyAny>,
    policy: OwnedPolicy,
    #[pyo3(get)]
    store: pyo3::Py<PyStore>,
}

impl PyServerVerifier {
    fn as_policy(&self) -> &Policy<'_, PyCryptoOps> {
        &self.policy.borrow_dependent().0
    }
}

#[pyo3::pymethods]
impl PyServerVerifier {
    #[getter]
    fn validation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        datetime_to_py(py, &self.as_policy().validation_time)
    }

    #[getter]
    fn max_chain_depth(&self) -> u8 {
        self.as_policy().max_chain_depth
    }

    fn verify<'p>(
        &self,
        py: pyo3::Python<'p>,
        leaf: &PyCertificate,
        intermediates: Vec<pyo3::PyRef<'p, PyCertificate>>,
    ) -> CryptographyResult<Vec<PyCertificate>> {
        let policy = self.as_policy();
        let store = self.store.as_ref(py).borrow();

        let chain = cryptography_x509_verification::verify(
            leaf.raw.borrow_dependent(),
            intermediates
                .iter()
                .map(|i| i.raw.borrow_dependent().clone()),
            policy,
            store.raw.borrow_dependent(),
        )
        .map_err(|e| VerificationError::new_err(format!("validation failed: {e:?}")))?;

        // TODO: Optimize this? Turning a Certificate back into a PyCertificate
        // involves a full round-trip back through DER, which isn't ideal.
        chain
            .iter()
            .map(|c| {
                let raw = pyo3::types::PyBytes::new(py, &asn1::write_single(c)?);
                Ok(PyCertificate {
                    raw: OwnedCertificate::try_new(raw.into(), |raw| {
                        asn1::parse_single(raw.as_bytes(py))
                    })?,
                    cached_extensions: pyo3::sync::GILOnceCell::new(),
                })
            })
            .collect()
    }
}

fn build_subject_owner(
    py: pyo3::Python<'_>,
    subject: &pyo3::Py<pyo3::PyAny>,
) -> pyo3::PyResult<SubjectOwner> {
    let subject = subject.as_ref(py);

    if subject.is_instance(types::DNS_NAME.get(py)?)? {
        let value = subject
            .getattr(pyo3::intern!(py, "value"))?
            .downcast::<pyo3::types::PyString>()?;

        Ok(SubjectOwner::DNSName(value.to_str()?.to_owned()))
    } else if subject.is_instance(types::IP_ADDRESS.get(py)?)? {
        let value = subject
            .getattr(pyo3::intern!(py, "_packed"))?
            .call0()?
            .downcast::<pyo3::types::PyBytes>()?;

        Ok(SubjectOwner::IPAddress(value.into()))
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

#[pyo3::prelude::pyfunction]
fn create_server_verifier(
    py: pyo3::Python<'_>,
    subject: pyo3::Py<pyo3::PyAny>,
    store: pyo3::Py<PyStore>,
    time: Option<&pyo3::PyAny>,
    max_chain_depth: Option<u8>,
) -> pyo3::PyResult<PyServerVerifier> {
    let time = match time {
        Some(time) => py_to_datetime(py, time)?,
        None => datetime_now(py)?,
    };

    let subject_owner = build_subject_owner(py, &subject)?;
    let policy = OwnedPolicy::try_new(subject_owner, |subject_owner| {
        let subject = build_subject(py, subject_owner)?;
        Ok::<PyCryptoPolicy<'_>, pyo3::PyErr>(PyCryptoPolicy(Policy::new(
            PyCryptoOps {},
            subject,
            time,
            max_chain_depth,
        )))
    })?;

    Ok(PyServerVerifier {
        py_subject: subject,
        policy,
        store,
    })
}

self_cell::self_cell!(
    struct RawPyStore {
        owner: Vec<pyo3::Py<PyCertificate>>,

        #[covariant]
        dependent: Store,
    }
);

#[pyo3::pyclass(
    frozen,
    name = "Store",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyStore {
    raw: RawPyStore,
}

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new(certs: Vec<pyo3::Py<PyCertificate>>) -> pyo3::PyResult<Self> {
        if certs.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty store",
            ));
        }
        Ok(Self {
            raw: RawPyStore::new(certs, |v| {
                Store::new(v.iter().map(|t| t.get().raw.borrow_dependent().clone()))
            }),
        })
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyServerVerifier>()?;
    module.add_class::<PyStore>()?;
    module.add_function(pyo3::wrap_pyfunction!(create_server_verifier, module)?)?;

    Ok(())
}
