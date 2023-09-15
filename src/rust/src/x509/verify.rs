// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509_validation::{
    ops::CryptoOps,
    policy::{Policy, Subject},
    types::{DNSName, IPAddress},
};
use pyo3::IntoPy;

use crate::error::{CryptographyError, CryptographyResult};
use crate::types;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::common::{datetime_now, datetime_to_py, py_to_datetime};
use crate::x509::sign;

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    type Key = pyo3::Py<pyo3::PyAny>;
    type Err = CryptographyError;

    fn public_key(&self, cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
        pyo3::Python::with_gil(|py| -> Result<Self::Key, Self::Err> {
            // This makes an unnecessary copy. It'd be nice to get rid of it.
            let spki_der = pyo3::types::PyBytes::new(py, &asn1::write_single(&cert.tbs_cert.spki)?);

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

struct FixedPolicy<'a>(Policy<'a, PyCryptoOps>);

/// This enum exists solely to provide heterogeneously typed ownership for `OwnedPolicy`.
enum SubjectOwner {
    // NOTE: This is ugly, but is effectively the easiest way to use a uniform
    // `OwnedPolicy` API when policies aren't strictly required to contain a subject.
    None,
    // TODO: Switch this to `Py<PyString>` once Pyo3's `to_str()` preserves a
    // lifetime relationship between an a `PyString` and its borrowed `&str`
    // reference in all limited API builds. PyO3 can't currently do that in
    // older limited API builds because it needs `PyUnicode_AsUTF8AndSize` to do
    // so, which was only stabilized with 3.10.
    DNSName((pyo3::Py<pyo3::PyAny>, String)),
    IPAddress((pyo3::Py<pyo3::PyAny>, pyo3::Py<pyo3::types::PyBytes>)),
}

self_cell::self_cell!(
    struct OwnedPolicy {
        owner: SubjectOwner,

        #[covariant]
        dependent: FixedPolicy,
    }
);

#[pyo3::pyclass(
    name = "ServerVerifier",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyServerVerifier(OwnedPolicy);

impl PyServerVerifier {
    fn as_policy(&self) -> &Policy<'_, PyCryptoOps> {
        &self.0.borrow_dependent().0
    }
}

#[pyo3::pymethods]
impl PyServerVerifier {
    #[getter]
    fn subject<'p>(&'p self, py: pyo3::Python<'p>) -> pyo3::PyResult<Option<&'p pyo3::PyAny>> {
        match self.0.borrow_owner() {
            SubjectOwner::None => Ok(None),
            SubjectOwner::DNSName((subject, _)) => Ok(Some(subject.as_ref(py))),
            SubjectOwner::IPAddress((subject, _)) => Ok(Some(subject.as_ref(py))),
        }
    }

    #[getter]
    fn validation_time<'p>(&self, py: pyo3::Python<'p>) -> pyo3::PyResult<&'p pyo3::PyAny> {
        datetime_to_py(py, &self.as_policy().validation_time)
    }
}

fn build_subject_owner(
    py: pyo3::Python<'_>,
    subject: pyo3::Py<pyo3::PyAny>,
) -> pyo3::PyResult<SubjectOwner> {
    let subject = subject.as_ref(py);

    if subject.is_none() {
        return Ok(SubjectOwner::None);
    }

    let x509_general_name_module =
        py.import(pyo3::intern!(py, "cryptography.x509.general_name"))?;
    let dns_name_class = x509_general_name_module.getattr(pyo3::intern!(py, "DNSName"))?;
    let ip_address_class = x509_general_name_module.getattr(pyo3::intern!(py, "IPAddress"))?;

    if subject.is_instance(dns_name_class)? {
        let value = subject
            .getattr(pyo3::intern!(py, "value"))?
            .downcast::<pyo3::types::PyString>()?;

        Ok(SubjectOwner::DNSName((
            subject.into_py(py),
            value.to_str()?.to_owned(),
        )))
    } else if subject.is_instance(ip_address_class)? {
        let value = subject
            .getattr(pyo3::intern!(py, "_packed"))?
            .call0()?
            .downcast::<pyo3::types::PyBytes>()?;

        Ok(SubjectOwner::IPAddress((subject.into_py(py), value.into())))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "unsupported subject type",
        ))
    }
}

fn build_subject<'a>(
    py: pyo3::Python<'_>,
    subject: &'a SubjectOwner,
) -> pyo3::PyResult<Option<Subject<'a>>> {
    match subject {
        SubjectOwner::None => Ok(None),
        SubjectOwner::DNSName((_, dns_name)) => {
            let dns_name = DNSName::new(dns_name)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid domain name"))?;

            Ok(Some(Subject::DNS(dns_name)))
        }
        SubjectOwner::IPAddress((_, ip_addr)) => {
            let ip_addr = IPAddress::from_bytes(ip_addr.as_bytes(py))
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid IP address"))?;

            Ok(Some(Subject::IP(ip_addr)))
        }
    }
}

#[pyo3::prelude::pyfunction]
fn create_server_verifier(
    py: pyo3::Python<'_>,
    subject: pyo3::Py<pyo3::PyAny>,
    time: Option<&pyo3::PyAny>,
) -> pyo3::PyResult<PyServerVerifier> {
    let time = match time {
        Some(time) => py_to_datetime(py, time)?,
        None => datetime_now(py)?,
    };

    let subject_owner = build_subject_owner(py, subject)?;
    let policy = OwnedPolicy::try_new(subject_owner, |subject_owner| {
        let subject = build_subject(py, subject_owner)?;
        Ok::<FixedPolicy<'_>, pyo3::PyErr>(FixedPolicy(Policy::webpki(
            PyCryptoOps {},
            subject,
            time,
        )))
    })?;

    Ok(PyServerVerifier(policy))
}

#[pyo3::pyclass(
    frozen,
    name = "Store",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyStore(Vec<pyo3::Py<PyCertificate>>);

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new(certs: Vec<pyo3::Py<PyCertificate>>) -> pyo3::PyResult<Self> {
        if certs.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty store",
            ));
        }
        Ok(Self(certs))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyServerVerifier>()?;
    module.add_class::<PyStore>()?;
    module.add_function(pyo3::wrap_pyfunction!(create_server_verifier, module)?)?;

    Ok(())
}
