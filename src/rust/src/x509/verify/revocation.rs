use cryptography_x509_verification::{
    ops::VerificationCertificate,
    policy::Policy,
    revocation::{CheckRevocation, CrlRevocationChecker, RevocationChecker},
    ValidationResult,
};

use crate::x509::{crl::CertificateRevocationList, verify::PyCryptoOps};

self_cell::self_cell!(
    pub(crate) struct RawPyCrlRevocationChecker {
        owner: Vec<pyo3::Py<CertificateRevocationList>>,

        #[covariant]
        dependent: CrlRevocationChecker,
    }
);

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.x509",
    name = "CRLRevocationChecker",
    extends = PyRevocationChecker,
)]
pub(crate) struct PyCrlRevocationChecker {
    pub(crate) raw: RawPyCrlRevocationChecker,
}

#[pyo3::pymethods]
impl PyCrlRevocationChecker {
    #[new]
    fn new(
        crls: Vec<pyo3::Py<CertificateRevocationList>>,
    ) -> pyo3::PyResult<(Self, PyRevocationChecker)> {
        if crls.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty CRL revocation checker",
            ));
        }

        Ok((
            Self {
                raw: RawPyCrlRevocationChecker::new(crls, |v| {
                    CrlRevocationChecker::new(v.iter().map(|i| i.get().owned.borrow_dependent()))
                }),
            },
            PyRevocationChecker {},
        ))
    }
}

/// A marker class that Rust and Python revocation checkers subclass from.
#[pyo3::pyclass(
    subclass,
    frozen,
    module = "cryptography.hazmat.bindings._rust.x509",
    name = "RevocationChecker"
)]
pub(crate) struct PyRevocationChecker;

impl CheckRevocation<PyCryptoOps> for pyo3::Py<PyRevocationChecker> {
    fn is_revoked(
        &self,
        _cert: &VerificationCertificate<'_, PyCryptoOps>,
        _issuer: &VerificationCertificate<'_, PyCryptoOps>,
        _policy: &Policy<'_, PyCryptoOps>,
    ) -> ValidationResult<'_, bool, PyCryptoOps> {
        pyo3::Python::attach(|py| {
            let _self = self.bind(py);
            todo!("self_.call_method w/ is_revoked ...")
        })
    }
}

pub(crate) fn build_rust_revocation_checker<'a>(
    py: pyo3::Python<'a>,
    checker: &'a pyo3::Py<PyRevocationChecker>,
) -> pyo3::PyResult<&'a RevocationChecker<'a, PyCryptoOps>> {
    if let Ok(crl) = checker.cast_bound::<PyCrlRevocationChecker>(py) {
        return Ok(crl.get().raw.borrow_dependent());
    }

    Err(pyo3::exceptions::PyTypeError::new_err(
        "not a Rust RevocationChecker",
    ))
}
