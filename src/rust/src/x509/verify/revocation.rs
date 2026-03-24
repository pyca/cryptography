use cryptography_x509_verification::{
    ops::VerificationCertificate,
    policy::Policy,
    revocation::{CheckRevocation, CrlRevocationChecker, RevocationChecker},
    ValidationError, ValidationErrorKind, ValidationResult,
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    subclass,
    frozen,
    module = "cryptography.hazmat.bindings._rust.x509",
    name = "RevocationChecker"
)]
// NO-COVERAGE-END
/// A marker class that Rust and Python revocation checkers subclass from.
pub(crate) struct PyRevocationChecker;

#[pyo3::pymethods]
impl PyRevocationChecker {
    #[new]
    #[pyo3(signature = (*_args))]
    pub fn new(_args: &pyo3::Bound<'_, pyo3::PyAny>) -> Self {
        Self
    }
}

impl CheckRevocation<PyCryptoOps> for pyo3::Py<PyRevocationChecker> {
    fn is_revoked<'chain>(
        &self,
        cert: &VerificationCertificate<'chain, PyCryptoOps>,
        issuer: &VerificationCertificate<'chain, PyCryptoOps>,
        policy: &Policy<'_, PyCryptoOps>,
    ) -> ValidationResult<'chain, bool, PyCryptoOps> {
        pyo3::Python::attach(|py| {
            let result = self
                .call_method1(
                    py,
                    pyo3::intern!(py, "is_revoked"),
                    (cert.extra(), issuer.extra(), &policy.extra),
                )
                .map_err(|_e| {
                    ValidationError::new(ValidationErrorKind::FatalError::<PyCryptoOps>(
                        "the revocation checker raised an exception",
                    ))
                })?;

            if result.is_none(py) {
                Err(ValidationError::new(
                    ValidationErrorKind::RevocationNotDetermined,
                ))
            } else {
                result.extract(py).map_err(|_e| {
                    ValidationError::new(ValidationErrorKind::FatalError::<PyCryptoOps>(
                        "the revocation checker must return one of True, False, or None",
                    ))
                })
            }
        })
    }
}

/// Retrieves the underlying native RevocationChecker from the PyRevocationChecker if it exists.
pub(crate) fn build_rust_revocation_checker<'a>(
    py: pyo3::Python<'a>,
    checker: &'a pyo3::Py<PyRevocationChecker>,
) -> &'a RevocationChecker<'a, PyCryptoOps> {
    if let Ok(crl) = checker.cast_bound::<PyCrlRevocationChecker>(py) {
        return crl.get().raw.borrow_dependent();
    }

    // this isn't a Rust-native revocation checker, fallthrough.
    checker
}
