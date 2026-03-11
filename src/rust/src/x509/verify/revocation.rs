use cryptography_x509_verification::revocation::{CRLRevocationChecker, RevocationChecker};

use crate::x509::{crl::CertificateRevocationList, verify::PyCryptoOps};

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "RevocationChecker"
)]
pub(crate) struct PyRevocationChecker {
    inner_checker: Box<dyn RevocationChecker<PyCryptoOps>>,
}

impl PyRevocationChecker {
    pub(super) fn clone_inner_checker(&self) -> Box<dyn RevocationChecker<PyCryptoOps>> {
        self.inner_checker.clone_box()
    }
}

#[pyo3::pymethods]
impl PyRevocationChecker {
    #[staticmethod]
    pub(crate) fn crl_checker(
        py: pyo3::Python<'_>,
        crls: Vec<pyo3::Py<CertificateRevocationList>>,
    ) -> pyo3::PyResult<Self> {
        if crls.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty CRL revocation checker",
            ));
        }

        let crls = CRLRevocationChecker::new(
            // XX(tnytown): CRLRevocationChecker.crls should *probably* be owned
            crls.iter()
                .map(|crl| crl.get().owned.borrow_dependent())
                .collect::<Vec<_>>(),
        );

        Ok(Self {
            inner_checker: Box::new(crls),
        })
    }
}
