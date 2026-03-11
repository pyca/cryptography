use cryptography_x509_verification::revocation::CrlRevocationChecker;

use crate::x509::crl::CertificateRevocationList;

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
    name = "CRLRevocationChecker"
)]
pub(crate) struct PyCrlRevocationChecker {
    pub(crate) raw: RawPyCrlRevocationChecker,
}

#[pyo3::pymethods]
impl PyCrlRevocationChecker {
    #[new]
    fn new(crls: Vec<pyo3::Py<CertificateRevocationList>>) -> pyo3::PyResult<Self> {
        if crls.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty CRL revocation checker",
            ));
        }

        Ok(Self {
            raw: RawPyCrlRevocationChecker::new(crls, |v| {
                CrlRevocationChecker::new(v.iter().map(|i| i.get().owned.borrow_dependent()))
            }),
        })
    }
}
