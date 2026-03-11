use cryptography_x509_verification::revocation::CrlRevocationChecker;

use crate::x509::{certificate::Certificate, crl::CertificateRevocationList, verify::PyCryptoOps};

self_cell::self_cell!(
    pub(crate) struct RawPyCrlRevocationChecker {
        owner: Vec<(pyo3::Py<Certificate>, pyo3::Py<CertificateRevocationList>)>,

        #[covariant]
        dependent: CrlRevocationChecker,
    }
);

/// A class that can be used to construct a [`CrlRevocationChecker`].
///
/// It holds the [`CertificateRevocationList`] entries that comprise a [`CrlRevocationChecker`] and
/// constructs an instance that borrows against them.
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
    fn new(
        issuers_to_crls: Vec<(pyo3::Py<Certificate>, pyo3::Py<CertificateRevocationList>)>,
    ) -> pyo3::PyResult<Self> {
        if issuers_to_crls.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "can't create an empty CRL revocation checker",
            ));
        }

        let raw = RawPyCrlRevocationChecker::try_new(issuers_to_crls, |v| {
            CrlRevocationChecker::new(
                PyCryptoOps {},
                v.iter().map(|i| {
                    (
                        i.0.get().raw.borrow_dependent(),
                        i.1.get().owned.borrow_dependent(),
                    )
                }),
            )
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "Failed to process CRLs. Ensure that CRLs and issuers match",
                )
            })
        })?;
        Ok(Self { raw })
    }
}
