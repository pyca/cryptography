use super::PyCryptoOps;
use cryptography_x509_verification::policy::ExtensionPolicy;

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "ExtensionPolicy"
)]
pub(crate) struct PyExtensionPolicy {
    rust_policy: ExtensionPolicy<'static, PyCryptoOps>,
}

impl PyExtensionPolicy {
    pub(super) fn get_rust_policy(&self) -> ExtensionPolicy<'static, PyCryptoOps> {
        self.rust_policy.clone()
    }

    fn new(rust_policy: ExtensionPolicy<'static, PyCryptoOps>) -> Self {
        PyExtensionPolicy { rust_policy }
    }
}

#[pyo3::pymethods]
impl PyExtensionPolicy {
    #[staticmethod]
    pub(crate) fn permit_all() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_permit_all())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ca() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_default_webpki_ca())
    }

    #[staticmethod]
    pub(crate) fn webpki_defaults_ee() -> Self {
        PyExtensionPolicy::new(ExtensionPolicy::new_default_webpki_ee())
    }
}
