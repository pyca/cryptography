use super::OwnedPolicyDefinition;
use crate::asn1::oid_to_py_oid;
use crate::x509::datetime_to_py;

/// Python-accessible wrapper for a cryptography_x509_verification::policy::Policy.
#[pyo3::pyclass(module = "cryptography.x509.verification", name = "Policy", frozen)]
pub(crate) struct PyPolicy {
    pub(super) policy_definition: OwnedPolicyDefinition,
    pub(super) subject: pyo3::PyObject,
}

#[pyo3::pymethods]
impl PyPolicy {
    #[getter]
    pub(super) fn max_chain_depth(&self) -> u8 {
        self.policy_definition.borrow_dependent().max_chain_depth
    }

    #[getter]
    pub(super) fn subject(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
        self.subject.clone_ref(py)
    }

    #[getter]
    pub(super) fn validation_time(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let time = &self.policy_definition.borrow_dependent().validation_time;
        Ok(datetime_to_py(py, time)?.as_unbound().clone_ref(py))
    }

    #[getter]
    fn extended_key_usage(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let eku_oid = &self.policy_definition.borrow_dependent().extended_key_usage;
        Ok(oid_to_py_oid(py, eku_oid)?.as_unbound().clone_ref(py))
    }

    #[getter]
    fn minimum_rsa_modulus(&self) -> usize {
        self.policy_definition
            .borrow_dependent()
            .minimum_rsa_modulus
    }
}
