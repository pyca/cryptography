use std::net::IpAddr;

use cryptography_x509_verification::policy::Subject;
use pyo3::types::PyAnyMethods;

use crate::asn1::oid_to_py_oid;

use crate::types;
use crate::x509::datetime_to_py;

use super::OwnedPolicyDefinition;

/// Python-accessible wrapper for a cryptography_x509_verification::policy::Policy.
#[pyo3::pyclass(module = "cryptography.x509.verification", name = "Policy", frozen)]
pub(crate) struct PyPolicyDefinition(pub(super) OwnedPolicyDefinition);

#[pyo3::pymethods]
impl PyPolicyDefinition {
    #[getter]
    fn max_chain_depth(&self) -> u8 {
        self.0.borrow_dependent().max_chain_depth
    }

    #[getter]
    fn subject(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        let policy_def = self.0.borrow_dependent();
        Ok(match &policy_def.subject {
            Some(Subject::DNS(dns_name)) => types::DNS_NAME
                .get(py)?
                .call1((dns_name.as_str(),))?
                .as_unbound()
                .clone_ref(py),
            Some(Subject::IP(ip_address)) => {
                let ip_string = Into::<IpAddr>::into(*ip_address).to_string();
                let py_ip_address = types::IPADDRESS_IPADDRESS.get(py)?.call1((ip_string,))?;
                types::IP_ADDRESS
                    .get(py)?
                    .call1((py_ip_address,))?
                    .as_unbound()
                    .clone_ref(py)
            }
            None => pyo3::types::PyNone::get(py)
                .as_any()
                .as_unbound()
                .clone_ref(py),
        })
    }

    #[getter]
    fn validation_time(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        Ok(
            datetime_to_py(py, &self.0.borrow_dependent().validation_time)?
                .as_unbound()
                .clone_ref(py),
        )
    }

    #[getter]
    fn extended_key_usage(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::PyObject> {
        Ok(
            oid_to_py_oid(py, &self.0.borrow_dependent().extended_key_usage)?
                .as_unbound()
                .clone_ref(py),
        )
    }

    #[getter]
    fn minimum_rsa_modulus(&self) -> usize {
        self.0.borrow_dependent().minimum_rsa_modulus
    }
}
