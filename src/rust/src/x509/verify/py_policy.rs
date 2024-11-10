use std::net::IpAddr;

use cryptography_x509_verification::policy::{Policy, Subject};
use pyo3::types::PyAnyMethods;

use crate::asn1::oid_to_py_oid;

use crate::types;
use crate::x509::datetime_to_py;

use super::PyCryptoOps;

/// Type alias for a cryptography_x509_verification::policy::Policy that uses PyCryptoOps.
pub(super) type PyCryptoPolicy<'a> = Policy<'a, PyCryptoOps>;

/// Python-accessible wrapper for a cryptography_x509_verification::policy::Policy.
#[pyo3::pyclass(module = "cryptography.x509.verification", name = "Policy")]
pub(crate) struct PyPolicy {
    #[pyo3(get)]
    max_chain_depth: u8,
    #[pyo3(get)]
    subject: Option<pyo3::PyObject>,
    #[pyo3(get)]
    validation_time: pyo3::PyObject,
    #[pyo3(get)]
    extended_key_usage: pyo3::PyObject,
    #[pyo3(get)]
    minimum_rsa_modulus: usize,
}

impl PyPolicy {
    /// Parses all fields of a Policy into Python objects and returns a PyPolicy containing them.
    /// (This is a workaround for the lack of lifetime parameters on PyO3 classes,
    /// otherwise storing the Policy itself would be preferred.)
    pub(super) fn from_rust_policy(
        py: pyo3::Python<'_>,
        policy: &Policy<'_, PyCryptoOps>,
    ) -> pyo3::PyResult<PyPolicy> {
        let subject = if let Some(subject) = &policy.subject {
            Some(
                match subject {
                    Subject::DNS(dns_name) => {
                        types::DNS_NAME.get(py)?.call1((dns_name.as_str(),))?
                    }
                    Subject::IP(ip_address) => {
                        let ip_string = Into::<IpAddr>::into(*ip_address).to_string();
                        let py_ip_address =
                            types::IPADDRESS_IPADDRESS.get(py)?.call1((ip_string,))?;
                        types::IP_ADDRESS.get(py)?.call1((py_ip_address,))?
                    }
                }
                .as_unbound()
                .clone_ref(py),
            )
        } else {
            None
        };

        let extended_key_usage = oid_to_py_oid(py, &policy.extended_key_usage)?
            .as_unbound()
            .clone_ref(py);

        Ok(PyPolicy {
            max_chain_depth: policy.max_chain_depth,
            subject,
            validation_time: datetime_to_py(py, &policy.validation_time)?
                .as_unbound()
                .clone_ref(py),
            extended_key_usage,
            minimum_rsa_modulus: policy.minimum_rsa_modulus,
        })
    }
}
