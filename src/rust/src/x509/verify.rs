// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::IntoPy;

use crate::x509::certificate::Certificate as PyCertificate;

#[pyo3::pyclass(name = "Store", module = "cryptography.hazmat.bindings._rust.x509")]
struct PyStore(pyo3::Py<pyo3::types::PyList>);

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new<'p>(py: pyo3::Python<'p>, certs: &'p pyo3::types::PyList) -> pyo3::PyResult<Self> {
        if certs.iter().any(|c| !c.is_instance_of::<PyCertificate>()) {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "cannot initialize store with non-certificate member",
            ));
        }
        Ok(Self(certs.into_py(py)))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyStore>()?;

    Ok(())
}
