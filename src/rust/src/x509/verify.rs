// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::x509::certificate::Certificate as PyCertificate;

#[pyo3::pyclass(
    frozen,
    name = "Store",
    module = "cryptography.hazmat.bindings._rust.x509"
)]
struct PyStore(Vec<pyo3::Py<PyCertificate>>);

#[pyo3::pymethods]
impl PyStore {
    #[new]
    fn new(certs: &pyo3::types::PyList) -> pyo3::PyResult<Self> {
        let certs: Vec<pyo3::Py<PyCertificate>> = certs
            .iter()
            .map(|o| {
                o.extract::<pyo3::PyRef<'_, PyCertificate>>()
                    .map(Into::into)
            })
            .collect::<Result<_, _>>()?;

        Ok(Self(certs))
    }
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyStore>()?;

    Ok(())
}
