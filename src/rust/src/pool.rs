// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::cell::Cell;

// An object pool that can contain a single object and will dynamically
// allocate new objects to fulfill requests if the pool'd object is already in
// use.
#[pyo3::prelude::pyclass]
pub(crate) struct FixedPool {
    create_fn: pyo3::PyObject,

    value: Cell<Option<pyo3::PyObject>>,
}

#[pyo3::prelude::pyclass]
struct PoolAcquisition {
    pool: pyo3::Py<FixedPool>,

    value: pyo3::PyObject,
    fresh: bool,
}

#[pyo3::pymethods]
impl FixedPool {
    #[new]
    fn new(py: pyo3::Python<'_>, create: pyo3::PyObject) -> pyo3::PyResult<Self> {
        let value = create.call0(py)?;

        Ok(FixedPool {
            create_fn: create,

            value: Cell::new(Some(value)),
        })
    }

    fn acquire(slf: pyo3::Py<Self>, py: pyo3::Python<'_>) -> pyo3::PyResult<PoolAcquisition> {
        let v = slf.as_ref(py).borrow().value.replace(None);
        if let Some(value) = v {
            Ok(PoolAcquisition {
                pool: slf,
                value,
                fresh: false,
            })
        } else {
            let value = slf.as_ref(py).borrow().create_fn.call0(py)?;
            Ok(PoolAcquisition {
                pool: slf,
                value,
                fresh: true,
            })
        }
    }
}

#[pyo3::pymethods]
impl PoolAcquisition {
    fn __enter__(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
        self.value.clone_ref(py)
    }

    fn __exit__(
        &self,
        py: pyo3::Python<'_>,
        _exc_type: &pyo3::PyAny,
        _exc_value: &pyo3::PyAny,
        _exc_tb: &pyo3::PyAny,
    ) -> pyo3::PyResult<()> {
        let pool = self.pool.as_ref(py).borrow();
        if !self.fresh {
            pool.value.replace(Some(self.value.clone_ref(py)));
        }
        Ok(())
    }
}
