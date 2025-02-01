// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyListMethods;

pyo3::create_exception!(
    OpenSSL.SSL,
    Error,
    pyo3::exceptions::PyException,
    "An error occurred in an `OpenSSL.SSL` API."
);

pub(crate) enum PyOpenSslError {
    Py(pyo3::PyErr),
    OpenSSL(openssl::error::ErrorStack),
}

impl From<pyo3::PyErr> for PyOpenSslError {
    fn from(e: pyo3::PyErr) -> PyOpenSslError {
        PyOpenSslError::Py(e)
    }
}

impl From<openssl::error::ErrorStack> for PyOpenSslError {
    fn from(e: openssl::error::ErrorStack) -> PyOpenSslError {
        PyOpenSslError::OpenSSL(e)
    }
}

impl From<PyOpenSslError> for pyo3::PyErr {
    fn from(e: PyOpenSslError) -> pyo3::PyErr {
        match e {
            PyOpenSslError::Py(e) => e,
            PyOpenSslError::OpenSSL(e) => pyo3::Python::with_gil(|py| {
                let errs = pyo3::types::PyList::empty(py);
                for err in e.errors() {
                    errs.append((
                        err.library().unwrap_or(""),
                        err.function().unwrap_or(""),
                        err.reason().unwrap_or(""),
                    ))?;
                }
                Ok(Error::new_err(errs.unbind()))
            })
            .unwrap_or_else(|e| e),
        }
    }
}

pub(crate) type PyOpenSslResult<T> = Result<T, PyOpenSslError>;

#[cfg(test)]
mod tests {
    use super::{Error, PyOpenSslError};

    #[test]
    fn test_pyopenssl_error_from_openssl_error() {
        pyo3::Python::with_gil(|py| {
            // Literally anything that returns a non-empty error stack
            let err = openssl::x509::X509::from_der(b"").unwrap_err();

            let py_err: pyo3::PyErr = PyOpenSslError::from(err).into();
            assert!(py_err.is_instance_of::<Error>(py));
            assert!(py_err.to_string().starts_with("Error: [("),);
        });
    }
}
