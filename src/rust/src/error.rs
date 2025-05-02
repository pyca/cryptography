// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::fmt;

use pyo3::types::PyListMethods;

use crate::exceptions;

pub enum CryptographyError {
    Asn1Parse(asn1::ParseError),
    Asn1Write(asn1::WriteError),
    KeyParsing(asn1::ParseError),
    Py(pyo3::PyErr),
    OpenSSL(openssl::error::ErrorStack),
}

impl From<asn1::ParseError> for CryptographyError {
    fn from(e: asn1::ParseError) -> CryptographyError {
        CryptographyError::Asn1Parse(e)
    }
}

impl From<asn1::WriteError> for CryptographyError {
    fn from(e: asn1::WriteError) -> CryptographyError {
        CryptographyError::Asn1Write(e)
    }
}

impl From<pyo3::PyErr> for CryptographyError {
    fn from(e: pyo3::PyErr) -> CryptographyError {
        CryptographyError::Py(e)
    }
}

impl From<pyo3::DowncastError<'_, '_>> for CryptographyError {
    fn from(e: pyo3::DowncastError<'_, '_>) -> CryptographyError {
        CryptographyError::Py(e.into())
    }
}

impl From<openssl::error::ErrorStack> for CryptographyError {
    fn from(e: openssl::error::ErrorStack) -> CryptographyError {
        CryptographyError::OpenSSL(e)
    }
}

impl From<pem::PemError> for CryptographyError {
    fn from(e: pem::PemError) -> CryptographyError {
        CryptographyError::Py(pyo3::exceptions::PyValueError::new_err(format!(
            "Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. {e:?}"
        )))
    }
}

impl From<cryptography_key_parsing::KeyParsingError> for CryptographyError {
    fn from(e: cryptography_key_parsing::KeyParsingError) -> CryptographyError {
        match e {
            cryptography_key_parsing::KeyParsingError::Parse(e) => CryptographyError::KeyParsing(e),
            cryptography_key_parsing::KeyParsingError::OpenSSL(e) => CryptographyError::OpenSSL(e),
            cryptography_key_parsing::KeyParsingError::InvalidKey => {
                CryptographyError::Py(pyo3::exceptions::PyValueError::new_err("Invalid key"))
            }
            cryptography_key_parsing::KeyParsingError::ExplicitCurveUnsupported => {
                CryptographyError::Py(pyo3::exceptions::PyValueError::new_err(
                    "ECDSA keys with explicit parameters are unsupported at this time",
                ))
            }
            cryptography_key_parsing::KeyParsingError::UnsupportedKeyType(oid) => {
                CryptographyError::Py(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown key type: {oid}"
                )))
            }
            cryptography_key_parsing::KeyParsingError::UnsupportedEllipticCurve(oid) => {
                CryptographyError::Py(exceptions::UnsupportedAlgorithm::new_err((
                    format!("Curve {oid} is not supported"),
                    exceptions::Reasons::UNSUPPORTED_ELLIPTIC_CURVE,
                )))
            }
        }
    }
}

pub(crate) fn list_from_openssl_error<'p>(
    py: pyo3::Python<'p>,
    error_stack: &openssl::error::ErrorStack,
) -> pyo3::Bound<'p, pyo3::types::PyList> {
    let errors = pyo3::types::PyList::empty(py);
    for e in error_stack.errors() {
        errors
            .append(
                pyo3::Bound::new(py, OpenSSLError { e: e.clone() })
                    .expect("Failed to create OpenSSLError"),
            )
            .expect("Failed to append to list");
    }
    errors
}

impl fmt::Display for CryptographyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptographyError::Asn1Parse(asn1_error) => {
                write!(f, "error parsing asn1 value: {asn1_error:?}")
            }
            CryptographyError::Asn1Write(asn1::WriteError::AllocationError) => {
                write!(
                    f,
                    "failed to allocate memory while performing ASN.1 serialization"
                )
            }
            CryptographyError::KeyParsing(asn1_error) => {
                write!(
                    f,
                    "Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: {asn1_error}",
                )
            }
            CryptographyError::Py(py_error) => write!(f, "{py_error}"),
            CryptographyError::OpenSSL(error_stack) => {
                write!(
                    f,
                    "Unknown OpenSSL error. This error is commonly encountered
                    when another library is not cleaning up the OpenSSL error
                    stack. If you are using cryptography with another library
                    that uses OpenSSL try disabling it before reporting a bug.
                    Otherwise please file an issue at
                    https://github.com/pyca/cryptography/issues with
                    information on how to reproduce this. ({error_stack})"
                )
            }
        }
    }
}

impl From<CryptographyError> for pyo3::PyErr {
    fn from(e: CryptographyError) -> pyo3::PyErr {
        match e {
            CryptographyError::Asn1Parse(_) | CryptographyError::KeyParsing(_) => {
                pyo3::exceptions::PyValueError::new_err(e.to_string())
            }
            CryptographyError::Asn1Write(asn1::WriteError::AllocationError) => {
                pyo3::exceptions::PyMemoryError::new_err(e.to_string())
            }
            CryptographyError::Py(py_error) => py_error,
            CryptographyError::OpenSSL(ref error_stack) => pyo3::Python::with_gil(|py| {
                let errors = list_from_openssl_error(py, error_stack);
                exceptions::InternalError::new_err((e.to_string(), errors.unbind()))
            }),
        }
    }
}

impl CryptographyError {
    pub(crate) fn add_location(self, loc: asn1::ParseLocation) -> Self {
        match self {
            CryptographyError::Py(e) => CryptographyError::Py(e),
            CryptographyError::Asn1Parse(e) => CryptographyError::Asn1Parse(e.add_location(loc)),
            CryptographyError::KeyParsing(e) => CryptographyError::KeyParsing(e.add_location(loc)),
            CryptographyError::Asn1Write(e) => CryptographyError::Asn1Write(e),
            CryptographyError::OpenSSL(e) => CryptographyError::OpenSSL(e),
        }
    }
}

// The primary purpose of this alias is for brevity to keep function signatures
// to a single-line as a work around for coverage issues. See
// https://github.com/pyca/cryptography/pull/6173
pub(crate) type CryptographyResult<T> = Result<T, CryptographyError>;

#[pyo3::pyfunction]
pub(crate) fn raise_openssl_error() -> crate::error::CryptographyResult<()> {
    Err(openssl::error::ErrorStack::get().into())
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl")]
pub(crate) struct OpenSSLError {
    e: openssl::error::Error,
}

#[pyo3::pymethods]
impl OpenSSLError {
    #[getter]
    fn lib(&self) -> i32 {
        self.e.library_code()
    }

    #[getter]
    fn reason(&self) -> i32 {
        self.e.reason_code()
    }

    #[getter]
    fn reason_text(&self) -> &[u8] {
        self.e.reason().unwrap_or("").as_bytes()
    }

    fn __repr__(&self) -> pyo3::PyResult<String> {
        Ok(format!(
            "<OpenSSLError(code={}, lib={}, reason={}, reason_text={})>",
            self.e.code(),
            self.e.library_code(),
            self.e.reason_code(),
            self.e.reason().unwrap_or("")
        ))
    }
}

#[pyo3::pyfunction]
pub(crate) fn capture_error_stack(
    py: pyo3::Python<'_>,
) -> pyo3::PyResult<pyo3::Bound<'_, pyo3::types::PyList>> {
    let errs = pyo3::types::PyList::empty(py);
    for e in openssl::error::ErrorStack::get().errors() {
        errs.append(pyo3::Bound::new(py, OpenSSLError { e: e.clone() })?)?;
    }
    Ok(errs)
}

#[cfg(test)]
mod tests {
    use super::CryptographyError;

    #[test]
    fn test_cryptographyerror_display() {
        pyo3::prepare_freethreaded_python();
        pyo3::Python::with_gil(|py| {
            let py_error = pyo3::exceptions::PyRuntimeError::new_err("abc");
            let e: CryptographyError = py_error.clone_ref(py).into();
            assert!(e.to_string() == py_error.to_string());
        })
    }

    #[test]
    fn test_cryptographyerror_from() {
        pyo3::prepare_freethreaded_python();
        pyo3::Python::with_gil(|py| {
            let e: CryptographyError = asn1::WriteError::AllocationError.into();
            assert!(matches!(
                e,
                CryptographyError::Asn1Write(asn1::WriteError::AllocationError)
            ));
            let py_e: pyo3::PyErr = e.into();
            assert!(py_e.is_instance_of::<pyo3::exceptions::PyMemoryError>(py));

            let e: CryptographyError = pyo3::DowncastError::new(py.None().bind(py), "abc").into();
            assert!(matches!(e, CryptographyError::Py(_)));

            let e = cryptography_key_parsing::KeyParsingError::OpenSSL(
                openssl::error::ErrorStack::get(),
            )
            .into();
            assert!(matches!(e, CryptographyError::OpenSSL(_)));
        })
    }

    #[test]
    fn test_cryptographyerror_add_location() {
        let py_err = pyo3::PyErr::new::<pyo3::exceptions::PyValueError, _>("Error!");
        CryptographyError::Py(py_err).add_location(asn1::ParseLocation::Field("meh"));

        let asn1_write_err = asn1::WriteError::AllocationError;
        CryptographyError::Asn1Write(asn1_write_err)
            .add_location(asn1::ParseLocation::Field("meh"));

        let openssl_error = openssl::error::ErrorStack::get();
        CryptographyError::from(openssl_error).add_location(asn1::ParseLocation::Field("meh"));

        let asn1_parse_error = asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue);
        CryptographyError::KeyParsing(asn1_parse_error)
            .add_location(asn1::ParseLocation::Field("meh"));
    }
}
