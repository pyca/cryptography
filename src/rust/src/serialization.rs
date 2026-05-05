// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::types;

#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.primitives._serialization"
)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    PEM,
    DER,
    OpenSSH,
    Raw,
    X962,
    SMIME,
}

#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.primitives._serialization"
)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivateFormat {
    PKCS8,
    TraditionalOpenSSL,
    Raw,
    OpenSSH,
    PKCS12,
}

#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.primitives._serialization"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicFormat {
    SubjectPublicKeyInfo,
    PKCS1,
    OpenSSH,
    Raw,
    CompressedPoint,
    UncompressedPoint,
}

#[pyo3::pyclass(
    frozen,
    eq,
    hash,
    from_py_object,
    module = "cryptography.hazmat.primitives._serialization"
)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterFormat {
    PKCS3,
}

#[pyo3::pymethods]
impl PrivateFormat {
    fn encryption_builder<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        match self {
            PrivateFormat::OpenSSH | PrivateFormat::PKCS12 => {
                types::KEY_SERIALIZATION_ENCRYPTION_BUILDER
                    .get(py)?
                    .call1((*self,))
            }
            _ => Err(pyo3::exceptions::PyValueError::new_err(
                "encryption_builder only supported with PrivateFormat.OpenSSH and PrivateFormat.PKCS12",
            )),
        }
    }
}
