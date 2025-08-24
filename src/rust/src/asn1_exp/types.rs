// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;
use pyo3::{IntoPyObject, PyTypeInfo};

/// Internal type representation for mapping between
/// Python and ASN.1.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub enum Type {
    // Core ASN.1 types
    //
    /// SEQUENCE (`class`)
    #[pyo3(constructor = (_0))]
    Sequence(pyo3::Py<pyo3::types::PyType>),

    // Python types that we map to canonical ASN.1 types
    //
    /// `int` -> `Integer`
    #[pyo3(constructor = ())]
    PyInt(),
}

/// A type that we know how to encode/decode, along with any
/// annotations that influence encoding/decoding.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct AnnotatedType {
    #[pyo3(get)]
    pub inner: pyo3::Py<Type>,
    #[pyo3(get)]
    pub annotation: Annotation,
}

#[pyo3::pymethods]
impl AnnotatedType {
    #[new]
    #[pyo3(signature = (inner, annotation))]
    fn new(inner: pyo3::Py<Type>, annotation: Annotation) -> Self {
        Self { inner, annotation }
    }
}

/// An Python object with its corresponding AnnotatedType.
pub struct AnnotatedTypeObject<'a> {
    pub annotated_type: &'a AnnotatedType,
    pub value: pyo3::Bound<'a, pyo3::PyAny>,
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Clone, Debug)]
pub struct Annotation {}

#[pyo3::pymethods]
impl Annotation {
    #[new]
    #[pyo3(signature = ())]
    fn new() -> Self {
        Self {}
    }
}

/// Utility function for converting builtin Python types
/// to their Rust `Type` equivalent.
#[pyo3::pyfunction]
pub fn non_root_python_to_rust<'p>(
    py: pyo3::Python<'p>,
    class: &pyo3::Bound<'p, pyo3::types::PyType>,
) -> pyo3::PyResult<pyo3::Bound<'p, Type>> {
    if class.is(pyo3::types::PyInt::type_object(py)) {
        Type::PyInt().into_pyobject(py)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "cannot handle type: {class:?}"
        )))
    }
}

/// Utility function for converting builtin Python types.
/// This is needed when `encode_der` and `decode_der` are called
/// with builtin Python types (`int`, `str`, etc), and we can't
/// handle the conversion to the Rust `AnnotatedType` like we
/// do for classes with `@sequence`.
pub fn non_root_type_to_annotated<'p>(
    py: pyo3::Python<'p>,
    class: &pyo3::Bound<'p, pyo3::types::PyType>,
    annotation: Option<Annotation>,
) -> pyo3::PyResult<AnnotatedType> {
    let inner = non_root_python_to_rust(py, class)?.unbind();
    Ok(AnnotatedType {
        inner,
        annotation: annotation.unwrap_or(Annotation {}),
    })
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod types {
    #[pymodule_export]
    use super::{AnnotatedType, Annotation, Type};
}
