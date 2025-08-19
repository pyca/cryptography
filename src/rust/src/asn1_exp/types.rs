// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyInt, PyType};
use pyo3::PyTypeInfo;

/// Markers for user-defined sequences/sets (via decorators).
#[derive(Clone, PartialEq)]
#[pyclass(eq, eq_int, frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub enum RootType {
    Sequence,
}

/// Internal type representation for mapping between
/// Python and ASN.1.
#[pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub enum Type {
    // Core ASN.1 types
    //
    /// SEQUENCE (`class`)
    #[pyo3(constructor = (_0))]
    Sequence(Py<PyType>),

    // Python types that we map to canonical ASN.1 types
    //
    /// `int` -> `Integer`
    #[pyo3(constructor = ())]
    PyInt(),
}

/// A type that we know how to encode/decode, along with any
/// annotations that influence encoding/decoding.
#[pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct AnnotatedType {
    #[pyo3(get)]
    pub inner: Py<Type>,
    #[pyo3(get)]
    pub annotation: Annotation,
}

#[pymethods]
impl AnnotatedType {
    #[new]
    #[pyo3(signature = (inner, annotation))]
    fn new(inner: Py<Type>, annotation: Annotation) -> Self {
        Self { inner, annotation }
    }
}

/// An Python object with its corresponding AnnotatedType.
pub struct AnnotatedTypeObject<'a> {
    pub annotated_type: &'a AnnotatedType,
    pub value: Bound<'a, PyAny>,
}

#[pyclass(module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Clone, Debug)]
pub struct Annotation {}

#[pymethods]
impl Annotation {
    #[new]
    #[pyo3(signature = ())]
    fn new() -> Self {
        Self {}
    }
}

/// Utility function for converting builtin Python types.
/// This is needed when `encode_der` and `decode_der` are called
/// with builtin Python types (`int`, `str`, etc), and we can't
/// handle the conversion to the Rust `AnnotatedType` like we
/// do for classes with `@sequence`.
pub fn non_root_type_to_annotated<'p>(
    py: Python<'p>,
    class: &Bound<'p, PyType>,
    annotation: Option<Annotation>,
) -> PyResult<AnnotatedType> {
    let inner = if class.is(PyInt::type_object(py)) {
        Type::PyInt().into_pyobject(py)
    } else {
        Err(PyValueError::new_err(format!(
            "Cannot handle simple type: {class:?}"
        )))
    }?
    .unbind();

    Ok(AnnotatedType {
        inner,
        annotation: annotation.unwrap_or(Annotation {}),
    })
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod types {
    #[pymodule_export]
    use super::{AnnotatedType, Annotation, RootType, Type};
}
