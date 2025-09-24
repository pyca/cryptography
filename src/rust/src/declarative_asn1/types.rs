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
    /// SEQUENCE (`class`, `dict`)
    /// The first element is the Python class that represents the sequence,
    /// the second element is a dict of the (already converted) fields of the class.
    #[pyo3(constructor = (_0, _1))]
    Sequence(pyo3::Py<pyo3::types::PyType>, pyo3::Py<pyo3::types::PyDict>),

    // Python types that we map to canonical ASN.1 types
    //
    /// `bool` -> `Boolean`
    #[pyo3(constructor = ())]
    PyBool(),
    /// `int` -> `Integer`
    #[pyo3(constructor = ())]
    PyInt(),
    /// `bytes` -> `Octet String`
    #[pyo3(constructor = ())]
    PyBytes(),
    /// `str` -> `UTF8String`
    #[pyo3(constructor = ())]
    PyStr(),
    /// PrintableString (`str`)
    #[pyo3(constructor = ())]
    PrintableString(),
}

/// A type that we know how to encode/decode, along with any
/// annotations that influence encoding/decoding.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct AnnotatedType {
    pub inner: pyo3::Py<Type>,
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
    fn new() -> Self {
        Self {}
    }
}

#[derive(pyo3::FromPyObject)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct PrintableString {
    pub(crate) inner: pyo3::Py<pyo3::types::PyString>,
}

#[pyo3::pymethods]
impl PrintableString {
    #[new]
    #[pyo3(signature = (inner,))]
    fn new(inner: pyo3::Py<pyo3::types::PyString>) -> Self {
        PrintableString { inner }
    }

    #[pyo3(signature = ())]
    pub fn as_str(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::types::PyString>> {
        Ok(self.inner.clone_ref(py))
    }

    pub fn __repr__(&self) -> String {
        format!("PrintableString({})", self.inner)
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
    } else if class.is(pyo3::types::PyBool::type_object(py)) {
        Type::PyBool().into_pyobject(py)
    } else if class.is(pyo3::types::PyString::type_object(py)) {
        Type::PyStr().into_pyobject(py)
    } else if class.is(pyo3::types::PyBytes::type_object(py)) {
        Type::PyBytes().into_pyobject(py)
    } else if class.is(PrintableString::type_object(py)) {
        Type::PrintableString().into_pyobject(py)
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
fn non_root_type_to_annotated<'p>(
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

// Utility function for converting a Python class or a Python builtin type
// into an AnnotatedType.
pub(crate) fn python_class_to_annotated<'p>(
    py: pyo3::Python<'p>,
    class: &pyo3::Bound<'p, pyo3::types::PyType>,
) -> pyo3::PyResult<pyo3::Bound<'p, AnnotatedType>> {
    if let Ok(root) = class.getattr("__asn1_root__") {
        // Handle decorated classes
        root.downcast_into::<AnnotatedType>().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(
                "target type has invalid annotations".to_string(),
            )
        })
    } else {
        // Handle builtin types
        pyo3::Bound::new(py, non_root_type_to_annotated(py, class, None)?)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod types {
    #[pymodule_export]
    use super::{AnnotatedType, Annotation, PrintableString, Type};
}
