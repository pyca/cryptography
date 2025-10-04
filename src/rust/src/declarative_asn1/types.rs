// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::GeneralizedTime as Asn1GeneralizedTime;
use asn1::PrintableString as Asn1PrintableString;
use asn1::SimpleAsn1Readable;
use asn1::UtcTime as Asn1UtcTime;
use pyo3::types::PyAnyMethods;
use pyo3::types::PyTzInfoAccess;
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
    /// OPTIONAL (`T | None`)
    #[pyo3(constructor = (_0))]
    Option(pyo3::Py<AnnotatedType>),

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
    /// UtcTime (`datetime`)
    #[pyo3(constructor = ())]
    UtcTime(),
    /// GeneralizedTime (`datetime`)
    #[pyo3(constructor = ())]
    GeneralizedTime(),
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
    fn new(py: pyo3::Python<'_>, inner: pyo3::Py<pyo3::types::PyString>) -> pyo3::PyResult<Self> {
        if Asn1PrintableString::new(&inner.to_cow(py)?).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid PrintableString: {inner}"
            )));
        }

        Ok(PrintableString { inner })
    }

    #[pyo3(signature = ())]
    pub fn as_str(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::types::PyString>> {
        Ok(self.inner.clone_ref(py))
    }

    fn __eq__(&self, py: pyo3::Python<'_>, other: pyo3::PyRef<'_, Self>) -> pyo3::PyResult<bool> {
        (**self.inner.bind(py)).eq(other.inner.bind(py))
    }

    pub fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        Ok(format!("PrintableString({})", self.inner.bind(py).repr()?))
    }
}

#[derive(pyo3::FromPyObject)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct UtcTime {
    pub(crate) inner: pyo3::Py<pyo3::types::PyDateTime>,
}

#[pyo3::pymethods]
impl UtcTime {
    #[new]
    #[pyo3(signature = (inner,))]
    fn new(py: pyo3::Python<'_>, inner: pyo3::Py<pyo3::types::PyDateTime>) -> pyo3::PyResult<Self> {
        if inner.bind(py).get_tzinfo().is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "invalid UtcTime: cannot initialize with naive datetime object",
            ));
        }
        let (datetime, microseconds) =
            crate::x509::py_to_datetime_with_microseconds(py, inner.clone_ref(py).into_bound(py))?;

        if microseconds.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "invalid UtcTime: fractional seconds are not supported",
            ));
        }
        Asn1UtcTime::new(datetime).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid UtcTime: {e}"))
        })?;
        Ok(UtcTime { inner })
    }

    #[pyo3(signature = ())]
    pub fn as_datetime(
        &self,
        py: pyo3::Python<'_>,
    ) -> pyo3::PyResult<pyo3::Py<pyo3::types::PyDateTime>> {
        Ok(self.inner.clone_ref(py))
    }

    fn __eq__(&self, py: pyo3::Python<'_>, other: pyo3::PyRef<'_, Self>) -> pyo3::PyResult<bool> {
        (**self.inner.bind(py)).eq(other.inner.bind(py))
    }

    pub fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        Ok(format!("UtcTime({})", self.inner.bind(py).repr()?))
    }
}

#[derive(pyo3::FromPyObject)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct GeneralizedTime {
    pub(crate) inner: pyo3::Py<pyo3::types::PyDateTime>,
}

#[pyo3::pymethods]
impl GeneralizedTime {
    #[new]
    #[pyo3(signature = (inner,))]
    fn new(py: pyo3::Python<'_>, inner: pyo3::Py<pyo3::types::PyDateTime>) -> pyo3::PyResult<Self> {
        if inner.bind(py).get_tzinfo().is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "invalid GeneralizedTime: cannot initialize with naive datetime object",
            ));
        }
        let (datetime, microseconds) =
            crate::x509::py_to_datetime_with_microseconds(py, inner.clone_ref(py).into_bound(py))?;
        let nanoseconds = microseconds.map(|m| m * 1000);
        Asn1GeneralizedTime::new(datetime, nanoseconds).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid GeneralizedTime: {e}"))
        })?;
        Ok(GeneralizedTime { inner })
    }

    #[pyo3(signature = ())]
    pub fn as_datetime(
        &self,
        py: pyo3::Python<'_>,
    ) -> pyo3::PyResult<pyo3::Py<pyo3::types::PyDateTime>> {
        Ok(self.inner.clone_ref(py))
    }

    fn __eq__(&self, py: pyo3::Python<'_>, other: pyo3::PyRef<'_, Self>) -> pyo3::PyResult<bool> {
        (**self.inner.bind(py)).eq(other.inner.bind(py))
    }

    pub fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        Ok(format!("GeneralizedTime({})", self.inner.bind(py).repr()?))
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
    } else if class.is(UtcTime::type_object(py)) {
        Type::UtcTime().into_pyobject(py)
    } else if class.is(GeneralizedTime::type_object(py)) {
        Type::GeneralizedTime().into_pyobject(py)
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

pub(crate) fn type_to_tag(t: &Type) -> asn1::Tag {
    match t {
        Type::Sequence(_, _) => asn1::Sequence::TAG,
        Type::Option(t) => type_to_tag(t.get().inner.get()),
        Type::PyBool() => bool::TAG,
        Type::PyInt() => asn1::BigInt::TAG,
        Type::PyBytes() => <&[u8] as SimpleAsn1Readable>::TAG,
        Type::PyStr() => asn1::Utf8String::TAG,
        Type::PrintableString() => asn1::PrintableString::TAG,
        Type::UtcTime() => asn1::UtcTime::TAG,
        Type::GeneralizedTime() => asn1::GeneralizedTime::TAG,
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod types {
    #[pymodule_export]
    use super::{AnnotatedType, Annotation, GeneralizedTime, PrintableString, Type, UtcTime};
}
