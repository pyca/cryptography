// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::IA5String as Asn1IA5String;
use asn1::PrintableString as Asn1PrintableString;
use asn1::SimpleAsn1Readable;
use asn1::UtcTime as Asn1UtcTime;
use pyo3::types::PyAnyMethods;
use pyo3::types::PyTzInfoAccess;
use pyo3::{IntoPyObject, PyTypeInfo};

/// Internal type representation for mapping between
/// Python and ASN.1.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub enum Type {
    // Core ASN.1 types
    //
    /// SEQUENCE (`class`, `dict`)
    /// The first element is the Python class that represents the sequence,
    /// the second element is a dict of the (already converted) fields of the class.
    Sequence(pyo3::Py<pyo3::types::PyType>, pyo3::Py<pyo3::types::PyDict>),
    /// SEQUENCE OF (`list[`T`]`)
    SequenceOf(pyo3::Py<AnnotatedType>),
    /// OPTIONAL (`T | None`)
    Option(pyo3::Py<AnnotatedType>),

    // Python types that we map to canonical ASN.1 types
    //
    /// `bool` -> `Boolean`
    PyBool(),
    /// `int` -> `Integer`
    PyInt(),
    /// `bytes` -> `Octet String`
    PyBytes(),
    /// `str` -> `UTF8String`
    PyStr(),
    /// PrintableString (`str`)
    PrintableString(),
    /// IA5String (`str`)
    IA5String(),
    /// UtcTime (`datetime`)
    UtcTime(),
    /// GeneralizedTime (`datetime`)
    GeneralizedTime(),
    /// BIT STRING (`bytes`)
    BitString(),
}

/// A type that we know how to encode/decode, along with any
/// annotations that influence encoding/decoding.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct AnnotatedType {
    pub inner: pyo3::Py<Type>,
    #[pyo3(get)]
    pub annotation: pyo3::Py<Annotation>,
}

#[pyo3::pymethods]
impl AnnotatedType {
    #[new]
    #[pyo3(signature = (inner, annotation))]
    fn new(inner: pyo3::Py<Type>, annotation: pyo3::Py<Annotation>) -> Self {
        Self { inner, annotation }
    }
}

/// An Python object with its corresponding AnnotatedType.
pub struct AnnotatedTypeObject<'a> {
    pub annotated_type: &'a AnnotatedType,
    pub value: pyo3::Bound<'a, pyo3::PyAny>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct Annotation {
    #[pyo3(get)]
    pub(crate) default: Option<pyo3::Py<pyo3::types::PyAny>>,
    #[pyo3(get)]
    pub(crate) encoding: Option<pyo3::Py<Encoding>>,
    #[pyo3(get)]
    pub(crate) size: Option<pyo3::Py<Size>>,
}

#[pyo3::pymethods]
impl Annotation {
    #[new]
    #[pyo3(signature = (default = None, encoding = None, size = None))]
    fn new(
        default: Option<pyo3::Py<pyo3::types::PyAny>>,
        encoding: Option<pyo3::Py<Encoding>>,
        size: Option<pyo3::Py<Size>>,
    ) -> Self {
        Self {
            default,
            encoding,
            size,
        }
    }

    fn is_empty(&self) -> bool {
        self.default.is_none() && self.encoding.is_none() && self.size.is_none()
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub enum Encoding {
    Implicit(u32),
    Explicit(u32),
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct Size {
    pub min: usize,
    pub max: Option<usize>,
}

#[pyo3::pymethods]
impl Size {
    #[new]
    fn new(min: usize, max: Option<usize>) -> Self {
        Size { min, max }
    }

    #[staticmethod]
    fn exact(n: usize) -> Self {
        Size {
            min: n,
            max: Some(n),
        }
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
        // TODO: Switch this to `to_str()` once our minimum version is py310+
        if Asn1PrintableString::new(&inner.to_cow(py)?).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid PrintableString: {inner}"
            )));
        }

        Ok(PrintableString { inner })
    }

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
pub struct IA5String {
    pub(crate) inner: pyo3::Py<pyo3::types::PyString>,
}

#[pyo3::pymethods]
impl IA5String {
    #[new]
    #[pyo3(signature = (inner,))]
    fn new(py: pyo3::Python<'_>, inner: pyo3::Py<pyo3::types::PyString>) -> pyo3::PyResult<Self> {
        // TODO: Switch this to `to_str()` once our minimum version is py310+
        if Asn1IA5String::new(&inner.to_cow(py)?).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid IA5String: {inner}"
            )));
        }

        Ok(IA5String { inner })
    }

    pub fn as_str(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Py<pyo3::types::PyString>> {
        Ok(self.inner.clone_ref(py))
    }

    fn __eq__(&self, py: pyo3::Python<'_>, other: pyo3::PyRef<'_, Self>) -> pyo3::PyResult<bool> {
        (**self.inner.bind(py)).eq(other.inner.bind(py))
    }

    pub fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        Ok(format!("IA5String({})", self.inner.bind(py).repr()?))
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
        // Since `PyDateTime` normalizes microseconds to be 0 <= microseconds <= 999,999,
        // we don't need to check if `inner` will be a valid asn1::GeneralizedTime: it will
        // be valid because its maximum value (999,999 microseconds == 999,999,000 nanoseconds)
        // does not exceed asn1::GeneralizedTime's max value (999,999,999 nanoseconds)
        Ok(GeneralizedTime { inner })
    }

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

#[derive(pyo3::FromPyObject)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct BitString {
    pub(crate) data: pyo3::Py<pyo3::types::PyBytes>,
    pub(crate) padding_bits: u8,
}

#[pyo3::pymethods]
impl BitString {
    #[new]
    #[pyo3(signature = (data, padding_bits,))]
    fn new(
        py: pyo3::Python<'_>,
        data: pyo3::Py<pyo3::types::PyBytes>,
        padding_bits: u8,
    ) -> pyo3::PyResult<Self> {
        if asn1::BitString::new(data.as_bytes(py), padding_bits).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid BIT STRING: data: {data}, padding_bits: {padding_bits}"
            )));
        }

        Ok(BitString { data, padding_bits })
    }

    pub fn as_bytes(&self, py: pyo3::Python<'_>) -> pyo3::Py<pyo3::types::PyBytes> {
        self.data.clone_ref(py)
    }

    pub fn padding_bits(&self) -> u8 {
        self.padding_bits
    }

    fn __eq__(&self, py: pyo3::Python<'_>, other: pyo3::PyRef<'_, Self>) -> pyo3::PyResult<bool> {
        Ok((**self.data.bind(py)).eq(other.data.bind(py))?
            && self.padding_bits == other.padding_bits)
    }

    pub fn __repr__(&self) -> pyo3::PyResult<String> {
        Ok(format!(
            "BitString(data={}, padding_bits={})",
            self.data, self.padding_bits,
        ))
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
    } else if class.is(IA5String::type_object(py)) {
        Type::IA5String().into_pyobject(py)
    } else if class.is(UtcTime::type_object(py)) {
        Type::UtcTime().into_pyobject(py)
    } else if class.is(GeneralizedTime::type_object(py)) {
        Type::GeneralizedTime().into_pyobject(py)
    } else if class.is(BitString::type_object(py)) {
        Type::BitString().into_pyobject(py)
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
) -> pyo3::PyResult<AnnotatedType> {
    let inner = non_root_python_to_rust(py, class)?.unbind();
    Ok(AnnotatedType {
        inner,
        annotation: Annotation {
            default: None,
            encoding: None,
            size: None,
        }
        .into_pyobject(py)?
        .unbind(),
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
        Ok(root.cast_into::<AnnotatedType>()?)
    } else {
        // Handle builtin types
        pyo3::Bound::new(py, non_root_type_to_annotated(py, class)?)
    }
}

pub(crate) fn type_to_tag(t: &Type, encoding: &Option<pyo3::Py<Encoding>>) -> asn1::Tag {
    let inner_tag = match t {
        Type::Sequence(_, _) => asn1::Sequence::TAG,
        Type::SequenceOf(_) => asn1::Sequence::TAG,
        Type::Option(t) => type_to_tag(t.get().inner.get(), encoding),
        Type::PyBool() => bool::TAG,
        Type::PyInt() => asn1::BigInt::TAG,
        Type::PyBytes() => <&[u8] as SimpleAsn1Readable>::TAG,
        Type::PyStr() => asn1::Utf8String::TAG,
        Type::PrintableString() => asn1::PrintableString::TAG,
        Type::IA5String() => asn1::IA5String::TAG,
        Type::UtcTime() => asn1::UtcTime::TAG,
        Type::GeneralizedTime() => asn1::GeneralizedTime::TAG,
        Type::BitString() => asn1::BitString::TAG,
    };

    match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(n) => asn1::implicit_tag(*n, inner_tag),
            Encoding::Explicit(n) => asn1::explicit_tag(*n),
        },
        None => inner_tag,
    }
}

#[cfg(test)]
mod tests {

    use pyo3::IntoPyObject;

    use super::{type_to_tag, AnnotatedType, Annotation, Type};

    #[test]
    // Needed for coverage of `type_to_tag(Type::Option(..))`, since
    // `type_to_tag` is never called with an optional value.
    fn test_option_type_to_tag() {
        pyo3::Python::initialize();

        pyo3::Python::attach(|py| {
            let ann_type = pyo3::Py::new(
                py,
                AnnotatedType {
                    inner: pyo3::Py::new(py, Type::PyInt()).unwrap(),
                    annotation: Annotation {
                        default: None,
                        encoding: None,
                        size: None,
                    }
                    .into_pyobject(py)
                    .unwrap()
                    .unbind(),
                },
            )
            .unwrap();
            let optional_type = pyo3::Py::new(
                py,
                AnnotatedType {
                    inner: pyo3::Py::new(py, Type::Option(ann_type)).unwrap(),
                    annotation: Annotation {
                        default: None,
                        encoding: None,
                        size: None,
                    }
                    .into_pyobject(py)
                    .unwrap()
                    .unbind(),
                },
            )
            .unwrap();
            let expected_tag = type_to_tag(&Type::Option(optional_type), &None);
            assert_eq!(expected_tag, type_to_tag(&Type::PyInt(), &None))
        })
    }
}
