// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{
    IA5String as Asn1IA5String, PrintableString as Asn1PrintableString, SimpleAsn1Readable,
    UtcTime as Asn1UtcTime,
};
use pyo3::types::{PyAnyMethods, PyTzInfoAccess};
use pyo3::{IntoPyObject, PyTypeInfo};

use crate::error::CryptographyError;

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
    /// CHOICE (`T | U | ...`)
    /// The list contains elements of type Variant
    Choice(pyo3::Py<pyo3::types::PyList>),

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
    /// ObjectIdentifier
    ObjectIdentifier(),
    /// UtcTime (`datetime`)
    UtcTime(),
    /// GeneralizedTime (`datetime`)
    GeneralizedTime(),
    /// BIT STRING (`bytes`)
    BitString(),
    /// ANY (parsed as a TLV)
    Tlv(),
}

/// A type that we know how to encode/decode, along with any
/// annotations that influence encoding/decoding.
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
#[derive(Debug)]
pub struct AnnotatedType {
    #[pyo3(get)]
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

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct Variant {
    #[pyo3(get)]
    pub python_class: pyo3::Py<pyo3::types::PyType>,
    #[pyo3(get)]
    pub ann_type: pyo3::Py<AnnotatedType>,
    #[pyo3(get)]
    pub tag_name: Option<String>,
}

#[pyo3::pymethods]
impl Variant {
    #[new]
    fn new(
        python_class: pyo3::Py<pyo3::types::PyType>,
        ann_type: pyo3::Py<AnnotatedType>,
        tag_name: Option<String>,
    ) -> Self {
        Self {
            python_class,
            ann_type,
            tag_name,
        }
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
pub struct Tlv {
    #[pyo3(get)]
    pub tag: u32,
    #[pyo3(get)]
    pub length: usize,

    // We store the bytes of the entire TLV, and to access the Value part
    // we store the index where it starts.
    pub data_index: usize,
    pub full_data: pyo3::Py<pyo3::types::PyBytes>,
}

#[pyo3::pymethods]
impl Tlv {
    pub fn parse<'p>(
        &'p self,
        py: pyo3::Python<'p>,
        class: &pyo3::Bound<'p, pyo3::types::PyType>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        crate::declarative_asn1::asn1::decode_der(py, class, self.full_data.as_bytes(py))
    }

    #[getter]
    pub fn data<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.full_data.as_bytes(py)[self.data_index..])
    }
}

// TODO: Once the minimum Python version is >= 3.10, use a `self_cell`
// to store the owned PyString along with the dependent Asn1PrintableString
// in order to avoid verifying the string twice (once during construction,
// and again during serialization).
// This is because for Python < 3.10 getting an Asn1PrintableString object
// from a PyString requires calling `to_cow()`, which creates an intermediate
// `Cow` object with a different lifetime from the PyString.
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

// TODO: Once the minimum Python version is >= 3.10, use a `self_cell`
// to store the owned PyString along with the dependent Asn1IA5String
// in order to avoid verifying the string twice (once during construction,
// and again during serialization).
// This is because for Python < 3.10 getting an Asn1IA5String object
// from a PyString requires calling `to_cow()`, which creates an intermediate
// `Cow` object with a different lifetime from the PyString.
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
            crate::x509::py_to_datetime_with_microseconds(py, inner.bind(py).clone())?;

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
    } else if class.is(crate::oid::ObjectIdentifier::type_object(py)) {
        Type::ObjectIdentifier().into_pyobject(py)
    } else if class.is(UtcTime::type_object(py)) {
        Type::UtcTime().into_pyobject(py)
    } else if class.is(GeneralizedTime::type_object(py)) {
        Type::GeneralizedTime().into_pyobject(py)
    } else if class.is(BitString::type_object(py)) {
        Type::BitString().into_pyobject(py)
    } else if class.is(Tlv::type_object(py)) {
        Type::Tlv().into_pyobject(py)
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

// Checks if encoding `tag_without_encoding` using `encoding` results
// in `tag`
fn check_tag_with_encoding(
    tag_without_encoding: asn1::Tag,
    encoding: &Option<pyo3::Py<Encoding>>,
    tag: asn1::Tag,
) -> bool {
    let tag_with_encoding = match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(n) => asn1::implicit_tag(*n, tag_without_encoding),
            Encoding::Explicit(n) => asn1::explicit_tag(*n),
        },
        None => tag_without_encoding,
    };
    tag_with_encoding == tag
}

// Utility function to see if a tag matches an unnanotated variant.
pub(crate) fn is_tag_valid_for_variant(
    py: pyo3::Python<'_>,
    tag: asn1::Tag,
    variant: &Variant,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> bool {
    let ann_type = variant.ann_type.get();

    // There are two encodings at play here: the encoding of the CHOICE itself,
    // and the encoding of each of the variants. The encoding of the CHOICE will
    // only affect the tag if it's EXPLICIT (where it adds a wrapper). Otherwise,
    // we use the encoding of the variant.
    let encoding_to_match = match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(_) => &ann_type.annotation.get().encoding,
            Encoding::Explicit(_) => encoding,
        },
        None => &ann_type.annotation.get().encoding,
    };

    is_tag_valid_for_type(py, tag, ann_type.inner.get(), encoding_to_match)
}

// Given `tag` and `encoding`, returns whether that tag with that encoding
// matches what one would expect to see when decoding `type_`
pub(crate) fn is_tag_valid_for_type(
    py: pyo3::Python<'_>,
    tag: asn1::Tag,
    type_: &Type,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> bool {
    match type_ {
        Type::Sequence(_, _) => check_tag_with_encoding(asn1::Sequence::TAG, encoding, tag),
        Type::SequenceOf(_) => check_tag_with_encoding(asn1::Sequence::TAG, encoding, tag),
        Type::Option(t) => is_tag_valid_for_type(py, tag, t.get().inner.get(), encoding),
        Type::Choice(variants) => variants.bind(py).into_iter().any(|v| {
            is_tag_valid_for_variant(py, tag, v.cast::<Variant>().unwrap().get(), encoding)
        }),
        Type::PyBool() => check_tag_with_encoding(bool::TAG, encoding, tag),
        Type::PyInt() => check_tag_with_encoding(asn1::BigInt::TAG, encoding, tag),
        Type::PyBytes() => {
            check_tag_with_encoding(<&[u8] as SimpleAsn1Readable>::TAG, encoding, tag)
        }
        Type::PyStr() => check_tag_with_encoding(asn1::Utf8String::TAG, encoding, tag),
        Type::PrintableString() => {
            check_tag_with_encoding(asn1::PrintableString::TAG, encoding, tag)
        }
        Type::IA5String() => check_tag_with_encoding(asn1::IA5String::TAG, encoding, tag),
        Type::ObjectIdentifier() => {
            check_tag_with_encoding(asn1::ObjectIdentifier::TAG, encoding, tag)
        }
        Type::UtcTime() => check_tag_with_encoding(asn1::UtcTime::TAG, encoding, tag),
        Type::GeneralizedTime() => {
            check_tag_with_encoding(asn1::GeneralizedTime::TAG, encoding, tag)
        }
        Type::BitString() => check_tag_with_encoding(asn1::BitString::TAG, encoding, tag),
        Type::Tlv() => {
            match encoding {
                Some(e) => match e.get() {
                    // TLVs with implicit annotations are not supported
                    // (they are caught first at the Python level)
                    Encoding::Implicit(_) => false,
                    Encoding::Explicit(n) => tag == asn1::explicit_tag(*n),
                },
                // When reading TLVs we accept any tag
                None => true,
            }
        }
    }
}

pub(crate) fn check_size_constraint(
    size_annotation: &Option<pyo3::Py<Size>>,
    data_length: usize,
    field_type: &str,
) -> Result<(), CryptographyError> {
    if let Some(size) = size_annotation {
        let min = size.get().min;
        let max = size.get().max.unwrap_or(usize::MAX);
        if !(min..=max).contains(&data_length) {
            return Err(CryptographyError::Py(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "{0} has size {1}, expected size in [{2}, {3}]",
                    field_type, data_length, min, max
                )),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use asn1::SimpleAsn1Readable;
    use pyo3::{IntoPyObject, PyTypeInfo};

    use super::{
        is_tag_valid_for_type, is_tag_valid_for_variant, AnnotatedType, Annotation, Encoding, Type,
        Variant,
    };

    #[test]
    // Needed for coverage of `is_tag_valid_for_type(Type::Option(..))`, since
    // `is_tag_valid_for_type` is never called with an optional value.
    fn test_option_is_tag_valid_for_type() {
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
            assert!(is_tag_valid_for_type(
                py,
                asn1::BigInt::TAG,
                &Type::Option(optional_type),
                &None
            ));
        })
    }
    #[test]
    // Needed for coverage of
    // `is_tag_valid_for_variant(..., encoding=Encoding::Implicit)`, since
    // `is_tag_valid_for_variant` is never called with an implicit encoding.
    fn test_is_tag_valid_for_implicit_variant() {
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
            let variant = Variant {
                python_class: pyo3::types::PyInt::type_object(py).unbind(),
                ann_type,
                tag_name: None,
            };
            let encoding = pyo3::Py::new(py, Encoding::Implicit(3)).ok();
            assert!(is_tag_valid_for_variant(
                py,
                asn1::BigInt::TAG,
                &variant,
                &encoding
            ));
        })
    }
}
