// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::Parser;
use pyo3::types::PyAnyMethods;

use crate::asn1::big_byte_slice_to_py_int;
use crate::declarative_asn1::types::{
    type_to_tag, AnnotatedType, GeneralizedTime, PrintableString, Type, UtcTime,
};
use crate::error::CryptographyError;

type ParseResult<T> = Result<T, CryptographyError>;

fn decode_pybool<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyBool>> {
    let value = parser.read_element::<bool>()?;
    Ok(pyo3::types::PyBool::new(py, value).to_owned())
}

fn decode_pyint<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyInt>> {
    let value = parser.read_element::<asn1::BigInt<'a>>()?;
    let pyint =
        big_byte_slice_to_py_int(py, value.as_bytes())?.downcast_into::<pyo3::types::PyInt>()?;
    Ok(pyint)
}

fn decode_pybytes<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyBytes>> {
    let value = parser.read_element::<&[u8]>()?;
    Ok(pyo3::types::PyBytes::new(py, value))
}

fn decode_pystr<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyString>> {
    let value = parser.read_element::<asn1::Utf8String<'a>>()?;
    Ok(pyo3::types::PyString::new(py, value.as_str()))
}

fn decode_printable_string<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, PrintableString>> {
    let value = parser.read_element::<asn1::PrintableString<'a>>()?.as_str();
    let inner = pyo3::types::PyString::new(py, value).unbind();
    Ok(pyo3::Bound::new(py, PrintableString { inner })?)
}

fn decode_utc_time<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, UtcTime>> {
    let value = parser.read_element::<asn1::UtcTime>()?;
    let dt = value.as_datetime();

    let inner = crate::x509::datetime_to_py_utc(py, dt)?
        .downcast_into::<pyo3::types::PyDateTime>()?
        .unbind();

    Ok(pyo3::Bound::new(py, UtcTime { inner })?)
}

fn decode_generalized_time<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, GeneralizedTime>> {
    let value = parser.read_element::<asn1::GeneralizedTime>()?;
    let dt = value.as_datetime();

    let microseconds = match value.nanoseconds() {
        Some(x) if x % 1_000 == 0 => x / 1_000,
        Some(_) => {
            return Err(CryptographyError::Py(
                pyo3::exceptions::PyValueError::new_err(
                    "decoded GeneralizedTime data has higher precision than supported".to_string(),
                ),
            ))
        }
        None => 0,
    };

    let inner = crate::x509::datetime_to_py_utc_with_microseconds(py, dt, microseconds)?
        .downcast_into::<pyo3::types::PyDateTime>()?
        .unbind();

    Ok(pyo3::Bound::new(py, GeneralizedTime { inner })?)
}

pub(crate) fn decode_annotated_type<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    ann_type: &AnnotatedType,
) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let inner = ann_type.inner.get();

    // Handle DEFAULT annotation if field is not present (by
    // returning the default value)
    if let Some(default) = &ann_type.annotation.default {
        let expected_tag = type_to_tag(inner);
        let next_tag = parser.peek_tag();
        if next_tag != Some(expected_tag) {
            return Ok(default.value.clone_ref(py).into_bound(py));
        }
    }

    match &inner {
        Type::Sequence(cls, fields) => {
            let seq_parse_result = parser.read_element::<asn1::Sequence<'_>>()?;

            seq_parse_result.parse(|d| {
                let kwargs = pyo3::types::PyDict::new(py);
                let fields = fields.bind(py);
                for (name, ann_type) in fields.into_iter() {
                    let ann_type = ann_type.downcast::<AnnotatedType>()?;
                    let value = decode_annotated_type(py, d, ann_type.get())?;
                    kwargs.set_item(name, value)?;
                }
                let val = cls.call(py, (), Some(&kwargs))?.into_bound(py);
                Ok(val)
            })
        }
        Type::Option(cls) => {
            let inner_tag = type_to_tag(cls.get().inner.get());
            match parser.peek_tag() {
                Some(t) if t == inner_tag => {
                    let decoded_value = decode_annotated_type(py, parser, cls.get())?;
                    Ok(decoded_value)
                }
                _ => Ok(pyo3::types::PyNone::get(py).to_owned().into_any()),
            }
        }
        Type::PyBool() => Ok(decode_pybool(py, parser)?.into_any()),
        Type::PyInt() => Ok(decode_pyint(py, parser)?.into_any()),
        Type::PyBytes() => Ok(decode_pybytes(py, parser)?.into_any()),
        Type::PyStr() => Ok(decode_pystr(py, parser)?.into_any()),
        Type::PrintableString() => Ok(decode_printable_string(py, parser)?.into_any()),
        Type::UtcTime() => Ok(decode_utc_time(py, parser)?.into_any()),
        Type::GeneralizedTime() => Ok(decode_generalized_time(py, parser)?.into_any()),
    }
}
