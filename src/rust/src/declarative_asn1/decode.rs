// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::Parser;
use pyo3::types::PyAnyMethods;
use pyo3::types::PyListMethods;

use crate::asn1::big_byte_slice_to_py_int;
use crate::declarative_asn1::types::{
    type_to_tag, AnnotatedType, BitString, Encoding, GeneralizedTime, IA5String, PrintableString,
    Type, UtcTime,
};
use crate::error::CryptographyError;

type ParseResult<T> = Result<T, CryptographyError>;

fn read_value<'a, T: asn1::SimpleAsn1Readable<'a>>(
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<T> {
    let value = match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(n) => parser.read_implicit_element::<T>(*n),
            Encoding::Explicit(n) => parser.read_explicit_element::<T>(*n),
        },
        None => parser.read_element::<T>(),
    }?;
    Ok(value)
}

fn decode_pybool<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyBool>> {
    let value = read_value::<bool>(parser, encoding)?;
    Ok(pyo3::types::PyBool::new(py, value).to_owned())
}

fn decode_pyint<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyInt>> {
    let value = read_value::<asn1::BigInt<'a>>(parser, encoding)?;
    let pyint =
        big_byte_slice_to_py_int(py, value.as_bytes())?.cast_into::<pyo3::types::PyInt>()?;
    Ok(pyint)
}

fn decode_pybytes<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyBytes>> {
    let value = read_value::<&[u8]>(parser, encoding)?;
    Ok(pyo3::types::PyBytes::new(py, value))
}

fn decode_pystr<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyString>> {
    let value = read_value::<asn1::Utf8String<'a>>(parser, encoding)?;
    Ok(pyo3::types::PyString::new(py, value.as_str()))
}

fn decode_printable_string<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, PrintableString>> {
    let value = read_value::<asn1::PrintableString<'a>>(parser, encoding)?.as_str();
    let inner = pyo3::types::PyString::new(py, value).unbind();
    Ok(pyo3::Bound::new(py, PrintableString { inner })?)
}

fn decode_ia5_string<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, IA5String>> {
    let value = read_value::<asn1::IA5String<'a>>(parser, encoding)?.as_str();
    let inner = pyo3::types::PyString::new(py, value).unbind();
    Ok(pyo3::Bound::new(py, IA5String { inner })?)
}

fn decode_utc_time<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, UtcTime>> {
    let value = read_value::<asn1::UtcTime>(parser, encoding)?;
    let dt = value.as_datetime();

    let inner = crate::x509::datetime_to_py_utc(py, dt)?
        .cast_into::<pyo3::types::PyDateTime>()?
        .unbind();

    Ok(pyo3::Bound::new(py, UtcTime { inner })?)
}

fn decode_generalized_time<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, GeneralizedTime>> {
    let value = read_value::<asn1::GeneralizedTime>(parser, encoding)?;
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
        .cast_into::<pyo3::types::PyDateTime>()?
        .unbind();

    Ok(pyo3::Bound::new(py, GeneralizedTime { inner })?)
}

fn decode_bitstring<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, BitString>> {
    let value = read_value::<asn1::BitString<'a>>(parser, encoding)?;
    let data = pyo3::types::PyBytes::new(py, value.as_bytes()).unbind();
    Ok(pyo3::Bound::new(
        py,
        BitString {
            data,
            padding_bits: value.padding_bits(),
        },
    )?)
}

pub(crate) fn decode_annotated_type<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    ann_type: &AnnotatedType,
) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let inner = ann_type.inner.get();
    let encoding = &ann_type.annotation.get().encoding;

    // Handle DEFAULT annotation if field is not present (by
    // returning the default value)
    if let Some(default) = &ann_type.annotation.get().default {
        let expected_tag = type_to_tag(inner, encoding);
        let next_tag = parser.peek_tag();
        if next_tag != Some(expected_tag) {
            return Ok(default.clone_ref(py).into_bound(py));
        }
    }

    let decoded = match &inner {
        Type::Sequence(cls, fields) => {
            let seq_parse_result = read_value::<asn1::Sequence<'_>>(parser, encoding)?;

            seq_parse_result.parse(|d| -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
                let kwargs = pyo3::types::PyDict::new(py);
                let fields = fields.bind(py);
                for (name, ann_type) in fields.into_iter() {
                    let ann_type = ann_type.cast::<AnnotatedType>()?;
                    let value = decode_annotated_type(py, d, ann_type.get())?;
                    kwargs.set_item(name, value)?;
                }
                let val = cls.call(py, (), Some(&kwargs))?.into_bound(py);
                Ok(val)
            })?
        }
        Type::SequenceOf(cls) => {
            let seqof_parse_result = read_value::<asn1::Sequence<'_>>(parser, encoding)?;

            seqof_parse_result.parse(|d| -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
                let inner_ann_type = cls.get();
                let list = pyo3::types::PyList::empty(py);
                while !d.is_empty() {
                    let val = decode_annotated_type(py, d, inner_ann_type)?;
                    list.append(val)?;
                }
                if let Some(size) = &ann_type.annotation.get().size {
                    let list_len = list.len();
                    let min = size.get().min;
                    let max = size.get().max.unwrap_or(usize::MAX);
                    if !(min..=max).contains(&list_len) {
                        return Err(CryptographyError::Py(
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "SEQUENCE OF has size {0}, expected size in [{1}, {2}]",
                                list_len, min, max
                            )),
                        ));
                    }
                }
                Ok(list.into_any())
            })?
        }
        Type::Option(cls) => {
            let inner_tag = type_to_tag(cls.get().inner.get(), encoding);
            match parser.peek_tag() {
                Some(t) if t == inner_tag => {
                    // For optional types, annotations will always be associated to the `Optional` type
                    // i.e: `Annotated[Optional[T], annotation]`, as opposed to the inner `T` type.
                    // Therefore, when decoding the inner type `T` we must pass the annotation of the `Optional`
                    let inner_ann_type = AnnotatedType {
                        inner: cls.get().inner.clone_ref(py),
                        annotation: ann_type.annotation.clone_ref(py),
                    };
                    decode_annotated_type(py, parser, &inner_ann_type)?
                }
                _ => pyo3::types::PyNone::get(py).to_owned().into_any(),
            }
        }
        Type::PyBool() => decode_pybool(py, parser, encoding)?.into_any(),
        Type::PyInt() => decode_pyint(py, parser, encoding)?.into_any(),
        Type::PyBytes() => decode_pybytes(py, parser, encoding)?.into_any(),
        Type::PyStr() => decode_pystr(py, parser, encoding)?.into_any(),
        Type::PrintableString() => decode_printable_string(py, parser, encoding)?.into_any(),
        Type::IA5String() => decode_ia5_string(py, parser, encoding)?.into_any(),
        Type::UtcTime() => decode_utc_time(py, parser, encoding)?.into_any(),
        Type::GeneralizedTime() => decode_generalized_time(py, parser, encoding)?.into_any(),
        Type::BitString() => decode_bitstring(py, parser, encoding)?.into_any(),
    };

    match &ann_type.annotation.get().default {
        Some(default) if decoded.eq(default.bind(py))? => Err(CryptographyError::Py(
            pyo3::exceptions::PyValueError::new_err(
                "invalid DER: DEFAULT value was explicitly encoded".to_string(),
            ),
        )),
        _ => Ok(decoded),
    }
}
