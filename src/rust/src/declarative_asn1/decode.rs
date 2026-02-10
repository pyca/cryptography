// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::Parser;
use pyo3::types::{PyAnyMethods, PyListMethods};

use crate::asn1::big_byte_slice_to_py_int;
use crate::declarative_asn1::types::{
    check_size_constraint, is_tag_valid_for_type, is_tag_valid_for_variant, AnnotatedType,
    Annotation, BitString, Encoding, GeneralizedTime, IA5String, PrintableString, Tlv, Type,
    UtcTime, Variant,
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
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyBytes>> {
    let value = read_value::<&[u8]>(parser, &annotation.encoding)?;
    check_size_constraint(&annotation.size, value.len(), "OCTET STRING")?;
    Ok(pyo3::types::PyBytes::new(py, value))
}

fn decode_pystr<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyString>> {
    let value = read_value::<asn1::Utf8String<'a>>(parser, &annotation.encoding)?;
    check_size_constraint(&annotation.size, value.as_str().len(), "UTF8String")?;
    Ok(pyo3::types::PyString::new(py, value.as_str()))
}

fn decode_printable_string<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, PrintableString>> {
    let value = read_value::<asn1::PrintableString<'a>>(parser, &annotation.encoding)?.as_str();
    check_size_constraint(&annotation.size, value.len(), "PrintableString")?;
    let inner = pyo3::types::PyString::new(py, value).unbind();
    Ok(pyo3::Bound::new(py, PrintableString { inner })?)
}

fn decode_ia5_string<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, IA5String>> {
    let value = read_value::<asn1::IA5String<'a>>(parser, &annotation.encoding)?.as_str();
    check_size_constraint(&annotation.size, value.len(), "IA5String")?;
    let inner = pyo3::types::PyString::new(py, value).unbind();
    Ok(pyo3::Bound::new(py, IA5String { inner })?)
}

fn decode_oid<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, crate::oid::ObjectIdentifier>> {
    let oid = read_value::<asn1::ObjectIdentifier>(parser, &annotation.encoding)?;
    Ok(pyo3::Bound::new(py, crate::oid::ObjectIdentifier { oid })?)
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
    annotation: &Annotation,
) -> ParseResult<pyo3::Bound<'a, BitString>> {
    let value = read_value::<asn1::BitString<'a>>(parser, &annotation.encoding)?;
    let n_bits = value.as_bytes().len() * 8 - usize::from(value.padding_bits());
    check_size_constraint(&annotation.size, n_bits, "BIT STRING")?;

    let data = pyo3::types::PyBytes::new(py, value.as_bytes()).unbind();
    Ok(pyo3::Bound::new(
        py,
        BitString {
            data,
            padding_bits: value.padding_bits(),
        },
    )?)
}

fn decode_tlv<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> ParseResult<pyo3::Bound<'a, Tlv>> {
    let tlv = match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(_) => Err(CryptographyError::Py(
                // We don't support IMPLICIT TLV
                pyo3::exceptions::PyValueError::new_err(
                    "invalid type definition: TLV/ANY fields cannot be implicitly encoded"
                        .to_string(),
                ),
            ))?,
            Encoding::Explicit(n) => parser.read_explicit_element::<asn1::Tlv<'_>>(*n),
        },
        None => parser.read_element::<asn1::Tlv<'_>>(),
    }?;
    Ok(pyo3::Bound::new(
        py,
        Tlv {
            tag: tlv.tag().value(),
            data_index: tlv.full_data().len() - tlv.data().len(),
            full_data: pyo3::types::PyBytes::new(py, tlv.full_data()).unbind(),
        },
    )?)
}

// Utility function to handle explicit encoding when parsing
// CHOICE fields.
fn decode_choice_with_encoding<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    ann_type: &AnnotatedType,
    encoding: &Encoding,
) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
    match encoding {
        Encoding::Implicit(_) => Err(CryptographyError::Py(
            // CHOICEs cannot be IMPLICIT. See X.680 section 31.2.9.
            pyo3::exceptions::PyValueError::new_err(
                "invalid type definition: CHOICE fields cannot be implicitly encoded".to_string(),
            ),
        ))?,
        Encoding::Explicit(n) => {
            // Since we don't know which of the variants is present for this
            // CHOICE field, we'll parse this as a generic TLV encoded with
            // EXPLICIT, so `read_explicit_element` will consume the EXPLICIT
            // wrapper tag, and the TLV data will contain the variant.
            let tlv = parser.read_explicit_element::<asn1::Tlv<'_>>(*n)?;
            let type_without_explicit = AnnotatedType {
                inner: ann_type.inner.clone_ref(py),
                annotation: pyo3::Py::new(
                    py,
                    Annotation {
                        default: None,
                        encoding: None,
                        size: None,
                    },
                )?,
            };
            // Parse the TLV data (which contains the field without the EXPLICIT
            // wrapper)
            asn1::parse(tlv.full_data(), |d| {
                decode_annotated_type(py, d, &type_without_explicit)
            })
        }
    }
}

pub(crate) fn decode_annotated_type<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    ann_type: &AnnotatedType,
) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let inner = ann_type.inner.get();
    let annotation = &ann_type.annotation.get();
    let encoding = &annotation.encoding;

    // Handle DEFAULT annotation if field is not present (by
    // returning the default value)
    if let Some(default) = &ann_type.annotation.get().default {
        match parser.peek_tag() {
            Some(next_tag) if is_tag_valid_for_type(py, next_tag, inner, encoding) => (),
            _ => return Ok(default.bind(py).clone()),
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
                check_size_constraint(&annotation.size, list.len(), "SEQUENCE OF")?;
                Ok(list.into_any())
            })?
        }
        Type::Option(cls) => {
            match parser.peek_tag() {
                Some(t) if is_tag_valid_for_type(py, t, cls.get().inner.get(), encoding) => {
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
        Type::Choice(ts) => match encoding {
            Some(e) => decode_choice_with_encoding(py, parser, ann_type, e.get())?,
            None => {
                for t in ts.bind(py) {
                    let variant = t.cast::<Variant>()?.get();
                    match parser.peek_tag() {
                        Some(tag) if is_tag_valid_for_variant(py, tag, variant, encoding) => {
                            let decoded_value =
                                decode_annotated_type(py, parser, variant.ann_type.get())?;
                            return match &variant.tag_name {
                                Some(tag_name) => Ok(variant
                                    .python_class
                                    .call1(py, (decoded_value, tag_name))?
                                    .into_bound(py)),
                                None => Ok(decoded_value),
                            };
                        }
                        _ => continue,
                    }
                }
                Err(CryptographyError::Py(
                    pyo3::exceptions::PyValueError::new_err(
                        "could not find matching variant when parsing CHOICE field".to_string(),
                    ),
                ))?
            }
        },
        Type::PyBool() => decode_pybool(py, parser, encoding)?.into_any(),
        Type::PyInt() => decode_pyint(py, parser, encoding)?.into_any(),
        Type::PyBytes() => decode_pybytes(py, parser, annotation)?.into_any(),
        Type::PyStr() => decode_pystr(py, parser, annotation)?.into_any(),
        Type::PrintableString() => decode_printable_string(py, parser, annotation)?.into_any(),
        Type::IA5String() => decode_ia5_string(py, parser, annotation)?.into_any(),
        Type::ObjectIdentifier() => decode_oid(py, parser, annotation)?.into_any(),
        Type::UtcTime() => decode_utc_time(py, parser, encoding)?.into_any(),
        Type::GeneralizedTime() => decode_generalized_time(py, parser, encoding)?.into_any(),
        Type::BitString() => decode_bitstring(py, parser, annotation)?.into_any(),
        Type::Tlv() => decode_tlv(py, parser, encoding)?.into_any(),
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

#[cfg(test)]
mod tests {
    use crate::declarative_asn1::types::{AnnotatedType, Annotation, Encoding, Type, Variant};
    #[test]
    fn test_decode_implicit_choice() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let result = asn1::parse(&[], |parser| {
                let variants: Vec<Variant> = vec![];
                let choice = Type::Choice(pyo3::types::PyList::new(py, variants)?.unbind());
                let annotation = Annotation {
                    default: None,
                    encoding: None,
                    size: None,
                };
                let ann_type = AnnotatedType {
                    inner: pyo3::Py::new(py, choice)?,
                    annotation: pyo3::Py::new(py, annotation)?,
                };
                let encoding = Encoding::Implicit(0);
                super::decode_choice_with_encoding(py, parser, &ann_type, &encoding)
            });
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(format!("{error}")
                .contains("invalid type definition: CHOICE fields cannot be implicitly encoded"));
        });
    }
}
