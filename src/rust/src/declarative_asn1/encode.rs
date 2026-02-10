// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{SimpleAsn1Writable, Writer};
use pyo3::types::{PyAnyMethods, PyListMethods};

use crate::declarative_asn1::types::{
    check_size_constraint, AnnotatedType, AnnotatedTypeObject, BitString, Encoding,
    GeneralizedTime, IA5String, PrintableString, Type, UtcTime, Variant,
};

fn write_value<T: SimpleAsn1Writable>(
    writer: &mut Writer<'_>,
    value: &T,
    encoding: &Option<pyo3::Py<Encoding>>,
) -> Result<(), asn1::WriteError> {
    match encoding {
        Some(e) => match e.get() {
            Encoding::Implicit(tag) => writer.write_implicit_element(value, *tag),
            Encoding::Explicit(tag) => writer.write_explicit_element(value, *tag),
        },
        None => writer.write_element(value),
    }
}

impl asn1::Asn1Writable for AnnotatedTypeObject<'_> {
    fn encoded_length(&self) -> Option<usize> {
        None
    }

    fn write(&self, writer: &mut Writer<'_>) -> Result<(), asn1::WriteError> {
        let value: pyo3::Bound<'_, pyo3::PyAny> = self.value.clone();
        let py = value.py();
        let annotated_type = self.annotated_type;

        // Handle DEFAULT annotation if value is same as default (by
        // not encoding the value)
        if let Some(default) = &annotated_type.annotation.get().default {
            if value
                .eq(default)
                .map_err(|_| asn1::WriteError::AllocationError)?
            {
                return Ok(());
            }
        }

        let annotation = &annotated_type.annotation.get();
        let encoding = &annotation.encoding;
        let inner = annotated_type.inner.get();
        match &inner {
            Type::Sequence(_cls, fields) => write_value(
                writer,
                &asn1::SequenceWriter::new(&|w| {
                    for (name, ann_type) in fields.bind(py).into_iter() {
                        let name = name
                            .cast::<pyo3::types::PyString>()
                            .map_err(|_| asn1::WriteError::AllocationError)?;
                        let ann_type = ann_type
                            .cast::<AnnotatedType>()
                            .map_err(|_| asn1::WriteError::AllocationError)?;
                        let object = AnnotatedTypeObject {
                            annotated_type: ann_type.get(),
                            value: self
                                .value
                                .getattr(name)
                                .map_err(|_| asn1::WriteError::AllocationError)?,
                        };
                        w.write_element(&object)?;
                    }
                    Ok(())
                }),
                encoding,
            ),
            Type::SequenceOf(cls) => {
                let values: Vec<AnnotatedTypeObject<'_>> = value
                    .cast::<pyo3::types::PyList>()
                    .map_err(|_| asn1::WriteError::AllocationError)?
                    .iter()
                    .map(|e| AnnotatedTypeObject {
                        annotated_type: cls.get(),
                        value: e,
                    })
                    .collect();

                check_size_constraint(&annotation.size, values.len(), "SEQUENCE OF")
                    .map_err(|_| asn1::WriteError::AllocationError)?;

                write_value(writer, &asn1::SequenceOfWriter::new(values), encoding)
            }
            Type::Option(cls) => {
                if !value.is_none() {
                    let inner_object = AnnotatedTypeObject {
                        annotated_type: &AnnotatedType {
                            inner: cls.get().inner.clone_ref(py),
                            // Since for optional types the annotations are enforced to be associated with the Option
                            // (instead of the inner type), when encoding the inner type we add the annotations of the Option
                            annotation: annotated_type.annotation.clone_ref(py),
                        },
                        value,
                    };
                    inner_object.write(writer)
                } else {
                    // Missing OPTIONAL values are omitted from DER encoding
                    Ok(())
                }
            }
            Type::Choice(ts) => {
                for t in ts.bind(py) {
                    let variant = t
                        .cast::<Variant>()
                        .map_err(|_| asn1::WriteError::AllocationError)?
                        .get();

                    if !value.is_exact_instance(variant.python_class.bind(py)) {
                        continue;
                    }

                    // Check if this variant matches the value
                    let matches = match &variant.tag_name {
                        Some(expected_tag) => {
                            let value_tag: String = value
                                .getattr("tag")
                                .map_err(|_| asn1::WriteError::AllocationError)?
                                .extract()
                                .map_err(|_| asn1::WriteError::AllocationError)?;
                            &value_tag == expected_tag
                        }
                        None => true,
                    };

                    if matches {
                        let val = if variant.tag_name.is_some() {
                            value
                                .getattr("value")
                                .map_err(|_| asn1::WriteError::AllocationError)?
                        } else {
                            value
                        };
                        let object = AnnotatedTypeObject {
                            annotated_type: variant.ann_type.get(),
                            value: val,
                        };
                        match encoding {
                            Some(e) => match e.get() {
                                // CHOICEs cannot be IMPLICIT. See X.680 section 31.2.9.
                                Encoding::Implicit(_) => {
                                    return Err(asn1::WriteError::AllocationError)
                                }
                                Encoding::Explicit(n) => {
                                    return writer.write_explicit_element(&object, *n)
                                }
                            },
                            None => return object.write(writer),
                        }
                    }
                }
                // No matching variant found
                Err(asn1::WriteError::AllocationError)
            }
            Type::PyBool() => {
                let val: bool = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val, encoding)
            }
            Type::PyInt() => {
                let val: i64 = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val, encoding)
            }
            Type::PyBytes() => {
                let val: &[u8] = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                check_size_constraint(&annotation.size, val.len(), "OCTET STRING")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val, encoding)
            }
            Type::PyStr() => {
                let val: pyo3::pybacked::PyBackedStr = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let asn1_string: asn1::Utf8String<'_> = asn1::Utf8String::new(&val);
                check_size_constraint(&annotation.size, val.len(), "UTF8String")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &asn1_string, encoding)
            }
            Type::PrintableString() => {
                let val: &pyo3::Bound<'_, PrintableString> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                // TODO: Switch this to `to_str()` once our minimum version is py310+
                let inner_str = val
                    .get()
                    .inner
                    .to_cow(py)
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                check_size_constraint(&annotation.size, inner_str.len(), "PrintableString")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let printable_string: asn1::PrintableString<'_> =
                    asn1::PrintableString::new(&inner_str)
                        .ok_or(asn1::WriteError::AllocationError)?;
                write_value(writer, &printable_string, encoding)
            }
            Type::IA5String() => {
                let val: &pyo3::Bound<'_, IA5String> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                // TODO: Switch this to `to_str()` once our minimum version is py310+
                let inner_str = val
                    .get()
                    .inner
                    .to_cow(py)
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                check_size_constraint(&annotation.size, inner_str.len(), "IA5String")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let ia5_string: asn1::IA5String<'_> =
                    asn1::IA5String::new(&inner_str).ok_or(asn1::WriteError::AllocationError)?;
                write_value(writer, &ia5_string, encoding)
            }
            Type::ObjectIdentifier() => {
                let val: &pyo3::Bound<'_, crate::oid::ObjectIdentifier> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val.get().oid, encoding)
            }
            Type::UtcTime() => {
                let val: &pyo3::Bound<'_, UtcTime> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let py_datetime = val.get().inner.bind(py).clone();
                let datetime = crate::x509::py_to_datetime(py, py_datetime)
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let utc_time =
                    asn1::UtcTime::new(datetime).map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &utc_time, encoding)
            }
            Type::GeneralizedTime() => {
                let val: &pyo3::Bound<'_, GeneralizedTime> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let py_datetime = val.get().inner.bind(py).clone();
                let (datetime, microseconds) =
                    crate::x509::py_to_datetime_with_microseconds(py, py_datetime)
                        .map_err(|_| asn1::WriteError::AllocationError)?;
                let nanoseconds = microseconds.map(|m| m * 1000);
                let generalized_time = asn1::GeneralizedTime::new(datetime, nanoseconds)
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &generalized_time, encoding)
            }
            Type::BitString() => {
                let val: &pyo3::Bound<'_, BitString> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let bitstring: asn1::BitString<'_> =
                    asn1::BitString::new(val.get().data.as_bytes(py), val.get().padding_bits)
                        .ok_or(asn1::WriteError::AllocationError)?;
                let n_bits = bitstring.as_bytes().len() * 8 - usize::from(bitstring.padding_bits());
                check_size_constraint(&annotation.size, n_bits, "BIT STRING")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &bitstring, encoding)
            }
            Type::Tlv() => Err(asn1::WriteError::AllocationError),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::declarative_asn1::types::{
        AnnotatedType, AnnotatedTypeObject, Annotation, Encoding, Type, Variant,
    };
    use asn1::Asn1Writable;
    use pyo3::PyTypeInfo;
    #[test]
    fn test_encode_implicit_choice() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let annotation = Annotation {
                default: None,
                encoding: None,
                size: None,
            };
            let ann_type_variant = AnnotatedType {
                inner: pyo3::Py::new(py, Type::PyInt()).unwrap(),
                annotation: pyo3::Py::new(py, annotation).unwrap(),
            };
            let variant = Variant {
                python_class: pyo3::types::PyInt::type_object(py).unbind(),
                ann_type: pyo3::Py::new(py, ann_type_variant).unwrap(),
                tag_name: None,
            };

            let variants = vec![variant];
            let choice = Type::Choice(pyo3::types::PyList::new(py, variants).unwrap().unbind());
            let annotation = Annotation {
                default: None,
                encoding: Some(pyo3::Py::new(py, Encoding::Implicit(0)).unwrap()),
                size: None,
            };
            let ann_type = AnnotatedType {
                inner: pyo3::Py::new(py, choice).unwrap(),
                annotation: pyo3::Py::new(py, annotation).unwrap(),
            };

            let value = pyo3::types::PyInt::new(py, 3).into_any();
            let object = AnnotatedTypeObject {
                annotated_type: &ann_type,
                value,
            };

            let result = asn1::write(|writer| object.write(writer));
            assert!(result.is_err());
        });
    }
}
