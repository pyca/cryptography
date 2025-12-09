// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{SimpleAsn1Writable, Writer};
use pyo3::types::PyAnyMethods;
use pyo3::types::PyListMethods;

use crate::declarative_asn1::types::{
    AnnotatedType, AnnotatedTypeObject, BitString, Encoding, GeneralizedTime, IA5String,
    PrintableString, Type, UtcTime,
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

        let encoding = &annotated_type.annotation.get().encoding;
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

                if let Some(size) = &annotated_type.annotation.get().size {
                    let min = size.get().min;
                    let max = size.get().max.unwrap_or(usize::MAX);
                    if !(min..=max).contains(&values.len()) {
                        return Err(asn1::WriteError::AllocationError);
                    }
                }
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
                write_value(writer, &val, encoding)
            }
            Type::PyStr() => {
                let val: pyo3::pybacked::PyBackedStr = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let asn1_string: asn1::Utf8String<'_> = asn1::Utf8String::new(&val);
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
                let ia5_string: asn1::IA5String<'_> =
                    asn1::IA5String::new(&inner_str).ok_or(asn1::WriteError::AllocationError)?;
                write_value(writer, &ia5_string, encoding)
            }
            Type::UtcTime() => {
                let val: &pyo3::Bound<'_, UtcTime> = value
                    .cast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let py_datetime = val.get().inner.clone_ref(py).into_bound(py);
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
                let py_datetime = val.get().inner.clone_ref(py).into_bound(py);
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
                write_value(writer, &bitstring, encoding)
            }
        }
    }
}
