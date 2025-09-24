// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{SimpleAsn1Writable, Writer};
use pyo3::types::{PyAnyMethods, PyStringMethods};

use crate::declarative_asn1::types::{AnnotatedType, AnnotatedTypeObject, PrintableString, Type};

fn write_value<T: SimpleAsn1Writable>(
    writer: &mut Writer<'_>,
    value: &T,
) -> Result<(), asn1::WriteError> {
    writer.write_element(value)
}

impl asn1::Asn1Writable for AnnotatedTypeObject<'_> {
    fn encoded_length(&self) -> Option<usize> {
        None
    }

    fn write(&self, writer: &mut Writer<'_>) -> Result<(), asn1::WriteError> {
        let value: pyo3::Bound<'_, pyo3::PyAny> = self.value.clone();
        let py = value.py();
        let annotated_type = self.annotated_type;

        let inner = annotated_type.inner.get();
        match &inner {
            Type::Sequence(_cls, fields) => write_value(
                writer,
                &asn1::SequenceWriter::new(&|w| {
                    for (name, ann_type) in fields.bind(py).into_iter() {
                        let name = name
                            .downcast::<pyo3::types::PyString>()
                            .map_err(|_| asn1::WriteError::AllocationError)?;
                        let ann_type = ann_type
                            .downcast::<AnnotatedType>()
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
            ),
            Type::PyBool() => {
                let val: bool = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val)
            }
            Type::PyInt() => {
                let val: i64 = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val)
            }
            Type::PyBytes() => {
                let val: &[u8] = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val)
            }
            Type::PyStr() => {
                let val: pyo3::pybacked::PyBackedStr = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let asn1_string: asn1::Utf8String<'_> = asn1::Utf8String::new(&val);
                write_value(writer, &asn1_string)
            }
            Type::PrintableString() => {
                let val: &pyo3::Bound<'_, PrintableString> = value
                    .downcast()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let inner_str = val
                    .get()
                    .inner
                    .bind(py)
                    .to_str()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let printable_string: asn1::PrintableString<'_> =
                    asn1::PrintableString::new(inner_str)
                        .ok_or(asn1::WriteError::AllocationError)?;
                write_value(writer, &printable_string)
            }
        }
    }
}
