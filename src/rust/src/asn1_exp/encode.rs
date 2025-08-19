// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{SimpleAsn1Writable, Writer};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use crate::asn1_exp::types::{AnnotatedType, AnnotatedTypeObject, Type};

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
        let value: Bound<'_, PyAny> = self.value.clone();
        let py = value.py();
        let annotated_type = self.annotated_type;

        let inner = annotated_type.inner.get();
        match &inner {
            Type::Sequence(cls) => {
                let fields = cls
                    .getattr(py, "__asn1_fields__")
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                let fields = fields
                    .downcast_bound::<PyDict>(py)
                    .map_err(|_| asn1::WriteError::AllocationError)?;

                write_value(
                    writer,
                    &asn1::SequenceWriter::new(&|w| {
                        for (name, ann_type) in fields.into_iter() {
                            let name = name
                                .downcast::<PyString>()
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
                )
            }
            Type::PyInt() => {
                let val: i64 = value
                    .extract()
                    .map_err(|_| asn1::WriteError::AllocationError)?;
                write_value(writer, &val)
            }
        }
    }
}
