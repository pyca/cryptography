// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::Asn1Writable;
use pyo3::types::PyAnyMethods;

use crate::declarative_asn1::decode::decode_annotated_type;
use crate::declarative_asn1::types as asn1_types;

#[pyo3::pyfunction]
pub(crate) fn encode_der<'p>(
    py: pyo3::Python<'p>,
    value: &pyo3::Bound<'p, pyo3::types::PyAny>,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let class = value.get_type();

    // TODO error messages are lost since asn1::WriteError does not allow
    // specifying error messages
    let annotated_type = asn1_types::python_class_to_annotated(py, &class)?;
    let object = asn1_types::AnnotatedTypeObject {
        annotated_type: annotated_type.get(),
        value: value.clone(),
    };
    let encoded_bytes = asn1::write(|writer| object.write(writer))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    Ok(pyo3::types::PyBytes::new(py, &encoded_bytes))
}

#[pyo3::pyfunction]
pub(crate) fn decode_der<'p>(
    py: pyo3::Python<'p>,
    class: &pyo3::Bound<'p, pyo3::types::PyType>,
    value: &'p [u8],
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    asn1::parse(value, |parser| {
        let annotated_type = asn1_types::python_class_to_annotated(py, class)?;
        decode_annotated_type(py, parser, annotated_type.get())
    })
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
