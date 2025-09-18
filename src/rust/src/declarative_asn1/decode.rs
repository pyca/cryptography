// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{Asn1Readable, Parser};
use pyo3::types::PyAnyMethods;

use crate::asn1::big_byte_slice_to_py_int;
use crate::declarative_asn1::types::{AnnotatedType, Type};
use crate::error::CryptographyError;

type ParseResult<T> = Result<T, CryptographyError>;

fn decode_pyint<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
) -> ParseResult<pyo3::Bound<'a, pyo3::types::PyInt>> {
    let value = asn1::BigInt::parse(parser)?;
    let pyint = big_byte_slice_to_py_int(py, value.as_bytes())?
        .downcast_into::<pyo3::types::PyInt>()
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("error converting integer value".to_string())
        })?;
    Ok(pyint)
}

pub(crate) fn decode_annotated_type<'a>(
    py: pyo3::Python<'a>,
    parser: &mut Parser<'a>,
    ann_type: &AnnotatedType,
) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
    let inner = ann_type.inner.get();
    match &inner {
        Type::Sequence(cls, fields) => {
            let seq_parse_result = parser.read_element::<asn1::Sequence<'_>>()?;

            seq_parse_result.parse(|d| {
                let kwargs = pyo3::types::PyDict::new(py);
                let fields = fields.bind(py);
                for (name, ann_type) in fields.into_iter() {
                    let ann_type = ann_type.downcast::<AnnotatedType>().map_err(|_| {
                        pyo3::exceptions::PyValueError::new_err(
                            "target type has invalid annotations".to_string(),
                        )
                    })?;
                    let value = decode_annotated_type(py, d, ann_type.get())?;
                    kwargs.set_item(name, value)?;
                }
                let val = cls.call(py, (), Some(&kwargs))?.into_bound(py);
                Ok(val)
            })
        }
        Type::PyInt() => Ok(decode_pyint(py, parser)?.into_any()),
    }
}
