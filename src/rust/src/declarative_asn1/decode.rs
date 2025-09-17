// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::{Asn1Readable, Parser, SimpleAsn1Readable};
use pyo3::types::IntoPyDict;
use pyo3::types::PyAnyMethods;
use std::collections::HashMap;

use crate::asn1::big_byte_slice_to_py_int;
use crate::declarative_asn1::types::{AnnotatedType, Type};

pub(crate) enum DecodeError {
    Asn1(asn1::ParseError),
    Py(pyo3::PyErr),
}

impl From<asn1::ParseError> for DecodeError {
    fn from(e: asn1::ParseError) -> Self {
        DecodeError::Asn1(e)
    }
}

impl From<pyo3::PyErr> for DecodeError {
    fn from(e: pyo3::PyErr) -> Self {
        DecodeError::Py(e)
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Asn1(e) => write!(f, "ASN.1 parse error: {e}"),
            DecodeError::Py(e) => write!(f, "{e}"),
        }
    }
}

type ParseResult<T> = Result<T, DecodeError>;

pub(crate) trait SimpleAsn1ReadablePy<'a>: Sized {
    type DerTarget: SimpleAsn1Readable<'a>;

    fn decode(py: pyo3::Python<'a>, parser: &mut Parser<'a>) -> ParseResult<pyo3::Bound<'a, Self>>;

    fn get_value(parser: &mut Parser<'a>) -> ParseResult<Self::DerTarget> {
        let value = Self::DerTarget::parse(parser)?;
        Ok(value)
    }
}

impl<'a> SimpleAsn1ReadablePy<'a> for pyo3::types::PyInt {
    type DerTarget = asn1::BigInt<'a>;

    fn decode(py: pyo3::Python<'a>, parser: &mut Parser<'a>) -> ParseResult<pyo3::Bound<'a, Self>> {
        let value = Self::get_value(parser)?;
        let pyint = big_byte_slice_to_py_int(py, value.as_bytes())?
            .downcast_into::<pyo3::types::PyInt>()
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "error converting integer value".to_string(),
                )
            })?;
        Ok(pyint)
    }
}

/// This mouthful of a trait allows for "dynamic" parsing of DER inputs,
/// where "dynamic" really just means we don't know what we're parsing
/// until runtime.
pub(crate) trait SimpleAsn1ReadablePyDyn<'a>: Sized {
    fn decode(
        &self,
        py: pyo3::Python<'a>,
        parser: &mut Parser<'a>,
    ) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>>;
}

impl<'a> SimpleAsn1ReadablePyDyn<'a> for AnnotatedType {
    fn decode(
        &self,
        py: pyo3::Python<'a>,
        parser: &mut Parser<'a>,
    ) -> ParseResult<pyo3::Bound<'a, pyo3::PyAny>> {
        let inner = self.inner.get();

        match &inner {
            Type::Sequence(cls, fields) => {
                let seq_parse_result = parser.read_element::<asn1::Sequence<'_>>()?;

                seq_parse_result.parse(|d| {
                    let mut kwargs: HashMap<String, pyo3::Bound<'a, pyo3::PyAny>> = HashMap::new();
                    let fields = fields.bind(py);
                    for (name, ann_type) in fields.into_iter() {
                        let name = name.extract::<&str>()?;
                        let ann_type = ann_type.downcast::<AnnotatedType>().map_err(|_| {
                            pyo3::exceptions::PyValueError::new_err(
                                "target type has invalid annotations".to_string(),
                            )
                        })?;
                        let value = ann_type.get().decode(py, d)?;
                        kwargs.insert(name.to_string(), value);
                    }
                    let val = cls
                        .call(py, (), Some(&kwargs.into_py_dict(py)?))?
                        .into_bound(py);
                    Ok(val)
                })
            }
            Type::PyInt() => pyo3::types::PyInt::decode(py, parser).map(|x| x.into_any()),
        }
    }
}
