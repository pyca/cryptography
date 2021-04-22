// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::class::basic::CompareOp;
use pyo3::conversion::ToPyObject;

enum PyAsn1Error {
    Asn1(asn1::ParseError),
    Py(pyo3::PyErr),
}

impl From<asn1::ParseError> for PyAsn1Error {
    fn from(e: asn1::ParseError) -> PyAsn1Error {
        PyAsn1Error::Asn1(e)
    }
}

impl From<pyo3::PyErr> for PyAsn1Error {
    fn from(e: pyo3::PyErr) -> PyAsn1Error {
        PyAsn1Error::Py(e)
    }
}

impl From<PyAsn1Error> for pyo3::PyErr {
    fn from(e: PyAsn1Error) -> pyo3::PyErr {
        match e {
            PyAsn1Error::Asn1(asn1_error) => pyo3::exceptions::PyValueError::new_err(format!(
                "error parsing asn1 value: {:?}",
                asn1_error
            )),
            PyAsn1Error::Py(py_error) => py_error,
        }
    }
}

#[pyo3::prelude::pyfunction]
fn encode_tls_feature(py: pyo3::Python<'_>, ext: &pyo3::PyAny) -> pyo3::PyResult<pyo3::PyObject> {
    // Ideally we'd skip building up a vec and just write directly into the
    // writer. This isn't possible at the moment because the callback to write
    // an asn1::Sequence can't return an error, and we need to handle errors
    // from Python.
    let mut els = vec![];
    for el in ext.iter()? {
        els.push(el?.getattr("value")?.extract::<u64>()?);
    }

    let result = asn1::write(|w| {
        w.write_element_with_type::<asn1::SequenceOf<u64>>(&els);
    });

    Ok(pyo3::types::PyBytes::new(py, &result).to_object(py))
}

#[pyo3::prelude::pyfunction]
fn parse_tls_feature(py: pyo3::Python<'_>, data: &[u8]) -> pyo3::PyResult<pyo3::PyObject> {
    let x509_mod = py.import("cryptography.x509.extensions")?;
    let tls_feature_type_to_enum = x509_mod.getattr("_TLS_FEATURE_TYPE_TO_ENUM")?;

    let features = asn1::parse::<_, PyAsn1Error, _>(data, |p| {
        let features = pyo3::types::PyList::empty(py);
        for el in p.read_element::<asn1::SequenceOf<u64>>()? {
            let feature = el?;
            let py_feature = tls_feature_type_to_enum.get_item(feature.to_object(py))?;
            features.append(py_feature)?;
        }
        Ok(features)
    })?;

    let x509_module = py.import("cryptography.x509")?;
    x509_module
        .call1("TLSFeature", (features,))
        .map(|o| o.to_object(py))
}

#[pyo3::prelude::pyfunction]
fn encode_precert_poison(py: pyo3::Python<'_>, _ext: &pyo3::PyAny) -> pyo3::PyObject {
    let result = asn1::write(|w| {
        w.write_element(());
    });

    pyo3::types::PyBytes::new(py, &result).to_object(py)
}

#[pyo3::prelude::pyfunction]
fn parse_precert_poison(py: pyo3::Python<'_>, data: &[u8]) -> pyo3::PyResult<pyo3::PyObject> {
    asn1::parse::<_, PyAsn1Error, _>(data, |p| {
        p.read_element::<()>()?;
        Ok(())
    })?;

    let x509_module = py.import("cryptography.x509")?;
    x509_module.call0("PrecertPoison").map(|o| o.to_object(py))
}

#[pyo3::prelude::pyfunction]
fn parse_spki_for_data(py: pyo3::Python<'_>, data: &[u8]) -> pyo3::PyResult<pyo3::PyObject> {
    let result = asn1::parse::<_, PyAsn1Error, _>(data, |p| {
        p.read_element::<asn1::Sequence>()?
            .parse::<_, PyAsn1Error, _>(|p| {
                // AlgorithmIdentifier
                p.read_element::<asn1::Sequence>()?
                    .parse::<_, PyAsn1Error, _>(|p| {
                        p.read_element::<asn1::ObjectIdentifier>()?;
                        if !p.is_empty() {
                            p.read_element::<asn1::Tlv>()?;
                        }
                        Ok(())
                    })?;

                let pubkey_data = p.read_element::<asn1::BitString>()?;
                if pubkey_data.padding_bits() != 0 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Invalid public key encoding",
                    )
                    .into());
                }
                Ok(pubkey_data.as_bytes())
            })
    })?;

    Ok(pyo3::types::PyBytes::new(py, result).to_object(py))
}

fn big_asn1_uint_to_py<'p>(
    py: pyo3::Python<'p>,
    v: asn1::BigUint,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let int_type = py.get_type::<pyo3::types::PyLong>();
    int_type.call_method1("from_bytes", (v.as_bytes(), "big"))
}

#[pyo3::prelude::pyfunction]
fn decode_dss_signature(py: pyo3::Python<'_>, data: &[u8]) -> pyo3::PyResult<pyo3::PyObject> {
    let (r, s) = asn1::parse::<_, PyAsn1Error, _>(data, |p| {
        p.read_element::<asn1::Sequence>()?.parse(|p| {
            let r = p.read_element::<asn1::BigUint>()?;
            let s = p.read_element::<asn1::BigUint>()?;
            Ok((r, s))
        })
    })?;

    Ok((big_asn1_uint_to_py(py, r)?, big_asn1_uint_to_py(py, s)?).to_object(py))
}

fn py_uint_to_big_endian_bytes<'p>(
    py: pyo3::Python<'p>,
    v: &'p pyo3::types::PyLong,
) -> pyo3::PyResult<&'p [u8]> {
    let zero = (0).to_object(py);
    if v.rich_compare(zero, CompareOp::Lt)?.is_true()? {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Negative integers are not supported",
        ));
    }

    // Round the length up so that we prefix an extra \x00. This ensures that
    // integers that'd have the high bit set in their first octet are not
    // encoded as negative in DER.
    let n = v.call_method0("bit_length")?.extract::<usize>()? / 8 + 1;
    v.call_method1("to_bytes", (n, "big"))?.extract()
}

#[pyo3::prelude::pyfunction]
fn encode_dss_signature(
    py: pyo3::Python<'_>,
    r: &pyo3::types::PyLong,
    s: &pyo3::types::PyLong,
) -> pyo3::PyResult<pyo3::PyObject> {
    let r = asn1::BigUint::new(py_uint_to_big_endian_bytes(py, r)?).unwrap();
    let s = asn1::BigUint::new(py_uint_to_big_endian_bytes(py, s)?).unwrap();
    let result = asn1::write(|w| {
        w.write_element_with_type::<asn1::Sequence>(&|w| {
            w.write_element(r);
            w.write_element(s);
        });
    });

    Ok(pyo3::types::PyBytes::new(py, &result).to_object(py))
}

#[pyo3::prelude::pyclass]
struct TestCertificate {
    #[pyo3(get)]
    not_before_tag: u8,
    #[pyo3(get)]
    not_after_tag: u8,
    #[pyo3(get)]
    issuer_value_tags: Vec<u8>,
    #[pyo3(get)]
    subject_value_tags: Vec<u8>,
}

fn parse_name_value_tags(p: &mut asn1::Parser) -> asn1::ParseResult<Vec<u8>> {
    let mut tags = vec![];
    for rdn in p.read_element::<asn1::SequenceOf<asn1::SetOf<asn1::Sequence>>>()? {
        let mut attributes = rdn?.collect::<asn1::ParseResult<Vec<_>>>()?;
        assert_eq!(attributes.len(), 1);

        let tag = attributes
            .pop()
            .unwrap()
            .parse::<_, asn1::ParseError, _>(|p| {
                p.read_element::<asn1::ObjectIdentifier>()?;
                let tlv = p.read_element::<asn1::Tlv>()?;
                Ok(tlv.tag())
            })?;
        tags.push(tag);
    }
    Ok(tags)
}

#[pyo3::prelude::pyfunction]
fn test_parse_certificate(data: &[u8]) -> pyo3::PyResult<TestCertificate> {
    let result = asn1::parse::<_, PyAsn1Error, _>(data, |p| {
        // Outer SEQUENCE
        p.read_element::<asn1::Sequence>()?.parse(|p| {
            // TBS certificate
            let result = p
                .read_element::<asn1::Sequence>()?
                .parse::<_, PyAsn1Error, _>(|p| {
                    // Version
                    p.read_optional_explicit_element::<u8>(0)?;
                    // Serial number
                    p.read_element::<asn1::BigUint>()?;
                    // Inner signature algorithm
                    p.read_element::<asn1::Sequence>()?;

                    // Issuer
                    let issuer_value_tags = parse_name_value_tags(p)?;
                    // Validity
                    let (not_before_tag, not_after_tag) = p
                        .read_element::<asn1::Sequence>()?
                        .parse::<_, asn1::ParseError, _>(|p| {
                        let not_before_tag = p.read_element::<asn1::Tlv>()?.tag();
                        let not_after_tag = p.read_element::<asn1::Tlv>()?.tag();
                        Ok((not_before_tag, not_after_tag))
                    })?;
                    // Subject
                    let subject_value_tags = parse_name_value_tags(p)?;

                    // Subject public key info
                    p.read_element::<asn1::Sequence>()?;
                    // Issuer unique ID - never used in the real world
                    p.read_optional_implicit_element::<asn1::BitString>(1)?;
                    // Subject unique ID - never used in the real world
                    p.read_optional_implicit_element::<asn1::BitString>(2)?;
                    // Extensions
                    p.read_optional_explicit_element::<asn1::Sequence>(3)?;

                    Ok(TestCertificate {
                        not_before_tag,
                        not_after_tag,
                        issuer_value_tags,
                        subject_value_tags,
                    })
                })?;
            // Outer signature algorithm
            p.read_element::<asn1::Sequence>()?;
            // Signature
            p.read_element::<asn1::BitString>()?;
            Ok(result)
        })
    })?;

    Ok(result)
}

pub(crate) fn create_submodule(py: pyo3::Python) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "asn1")?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_tls_feature))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_tls_feature))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_precert_poison))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_precert_poison))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_spki_for_data))?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(decode_dss_signature))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_dss_signature))?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(test_parse_certificate))?;

    Ok(submod)
}
