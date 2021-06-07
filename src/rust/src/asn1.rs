// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::class::basic::CompareOp;
use pyo3::conversion::ToPyObject;

pub(crate) enum PyAsn1Error {
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

    let result = asn1::write_single(&asn1::SequenceOfWriter::new(&els));
    Ok(pyo3::types::PyBytes::new(py, &result).to_object(py))
}

#[pyo3::prelude::pyfunction]
fn encode_precert_poison(py: pyo3::Python<'_>, _ext: &pyo3::PyAny) -> pyo3::PyObject {
    let result = asn1::write_single(&());
    pyo3::types::PyBytes::new(py, &result).to_object(py)
}

#[derive(asn1::Asn1Read)]
struct AlgorithmIdentifier<'a> {
    _oid: asn1::ObjectIdentifier<'a>,
    _params: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read)]
struct Spki<'a> {
    _algorithm: AlgorithmIdentifier<'a>,
    data: asn1::BitString<'a>,
}

#[pyo3::prelude::pyfunction]
fn parse_spki_for_data(py: pyo3::Python<'_>, data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let spki = asn1::parse_single::<Spki<'_>>(data)?;
    if spki.data.padding_bits() != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Invalid public key encoding").into());
    }

    Ok(pyo3::types::PyBytes::new(py, spki.data.as_bytes()).to_object(py))
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
struct DssSignature<'a> {
    r: asn1::BigUint<'a>,
    s: asn1::BigUint<'a>,
}

pub(crate) fn big_asn1_uint_to_py<'p>(
    py: pyo3::Python<'p>,
    v: asn1::BigUint<'_>,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let int_type = py.get_type::<pyo3::types::PyLong>();
    int_type.call_method1("from_bytes", (v.as_bytes(), "big"))
}

#[pyo3::prelude::pyfunction]
fn decode_dss_signature(py: pyo3::Python<'_>, data: &[u8]) -> Result<pyo3::PyObject, PyAsn1Error> {
    let sig = asn1::parse_single::<DssSignature<'_>>(data)?;

    Ok((
        big_asn1_uint_to_py(py, sig.r)?,
        big_asn1_uint_to_py(py, sig.s)?,
    )
        .to_object(py))
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
    let sig = DssSignature {
        r: asn1::BigUint::new(py_uint_to_big_endian_bytes(py, r)?).unwrap(),
        s: asn1::BigUint::new(py_uint_to_big_endian_bytes(py, s)?).unwrap(),
    };
    let result = asn1::write_single(&sig);
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

#[derive(asn1::Asn1Read)]
struct Asn1Certificate<'a> {
    tbs_cert: TbsCertificate<'a>,
    _signature_alg: asn1::Sequence<'a>,
    _signature: asn1::BitString<'a>,
}

#[derive(asn1::Asn1Read)]
struct TbsCertificate<'a> {
    #[explicit(0)]
    _version: Option<u8>,
    _serial: asn1::BigUint<'a>,
    _signature_alg: asn1::Sequence<'a>,

    issuer: Name<'a>,
    validity: Validity<'a>,
    subject: Name<'a>,

    _spki: asn1::Sequence<'a>,
    #[implicit(1)]
    _issuer_unique_id: Option<asn1::BitString<'a>>,
    #[implicit(2)]
    _subject_unique_id: Option<asn1::BitString<'a>>,
    #[explicit(3)]
    _extensions: Option<asn1::Sequence<'a>>,
}

pub(crate) type Name<'a> = asn1::SequenceOf<'a, asn1::SetOf<'a, AttributeTypeValue<'a>>>;

#[derive(asn1::Asn1Read)]
pub(crate) struct AttributeTypeValue<'a> {
    pub(crate) type_id: asn1::ObjectIdentifier<'a>,
    pub(crate) value: asn1::Tlv<'a>,
}

#[derive(asn1::Asn1Read)]
struct Validity<'a> {
    not_before: asn1::Tlv<'a>,
    not_after: asn1::Tlv<'a>,
}

fn parse_name_value_tags(rdns: &mut Name<'_>) -> Result<Vec<u8>, PyAsn1Error> {
    let mut tags = vec![];
    for rdn in rdns {
        let mut attributes = rdn.collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);

        tags.push(attributes.pop().unwrap().value.tag());
    }
    Ok(tags)
}

#[pyo3::prelude::pyfunction]
fn test_parse_certificate(data: &[u8]) -> Result<TestCertificate, PyAsn1Error> {
    let mut asn1_cert = asn1::parse_single::<Asn1Certificate<'_>>(data)?;

    Ok(TestCertificate {
        not_before_tag: asn1_cert.tbs_cert.validity.not_before.tag(),
        not_after_tag: asn1_cert.tbs_cert.validity.not_after.tag(),
        issuer_value_tags: parse_name_value_tags(&mut asn1_cert.tbs_cert.issuer)?,
        subject_value_tags: parse_name_value_tags(&mut asn1_cert.tbs_cert.subject)?,
    })
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "asn1")?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_tls_feature))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_precert_poison))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(parse_spki_for_data))?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(decode_dss_signature))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(encode_dss_signature))?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(test_parse_certificate))?;

    Ok(submod)
}
