// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{encode_der_data, PyAsn1Result};
use crate::x509;

use once_cell::sync::Lazy;

const PKCS7_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 1);
const PKCS7_SIGNED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 2);

static EMPTY_STRING_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    // TODO: kind of verbose way to say "\x04\x00".
    asn1::write_single(&(&[] as &[u8])).unwrap()
});
pub(crate) static EMPTY_STRING_TLV: Lazy<asn1::Tlv<'static>> =
    Lazy::new(|| asn1::parse_single(&EMPTY_STRING_DER).unwrap());

#[derive(asn1::Asn1Write)]
struct ContentInfo<'a> {
    content_type: asn1::ObjectIdentifier,
    #[explicit(0)]
    content: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Write)]
struct SignedData<'a> {
    version: u8,
    digest_algorithms: asn1::SetOfWriter<'a, x509::AlgorithmIdentifier<'a>>,
    content_info: ContentInfo<'a>,
    #[implicit(0)]
    certificates: Option<asn1::SetOfWriter<'a, &'a x509::certificate::RawCertificate<'a>>>,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    #[implicit(1)]
    crls: Option<asn1::SetOfWriter<'a, asn1::Sequence<'a>>>,

    // We don't ever supply any of these, so for now, don't fill out the fields.
    signer_infos: asn1::SetOfWriter<'a, asn1::Sequence<'a>>,
}

#[pyo3::prelude::pyfunction]
fn serialize_certificates<'p>(
    py: pyo3::Python<'p>,
    py_certs: Vec<pyo3::PyRef<'p, x509::Certificate>>,
    encoding: &'p pyo3::PyAny,
) -> PyAsn1Result<&'p pyo3::types::PyBytes> {
    if py_certs.is_empty() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "certs must be a list of certs with length >= 1",
        )
        .into());
    }

    let raw_certs = py_certs
        .iter()
        .map(|c| c.raw.borrow_value_public())
        .collect::<Vec<_>>();

    let signed_data = SignedData {
        version: 1,
        digest_algorithms: asn1::SetOfWriter::new(&[]),
        content_info: ContentInfo {
            content_type: PKCS7_DATA_OID,
            content: Some(*EMPTY_STRING_TLV),
        },
        certificates: Some(asn1::SetOfWriter::new(&raw_certs)),
        crls: None,
        signer_infos: asn1::SetOfWriter::new(&[]),
    };

    let signed_data_bytes = asn1::write_single(&signed_data)?;

    let content_info = ContentInfo {
        content_type: PKCS7_SIGNED_DATA_OID,
        content: Some(asn1::parse_single(&signed_data_bytes).unwrap()),
    };
    let content_info_bytes = asn1::write_single(&content_info)?;

    encode_der_data(py, "PKCS7".to_string(), content_info_bytes, encoding)
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "pkcs7")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(serialize_certificates))?;

    Ok(submod)
}
