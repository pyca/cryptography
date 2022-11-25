// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{encode_der_data, PyAsn1Result};
use crate::x509;

use chrono::Timelike;
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;

const PKCS7_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 1);
const PKCS7_SIGNED_DATA_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 7, 2);

const PKCS7_CONTENT_TYPE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 3);
const PKCS7_MESSAGE_DIGEST_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 4);
const PKCS7_SIGNING_TIME_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 5);
const PKCS7_SMIME_CAP_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 15);

const AES_256_CBC_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 42);
const AES_192_CBC_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 22);
const AES_128_CBC_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 1, 2);

static EMPTY_STRING_DER: Lazy<Vec<u8>> = Lazy::new(|| {
    // TODO: kind of verbose way to say "\x04\x00".
    asn1::write_single(&(&[] as &[u8])).unwrap()
});
static EMPTY_STRING_TLV: Lazy<asn1::Tlv<'static>> =
    Lazy::new(|| asn1::parse_single(&EMPTY_STRING_DER).unwrap());

static OIDS_TO_MIC_NAME: Lazy<HashMap<&asn1::ObjectIdentifier, &str>> = Lazy::new(|| {
    let mut h = HashMap::new();
    h.insert(&x509::oid::SHA1_OID, "sha1");
    h.insert(&x509::oid::SHA224_OID, "sha-224");
    h.insert(&x509::oid::SHA256_OID, "sha-256");
    h.insert(&x509::oid::SHA384_OID, "sha-384");
    h.insert(&x509::oid::SHA512_OID, "sha-512");
    h
});

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

    signer_infos: asn1::SetOfWriter<'a, SignerInfo<'a>>,
}

#[derive(asn1::Asn1Write)]
struct SignerInfo<'a> {
    version: u8,
    issuer_and_serial_number: IssuerAndSerialNumber<'a>,
    digest_algorithm: x509::AlgorithmIdentifier<'a>,
    #[implicit(0)]
    authenticated_attributes: Option<x509::csr::Attributes<'a>>,

    digest_encryption_algorithm: x509::AlgorithmIdentifier<'a>,
    encrypted_digest: &'a [u8],

    #[implicit(1)]
    unauthenticated_attributes: Option<x509::csr::Attributes<'a>>,
}

#[derive(asn1::Asn1Write)]
struct IssuerAndSerialNumber<'a> {
    issuer: x509::Name<'a>,
    serial_number: asn1::BigInt<'a>,
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

#[pyo3::prelude::pyfunction]
fn sign_and_serialize<'p>(
    py: pyo3::Python<'p>,
    builder: &'p pyo3::PyAny,
    encoding: &'p pyo3::PyAny,
    options: &'p pyo3::types::PyList,
) -> PyAsn1Result<&'p pyo3::types::PyBytes> {
    let pkcs7_options = py
        .import("cryptography.hazmat.primitives.serialization.pkcs7")?
        .getattr(crate::intern!(py, "PKCS7Options"))?;

    let raw_data = builder.getattr(crate::intern!(py, "_data"))?.extract()?;
    let data = if options.contains(pkcs7_options.getattr(crate::intern!(py, "Binary"))?)? {
        Cow::Borrowed(raw_data)
    } else {
        smime_canonicalize(
            raw_data,
            options.contains(pkcs7_options.getattr(crate::intern!(py, "Text"))?)?,
        )
    };

    let content_type_bytes = asn1::write_single(&PKCS7_DATA_OID)?;
    let signing_time_bytes = asn1::write_single(&x509::certificate::time_from_chrono(
        chrono::Utc::now().with_nanosecond(0).unwrap(),
    )?)?;
    let smime_cap_bytes = asn1::write_single(&asn1::SequenceOfWriter::new([
        // Subset of values OpenSSL provides:
        // https://github.com/openssl/openssl/blob/667a8501f0b6e5705fd611d5bb3ca24848b07154/crypto/pkcs7/pk7_smime.c#L150
        // removing all the ones that are bad cryptography
        AES_256_CBC_OID,
        AES_192_CBC_OID,
        AES_128_CBC_OID,
    ]))?;

    let py_signers: Vec<(
        pyo3::PyRef<'p, x509::Certificate>,
        &pyo3::PyAny,
        &pyo3::PyAny,
    )> = builder.getattr(crate::intern!(py, "_signers"))?.extract()?;

    let py_certs: Vec<pyo3::PyRef<'p, x509::Certificate>> = builder
        .getattr(crate::intern!(py, "_additional_certs"))?
        .extract()?;

    let mut signer_infos = vec![];
    let mut digest_algs = vec![];
    let mut certs = py_certs
        .iter()
        .map(|p| p.raw.borrow_value_public())
        .collect::<Vec<_>>();
    for (cert, py_private_key, py_hash_alg) in &py_signers {
        let (authenticated_attrs, signature) = if options
            .contains(pkcs7_options.getattr(crate::intern!(py, "NoAttributes"))?)?
        {
            (
                None,
                x509::sign::sign_data(py, py_private_key, py_hash_alg, &data)?,
            )
        } else {
            let mut authenticated_attrs = vec![];

            authenticated_attrs.push(x509::csr::Attribute {
                type_id: PKCS7_CONTENT_TYPE_OID,
                values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                    asn1::parse_single(&content_type_bytes).unwrap(),
                ])),
            });
            authenticated_attrs.push(x509::csr::Attribute {
                type_id: PKCS7_SIGNING_TIME_OID,
                values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                    asn1::parse_single(&signing_time_bytes).unwrap(),
                ])),
            });

            let digest = asn1::write_single(&x509::ocsp::hash_data(py, py_hash_alg, &data)?)?;
            // Gross hack: copy to PyBytes to extend the lifetime to 'p
            let digest_bytes = pyo3::types::PyBytes::new(py, &digest);
            authenticated_attrs.push(x509::csr::Attribute {
                type_id: PKCS7_MESSAGE_DIGEST_OID,
                values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                    asn1::parse_single(digest_bytes.as_bytes()).unwrap(),
                ])),
            });

            if !options.contains(pkcs7_options.getattr(crate::intern!(py, "NoCapabilities"))?)? {
                authenticated_attrs.push(x509::csr::Attribute {
                    type_id: PKCS7_SMIME_CAP_OID,
                    values: x509::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                        asn1::parse_single(&smime_cap_bytes).unwrap(),
                    ])),
                });
            }

            let signed_data =
                asn1::write_single(&asn1::SetOfWriter::new(authenticated_attrs.as_slice()))?;

            (
                Some(x509::Asn1ReadableOrWritable::new_write(
                    asn1::SetOfWriter::new(authenticated_attrs),
                )),
                x509::sign::sign_data(py, py_private_key, py_hash_alg, &signed_data)?,
            )
        };

        let digest_alg = x509::AlgorithmIdentifier {
            oid: x509::ocsp::HASH_NAME_TO_OIDS[py_hash_alg
                .getattr(crate::intern!(py, "name"))?
                .extract::<&str>()?]
            .clone(),
            params: Some(*x509::sign::NULL_TLV),
        };
        // Technically O(n^2), but no one will have that many signers.
        if !digest_algs.contains(&digest_alg) {
            digest_algs.push(digest_alg.clone());
        }
        certs.push(cert.raw.borrow_value_public());

        signer_infos.push(SignerInfo {
            version: 1,
            issuer_and_serial_number: IssuerAndSerialNumber {
                issuer: cert.raw.borrow_value_public().tbs_cert.issuer.clone(),
                serial_number: cert.raw.borrow_value_public().tbs_cert.serial,
            },
            digest_algorithm: digest_alg,
            authenticated_attributes: authenticated_attrs,
            digest_encryption_algorithm: x509::sign::compute_signature_algorithm(
                py,
                py_private_key,
                py_hash_alg,
            )?,
            encrypted_digest: signature,
            unauthenticated_attributes: None,
        });
    }

    let data_tlv_bytes;
    let content =
        if options.contains(pkcs7_options.getattr(crate::intern!(py, "DetachedSignature"))?)? {
            None
        } else {
            data_tlv_bytes = asn1::write_single(&data.deref())?;
            Some(asn1::parse_single(&data_tlv_bytes).unwrap())
        };

    let signed_data = SignedData {
        version: 1,
        digest_algorithms: asn1::SetOfWriter::new(&digest_algs),
        content_info: ContentInfo {
            content_type: PKCS7_DATA_OID,
            content,
        },
        certificates: if options.contains(pkcs7_options.getattr(crate::intern!(py, "NoCerts"))?)? {
            None
        } else {
            Some(asn1::SetOfWriter::new(&certs))
        },
        crls: None,
        signer_infos: asn1::SetOfWriter::new(&signer_infos),
    };

    let signed_data_bytes = asn1::write_single(&signed_data)?;

    let content_info = ContentInfo {
        content_type: PKCS7_SIGNED_DATA_OID,
        content: Some(asn1::parse_single(&signed_data_bytes).unwrap()),
    };
    let content_info_bytes = asn1::write_single(&content_info)?;

    let encoding_class = py
        .import("cryptography.hazmat.primitives.serialization")?
        .getattr(crate::intern!(py, "Encoding"))?;

    if encoding == encoding_class.getattr(crate::intern!(py, "SMIME"))? {
        let mic_algs = digest_algs
            .iter()
            .map(|d| OIDS_TO_MIC_NAME[&d.oid])
            .collect::<Vec<_>>()
            .join(",");
        Ok(py
            .import("cryptography.hazmat.primitives.serialization.pkcs7")?
            .getattr(crate::intern!(py, "_smime_encode"))?
            .call1((
                pyo3::types::PyBytes::new(py, &data),
                pyo3::types::PyBytes::new(py, &content_info_bytes),
                mic_algs,
            ))?
            .extract()?)
    } else {
        // Handles the DER, PEM, and error cases
        encode_der_data(py, "PKCS7".to_string(), content_info_bytes, encoding)
    }
}

fn smime_canonicalize(data: &[u8], text_mode: bool) -> Cow<'_, [u8]> {
    let mut new_data = vec![];
    if text_mode {
        new_data.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    }

    let mut last_idx = 0;
    for (i, c) in data.iter().copied().enumerate() {
        if c == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            new_data.extend_from_slice(&data[last_idx..i]);
            new_data.push(b'\r');
            new_data.push(b'\n');
            last_idx = i + 1;
        }
    }
    // If there's stuff in new_data, that means we need to copy the rest of
    // data over.
    if !new_data.is_empty() {
        new_data.extend_from_slice(&data[last_idx..]);
        Cow::Owned(new_data)
    } else {
        Cow::Borrowed(data)
    }
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "pkcs7")?;

    submod.add_wrapped(pyo3::wrap_pyfunction!(serialize_certificates))?;
    submod.add_wrapped(pyo3::wrap_pyfunction!(sign_and_serialize))?;

    Ok(submod)
}

#[cfg(test)]
mod tests {
    use super::smime_canonicalize;
    use std::borrow::Cow;
    use std::ops::Deref;

    #[test]
    fn test_smime_canonicalize() {
        for (input, text_mode, expected, expected_is_borrowed) in [
            // Values with text_mode=false
            (b"" as &[u8], false, b"" as &[u8], true),
            (b"\n", false, b"\r\n", false),
            (b"abc", false, b"abc", true),
            (b"abc\r\ndef\n", false, b"abc\r\ndef\r\n", false),
            (b"abc\r\n", false, b"abc\r\n", true),
            (b"abc\ndef\n", false, b"abc\r\ndef\r\n", false),
            // Values with text_mode=true
            (b"", true, b"Content-Type: text/plain\r\n\r\n", false),
            (b"abc", true, b"Content-Type: text/plain\r\n\r\nabc", false),
            (
                b"abc\n",
                true,
                b"Content-Type: text/plain\r\n\r\nabc\r\n",
                false,
            ),
        ] {
            let result = smime_canonicalize(input, text_mode);
            assert_eq!(result.deref(), expected);
            assert_eq!(matches!(result, Cow::Borrowed(_)), expected_is_borrowed);
        }
    }
}
