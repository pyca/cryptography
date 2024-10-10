// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;

use cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use cryptography_x509::csr::Attribute;
use cryptography_x509::pkcs7::PKCS7_DATA_OID;
use cryptography_x509::{common, oid, pkcs7};
use once_cell::sync::Lazy;
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use openssl::pkcs7::Pkcs7;
use pyo3::types::{PyAnyMethods, PyBytesMethods, PyListMethods};
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use pyo3::IntoPy;

use crate::asn1::encode_der_data;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::pkcs12::{symmetric_decrypt, symmetric_encrypt};
#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
use crate::x509::certificate::load_der_x509_certificate;
use crate::{backend, exceptions, types, x509};

const PKCS7_CONTENT_TYPE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 3);
const PKCS7_MESSAGE_DIGEST_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 4);
const PKCS7_SIGNING_TIME_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 5);
const PKCS7_SMIME_CAP_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 15);

static OIDS_TO_MIC_NAME: Lazy<HashMap<&asn1::ObjectIdentifier, &str>> = Lazy::new(|| {
    let mut h = HashMap::new();
    h.insert(&oid::SHA224_OID, "sha-224");
    h.insert(&oid::SHA256_OID, "sha-256");
    h.insert(&oid::SHA384_OID, "sha-384");
    h.insert(&oid::SHA512_OID, "sha-512");
    h
});

#[pyo3::pyfunction]
fn serialize_certificates<'p>(
    py: pyo3::Python<'p>,
    py_certs: Vec<pyo3::PyRef<'p, x509::certificate::Certificate>>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if py_certs.is_empty() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "certs must be a list of certs with length >= 1",
        )
        .into());
    }

    let raw_certs = py_certs
        .iter()
        .map(|c| c.raw.borrow_dependent())
        .collect::<Vec<_>>();

    let signed_data = pkcs7::SignedData {
        version: 1,
        digest_algorithms: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&[])),
        content_info: pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: pkcs7::Content::Data(None),
        },
        certificates: Some(common::Asn1ReadableOrWritable::new_write(
            asn1::SetOfWriter::new(&raw_certs),
        )),
        crls: None,
        signer_infos: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(&[])),
    };

    let content_info = pkcs7::ContentInfo {
        _content_type: asn1::DefinedByMarker::marker(),
        content: pkcs7::Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };
    let content_info_bytes = asn1::write_single(&content_info)?;

    encode_der_data(py, "PKCS7".to_string(), content_info_bytes, encoding)
}

#[pyo3::pyfunction]
fn encrypt_and_serialize<'p>(
    py: pyo3::Python<'p>,
    builder: &pyo3::Bound<'p, pyo3::PyAny>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    options: &pyo3::Bound<'p, pyo3::types::PyList>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let raw_data: CffiBuf<'p> = builder.getattr(pyo3::intern!(py, "_data"))?.extract()?;
    let text_mode = options.contains(types::PKCS7_TEXT.get(py)?)?;
    let data_with_header = if options.contains(types::PKCS7_BINARY.get(py)?)? {
        Cow::Borrowed(raw_data.as_bytes())
    } else {
        smime_canonicalize(raw_data.as_bytes(), text_mode).0
    };

    // The message is encrypted with AES-128-CBC, which the S/MIME v3.2 RFC
    // specifies as MUST support (https://datatracker.ietf.org/doc/html/rfc5751#section-2.7)
    let key = types::OS_URANDOM.get(py)?.call1((16,))?;
    let aes128_algorithm = types::AES128.get(py)?.call1((&key,))?;
    let iv = types::OS_URANDOM.get(py)?.call1((16,))?;
    let cbc_mode = types::CBC.get(py)?.call1((&iv,))?;

    let encrypted_content = symmetric_encrypt(py, aes128_algorithm, cbc_mode, &data_with_header)?;

    let py_recipients: Vec<pyo3::Bound<'p, x509::certificate::Certificate>> = builder
        .getattr(pyo3::intern!(py, "_recipients"))?
        .extract()?;

    let mut recipient_infos = vec![];
    let padding = types::PKCS1V15.get(py)?.call0()?;
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    for cert in py_recipients.iter() {
        // Currently, keys are encrypted with RSA (PKCS #1 v1.5), which the S/MIME v3.2 RFC
        // specifies as MUST support (https://datatracker.ietf.org/doc/html/rfc5751#section-2.3)
        let encrypted_key = cert
            .call_method0(pyo3::intern!(py, "public_key"))?
            .call_method1(pyo3::intern!(py, "encrypt"), (&key, &padding))?
            .extract::<pyo3::pybacked::PyBackedBytes>()?;

        recipient_infos.push(pkcs7::RecipientInfo {
            version: 0,
            issuer_and_serial_number: pkcs7::IssuerAndSerialNumber {
                issuer: cert.get().raw.borrow_dependent().tbs_cert.issuer.clone(),
                serial_number: cert.get().raw.borrow_dependent().tbs_cert.serial,
            },
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Rsa(Some(())),
            },
            encrypted_key: ka_bytes.add(encrypted_key),
        });
    }

    let enveloped_data = pkcs7::EnvelopedData {
        version: 0,
        recipient_infos: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
            &recipient_infos,
        )),

        encrypted_content_info: pkcs7::EncryptedContentInfo {
            content_type: PKCS7_DATA_OID,
            content_encryption_algorithm: AlgorithmIdentifier {
                oid: asn1::DefinedByMarker::marker(),
                params: AlgorithmParameters::Aes128Cbc(iv.extract()?),
            },
            encrypted_content: Some(&encrypted_content),
        },
    };

    let content_info = pkcs7::ContentInfo {
        _content_type: asn1::DefinedByMarker::marker(),
        content: pkcs7::Content::EnvelopedData(asn1::Explicit::new(Box::new(enveloped_data))),
    };
    let ci_bytes = asn1::write_single(&content_info)?;

    if encoding.is(&types::ENCODING_SMIME.get(py)?) {
        Ok(types::SMIME_ENVELOPED_ENCODE
            .get(py)?
            .call1((&*ci_bytes,))?
            .extract()?)
    } else {
        // Handles the DER, PEM, and error cases
        encode_der_data(py, "PKCS7".to_string(), ci_bytes, encoding)
    }
}

#[pyo3::pyfunction]
fn deserialize_and_decrypt<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'p>,
    certificate: pyo3::Bound<'p, x509::certificate::Certificate>,
    private_key: pyo3::Bound<'p, backend::rsa::RsaPrivateKey>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    options: &pyo3::Bound<'p, pyo3::types::PyList>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    // Extract the data on the right format (PEM or DER, SMIME handled by Python)
    let extracted_data = if encoding.is(&types::ENCODING_DER.get(py)?) {
        data.as_bytes().to_vec()
    } else {
        let pem_str = std::str::from_utf8(data.as_bytes())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid PEM data"))?;
        let pem = pem::parse(pem_str)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Failed to parse PEM data"))?;
        pem.contents().to_vec()
    };

    // Deserialize the content info
    let content_info = asn1::parse_single::<pkcs7::ContentInfo<'_>>(&extracted_data).unwrap();
    let plain_content = match content_info.content {
        pkcs7::Content::EnvelopedData(data) => {
            // Extract enveloped data
            let enveloped_data = data.into_inner();

            // Get recipients, and the one matching with the given certificate (if any)
            let mut recipient_infos = enveloped_data.recipient_infos.unwrap_read().clone();
            let recipient_serial_number = certificate.get().raw.borrow_dependent().tbs_cert.serial;
            let found_recipient_info = recipient_infos.find(|info| {
                info.issuer_and_serial_number.serial_number.as_bytes()
                    == recipient_serial_number.as_bytes()
            });

            // Raise error when no recipient is found
            // Unsure if this is the right exception to raise
            let recipient_info = match found_recipient_info {
                Some(info) => info,
                None => {
                    return Err(CryptographyError::from(
                        exceptions::AttributeNotFound::new_err((
                            "No recipient found that matches the given certificate.",
                            exceptions::Reasons::UNSUPPORTED_X509,
                        )),
                    ));
                }
            };

            // Decrypt the key using the private key
            let padding = types::PKCS1V15.get(py)?.call0()?;
            let key = private_key
                .call_method1(
                    pyo3::intern!(py, "decrypt"),
                    (recipient_info.encrypted_key, &padding),
                )?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;

            // Get algorithm
            // TODO: implement all the possible algorithms
            let algorithm_identifier = enveloped_data
                .encrypted_content_info
                .content_encryption_algorithm;
            let (algorithm, mode) = match algorithm_identifier.params {
                AlgorithmParameters::Aes128Cbc(iv) => (
                    types::AES128.get(py)?.call1((key,))?,
                    types::CBC
                        .get(py)?
                        .call1((pyo3::types::PyBytes::new_bound(py, &iv),))?,
                ),
                _ => {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "Only AES-128-CBC is currently supported for decryption.",
                            exceptions::Reasons::UNSUPPORTED_SERIALIZATION,
                        )),
                    ));
                }
            };

            // Decrypt the content using the key and proper algorithm
            let encrypted_content = enveloped_data
                .encrypted_content_info
                .encrypted_content
                .unwrap();
            let decrypted_content = symmetric_decrypt(py, algorithm, mode, encrypted_content)?;
            pyo3::types::PyBytes::new_bound(py, decrypted_content.as_slice())
        }
        _ => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Only EnvelopedData structures are currently supported.",
                    exceptions::Reasons::UNSUPPORTED_SERIALIZATION,
                )),
            ));
        }
    };

    // Return content in different form, based on options
    let text_mode = options.contains(types::PKCS7_TEXT.get(py)?)?;
    let plain_data = if options.contains(types::PKCS7_BINARY.get(py)?)? {
        plain_content
    } else {
        let decanonicalized = smime_decanonicalize(plain_content.as_bytes(), text_mode);
        pyo3::types::PyBytes::new_bound(py, decanonicalized.into_owned().as_slice())
    };

    Ok(plain_data)
}

#[pyo3::pyfunction]
fn sign_and_serialize<'p>(
    py: pyo3::Python<'p>,
    builder: &pyo3::Bound<'p, pyo3::PyAny>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    options: &pyo3::Bound<'p, pyo3::types::PyList>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let raw_data: CffiBuf<'p> = builder.getattr(pyo3::intern!(py, "_data"))?.extract()?;
    let text_mode = options.contains(types::PKCS7_TEXT.get(py)?)?;
    let (data_with_header, data_without_header) =
        if options.contains(types::PKCS7_BINARY.get(py)?)? {
            (
                Cow::Borrowed(raw_data.as_bytes()),
                Cow::Borrowed(raw_data.as_bytes()),
            )
        } else {
            smime_canonicalize(raw_data.as_bytes(), text_mode)
        };

    let content_type_bytes = asn1::write_single(&pkcs7::PKCS7_DATA_OID)?;
    let now = x509::common::datetime_now(py)?;
    let signing_time_bytes = asn1::write_single(&x509::certificate::time_from_datetime(now)?)?;
    let smime_cap_bytes = asn1::write_single(&asn1::SequenceOfWriter::new([
        // Subset of values OpenSSL provides:
        // https://github.com/openssl/openssl/blob/667a8501f0b6e5705fd611d5bb3ca24848b07154/crypto/pkcs7/pk7_smime.c#L150
        // removing all the ones that are bad cryptography
        &asn1::SequenceOfWriter::new([oid::AES_256_CBC_OID]),
        &asn1::SequenceOfWriter::new([oid::AES_192_CBC_OID]),
        &asn1::SequenceOfWriter::new([oid::AES_128_CBC_OID]),
    ]))?;

    #[allow(clippy::type_complexity)]
    let py_signers: Vec<(
        pyo3::PyRef<'p, x509::certificate::Certificate>,
        pyo3::Bound<'_, pyo3::PyAny>,
        pyo3::Bound<'_, pyo3::PyAny>,
        pyo3::Bound<'_, pyo3::PyAny>,
    )> = builder.getattr(pyo3::intern!(py, "_signers"))?.extract()?;

    let py_certs: Vec<pyo3::PyRef<'p, x509::certificate::Certificate>> = builder
        .getattr(pyo3::intern!(py, "_additional_certs"))?
        .extract()?;

    let mut signer_infos = vec![];
    let mut digest_algs = vec![];
    let mut certs = py_certs
        .iter()
        .map(|p| p.raw.borrow_dependent())
        .collect::<Vec<_>>();

    let ka_vec = cryptography_keepalive::KeepAlive::new();
    let ka_bytes = cryptography_keepalive::KeepAlive::new();
    for (cert, py_private_key, py_hash_alg, rsa_padding) in py_signers.iter() {
        let (authenticated_attrs, signature) =
            if options.contains(&types::PKCS7_NO_ATTRIBUTES.get(py)?)? {
                (
                    None,
                    x509::sign::sign_data(
                        py,
                        py_private_key.clone(),
                        py_hash_alg.clone(),
                        rsa_padding.clone(),
                        &data_with_header,
                    )?,
                )
            } else {
                let mut authenticated_attrs = vec![
                    Attribute {
                        type_id: PKCS7_CONTENT_TYPE_OID,
                        values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
                            [asn1::parse_single(&content_type_bytes).unwrap()],
                        )),
                    },
                    Attribute {
                        type_id: PKCS7_SIGNING_TIME_OID,
                        values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
                            [asn1::parse_single(&signing_time_bytes).unwrap()],
                        )),
                    },
                ];

                let digest = x509::ocsp::hash_data(py, py_hash_alg, &data_with_header)?;
                let digest_wrapped = ka_vec.add(asn1::write_single(&digest.as_bytes())?);
                authenticated_attrs.push(Attribute {
                    type_id: PKCS7_MESSAGE_DIGEST_OID,
                    values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new([
                        asn1::parse_single(digest_wrapped).unwrap(),
                    ])),
                });

                if !options.contains(types::PKCS7_NO_CAPABILITIES.get(py)?)? {
                    authenticated_attrs.push(Attribute {
                        type_id: PKCS7_SMIME_CAP_OID,
                        values: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
                            [asn1::parse_single(&smime_cap_bytes).unwrap()],
                        )),
                    });
                }

                let signed_data =
                    asn1::write_single(&asn1::SetOfWriter::new(authenticated_attrs.as_slice()))?;

                (
                    Some(common::Asn1ReadableOrWritable::new_write(
                        asn1::SetOfWriter::new(authenticated_attrs),
                    )),
                    x509::sign::sign_data(
                        py,
                        py_private_key.clone(),
                        py_hash_alg.clone(),
                        rsa_padding.clone(),
                        &signed_data,
                    )?,
                )
            };

        let digest_alg = x509::ocsp::HASH_NAME_TO_ALGORITHM_IDENTIFIERS[&*py_hash_alg
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?]
            .clone();
        // Technically O(n^2), but no one will have that many signers.
        if !digest_algs.contains(&digest_alg) {
            digest_algs.push(digest_alg.clone());
        }
        certs.push(cert.raw.borrow_dependent());

        signer_infos.push(pkcs7::SignerInfo {
            version: 1,
            issuer_and_serial_number: pkcs7::IssuerAndSerialNumber {
                issuer: cert.raw.borrow_dependent().tbs_cert.issuer.clone(),
                serial_number: cert.raw.borrow_dependent().tbs_cert.serial,
            },
            digest_algorithm: digest_alg,
            authenticated_attributes: authenticated_attrs,
            digest_encryption_algorithm: compute_pkcs7_signature_algorithm(
                py,
                py_private_key.clone(),
                py_hash_alg.clone(),
                rsa_padding.clone(),
            )?,
            encrypted_digest: ka_bytes.add(signature),
            unauthenticated_attributes: None,
        });
    }

    let data_tlv_bytes;
    let content = if options.contains(types::PKCS7_DETACHED_SIGNATURE.get(py)?)? {
        None
    } else {
        data_tlv_bytes = asn1::write_single(&data_with_header.deref())?;
        Some(asn1::parse_single(&data_tlv_bytes).unwrap())
    };

    let signed_data = pkcs7::SignedData {
        version: 1,
        digest_algorithms: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
            &digest_algs,
        )),
        content_info: pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: pkcs7::Content::Data(content.map(asn1::Explicit::new)),
        },
        certificates: if options.contains(types::PKCS7_NO_CERTS.get(py)?)? {
            None
        } else {
            Some(common::Asn1ReadableOrWritable::new_write(
                asn1::SetOfWriter::new(&certs),
            ))
        },
        crls: None,
        signer_infos: common::Asn1ReadableOrWritable::new_write(asn1::SetOfWriter::new(
            &signer_infos,
        )),
    };

    let content_info = pkcs7::ContentInfo {
        _content_type: asn1::DefinedByMarker::marker(),
        content: pkcs7::Content::SignedData(asn1::Explicit::new(Box::new(signed_data))),
    };
    let ci_bytes = asn1::write_single(&content_info)?;

    if encoding.is(&types::ENCODING_SMIME.get(py)?) {
        let mic_algs = digest_algs
            .iter()
            .map(|d| OIDS_TO_MIC_NAME[&d.oid()])
            .collect::<Vec<_>>()
            .join(",");
        Ok(types::SMIME_SIGNED_ENCODE
            .get(py)?
            .call1((&*data_without_header, &*ci_bytes, mic_algs, text_mode))?
            .extract()?)
    } else {
        // Handles the DER, PEM, and error cases
        encode_der_data(py, "PKCS7".to_string(), ci_bytes, encoding)
    }
}

fn compute_pkcs7_signature_algorithm<'p>(
    py: pyo3::Python<'p>,
    private_key: pyo3::Bound<'p, pyo3::PyAny>,
    hash_algorithm: pyo3::Bound<'p, pyo3::PyAny>,
    rsa_padding: pyo3::Bound<'p, pyo3::PyAny>,
) -> pyo3::PyResult<common::AlgorithmIdentifier<'static>> {
    let key_type = x509::sign::identify_key_type(py, private_key.clone())?;
    let has_pss_padding = rsa_padding.is_instance(&types::PSS.get(py)?)?;
    // For RSA signatures (with no PSS padding), the OID is always the same no matter the
    // digest algorithm. See RFC 3370 (section 3.2).
    if key_type == x509::sign::KeyType::Rsa && !has_pss_padding {
        Ok(common::AlgorithmIdentifier {
            oid: asn1::DefinedByMarker::marker(),
            params: common::AlgorithmParameters::Rsa(Some(())),
        })
    } else {
        x509::sign::compute_signature_algorithm(py, private_key, hash_algorithm, rsa_padding)
    }
}

fn smime_canonicalize(data: &[u8], text_mode: bool) -> (Cow<'_, [u8]>, Cow<'_, [u8]>) {
    let mut new_data_with_header = vec![];
    let mut new_data_without_header = vec![];
    if text_mode {
        new_data_with_header.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    }

    let mut last_idx = 0;
    for (i, c) in data.iter().copied().enumerate() {
        if c == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            new_data_with_header.extend_from_slice(&data[last_idx..i]);
            new_data_with_header.push(b'\r');
            new_data_with_header.push(b'\n');

            new_data_without_header.extend_from_slice(&data[last_idx..i]);
            new_data_without_header.push(b'\r');
            new_data_without_header.push(b'\n');
            last_idx = i + 1;
        }
    }
    // If there's stuff in new_data, that means we need to copy the rest of
    // data over.
    if !new_data_with_header.is_empty() {
        new_data_with_header.extend_from_slice(&data[last_idx..]);
        new_data_without_header.extend_from_slice(&data[last_idx..]);
        (
            Cow::Owned(new_data_with_header),
            Cow::Owned(new_data_without_header),
        )
    } else {
        (Cow::Borrowed(data), Cow::Borrowed(data))
    }
}

fn smime_decanonicalize(data: &[u8], text_mode: bool) -> Cow<'_, [u8]> {
    let mut new_data = vec![];
    let mut last_idx = 0;

    // Remove the header if text_mode is true
    let data = if text_mode {
        let header = b"Content-Type: text/plain\r\n\r\n";
        if data.starts_with(header) {
            &data[header.len()..]
        } else {
            data
        }
    } else {
        data
    };

    // Remove the \r in the data
    for (i, c) in data.iter().copied().enumerate() {
        if c == b'\n' && i > 0 && data[i - 1] == b'\r' {
            new_data.extend_from_slice(&data[last_idx..i - 1]);
            new_data.push(b'\n');
            last_idx = i + 1;
        }
    }

    // Copy the remaining data
    if last_idx < data.len() {
        new_data.extend_from_slice(&data[last_idx..]);
    }

    Cow::Owned(new_data)
}

#[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
fn load_pkcs7_certificates(
    py: pyo3::Python<'_>,
    pkcs7: Pkcs7,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyList>> {
    let nid = pkcs7.type_().map(|t| t.nid());
    if nid != Some(openssl::nid::Nid::PKCS7_SIGNED) {
        let nid_string = nid.map_or("empty".to_string(), |n| n.as_raw().to_string());
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!("Only basic signed structures are currently supported. NID for this data was {}", nid_string),
                exceptions::Reasons::UNSUPPORTED_SERIALIZATION,
            )),
        ));
    }

    let signed_certificates = pkcs7.signed().and_then(|x| x.certificates());
    match signed_certificates {
        None => Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "The provided PKCS7 has no certificate data, but a cert loading method was called.",
            ),
        )),
        Some(certificates) => {
            let result = pyo3::types::PyList::empty_bound(py);
            for c in certificates {
                let cert_der = pyo3::types::PyBytes::new_bound(py, c.to_der()?.as_slice()).unbind();
                let cert = load_der_x509_certificate(py, cert_der, None)?;
                result.append(cert.into_py(py))?;
            }
            Ok(result)
        }
    }
}

#[pyo3::pyfunction]
fn load_pem_pkcs7_certificates<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyList>> {
    cfg_if::cfg_if! {
        if #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))] {
            let pkcs7_decoded = openssl::pkcs7::Pkcs7::from_pem(data).map_err(|_| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Unable to parse PKCS7 data",
                ))
            })?;
            load_pkcs7_certificates(py, pkcs7_decoded)
        } else {
            let _ = py;
            let _ = data;
            Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "PKCS#7 is not supported by this backend.",
                    exceptions::Reasons::UNSUPPORTED_SERIALIZATION,
                )),
            ))
        }
    }
}

#[pyo3::pyfunction]
fn load_der_pkcs7_certificates<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyList>> {
    cfg_if::cfg_if! {
        if #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))] {
            let pkcs7_decoded = openssl::pkcs7::Pkcs7::from_der(data).map_err(|_| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Unable to parse PKCS7 data",
                ))
            })?;
            load_pkcs7_certificates(py, pkcs7_decoded)
        } else {
            let _ = py;
            let _ = data;
            Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "PKCS#7 is not supported by this backend.",
                    exceptions::Reasons::UNSUPPORTED_SERIALIZATION,
                )),
            ))
        }
    }
}

#[pyo3::pymodule]
#[pyo3(name = "pkcs7")]
pub(crate) mod pkcs7_mod {
    #[pymodule_export]
    use super::{
        deserialize_and_decrypt, encrypt_and_serialize, load_der_pkcs7_certificates,
        load_pem_pkcs7_certificates, serialize_certificates, sign_and_serialize,
    };
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::ops::Deref;

    use super::{smime_canonicalize, smime_decanonicalize};

    #[test]
    fn test_smime_canonicalize() {
        for (
            input,
            text_mode,
            expected_with_header,
            expected_without_header,
            expected_is_borrowed,
        ) in [
            // Values with text_mode=false
            (b"" as &[u8], false, b"" as &[u8], b"" as &[u8], true),
            (b"\n", false, b"\r\n", b"\r\n", false),
            (b"abc", false, b"abc", b"abc", true),
            (
                b"abc\r\ndef\n",
                false,
                b"abc\r\ndef\r\n",
                b"abc\r\ndef\r\n",
                false,
            ),
            (b"abc\r\n", false, b"abc\r\n", b"abc\r\n", true),
            (
                b"abc\ndef\n",
                false,
                b"abc\r\ndef\r\n",
                b"abc\r\ndef\r\n",
                false,
            ),
            // Values with text_mode=true
            (b"", true, b"Content-Type: text/plain\r\n\r\n", b"", false),
            (
                b"abc",
                true,
                b"Content-Type: text/plain\r\n\r\nabc",
                b"abc",
                false,
            ),
            (
                b"abc\n",
                true,
                b"Content-Type: text/plain\r\n\r\nabc\r\n",
                b"abc\r\n",
                false,
            ),
        ] {
            let (result_with_header, result_without_header) = smime_canonicalize(input, text_mode);
            assert_eq!(result_with_header.deref(), expected_with_header);
            assert_eq!(result_without_header.deref(), expected_without_header);
            assert_eq!(
                matches!(result_with_header, Cow::Borrowed(_)),
                expected_is_borrowed
            );
            assert_eq!(
                matches!(result_without_header, Cow::Borrowed(_)),
                expected_is_borrowed
            );
        }
    }

    #[test]
    fn test_smime_decanonicalize() {
        for (input, text_mode, expected_output) in [
            // Values with text_mode=false
            (b"" as &[u8], false, b"" as &[u8]),
            (b"abc\r\n", false, b"abc\n"),
            (b"\r\nabc\n", false, b"\nabc\n"),
            (b"abc\r\ndef\r\n", false, b"abc\ndef\n"),
            (b"abc\r\ndef\nabc", false, b"abc\ndef\nabc"),
            // Values with text_mode=true
            (b"abc\r\n", true, b"abc\n"),
            (b"Content-Type: text/plain\r\n\r\n", true, b""),
            (b"Content-Type: text/plain\r\n\r\nabc", true, b"abc"),
            (
                b"Content-Type: text/plain\r\n\r\nabc\r\ndef\nabc",
                true,
                b"abc\ndef\nabc",
            ),
        ] {
            let result = smime_decanonicalize(input, text_mode);
            assert_eq!(result.deref(), expected_output);
        }
    }
}
