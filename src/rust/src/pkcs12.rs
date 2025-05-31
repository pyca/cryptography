// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use cryptography_x509::common::Utf8StoredBMPString;
use cryptography_x509::oid::EKU_ANY_KEY_USAGE_OID;
use pyo3::types::{PyAnyMethods, PyBytesMethods, PyListMethods};
use pyo3::{IntoPyObject, PyTypeInfo};

use crate::backend::{ciphers, hashes, hmac, kdf, keys};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::padding::PKCS7PaddingContext;
use crate::utils::cstr_from_literal;
use crate::x509::certificate::Certificate;
use crate::{types, x509};

#[pyo3::pyclass(frozen)]
struct PKCS12Certificate {
    #[pyo3(get)]
    certificate: pyo3::Py<Certificate>,
    #[pyo3(get)]
    friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
}

#[pyo3::pymethods]
impl PKCS12Certificate {
    #[new]
    #[pyo3(signature = (cert, friendly_name=None))]
    fn new(
        cert: pyo3::Py<Certificate>,
        friendly_name: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> PKCS12Certificate {
        PKCS12Certificate {
            certificate: cert,
            friendly_name,
        }
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        let friendly_name_eq = match (&self.friendly_name, &other.friendly_name) {
            (Some(a), Some(b)) => a.bind(py).as_bytes() == b.bind(py).as_bytes(),
            (None, None) => true,
            _ => false,
        };
        Ok(friendly_name_eq && self.certificate.bind(py).eq(other.certificate.bind(py))?)
    }

    fn __hash__(&self, py: pyo3::Python<'_>) -> CryptographyResult<u64> {
        let mut hasher = DefaultHasher::new();
        self.certificate.bind(py).hash()?.hash(&mut hasher);
        match &self.friendly_name {
            Some(v) => v.bind(py).hash()?.hash(&mut hasher),
            None => None::<u32>.hash(&mut hasher),
        };
        Ok(hasher.finish())
    }

    fn __repr__(&self, py: pyo3::Python<'_>) -> pyo3::PyResult<String> {
        let py_friendly_name_repr;
        let friendly_name_repr = match &self.friendly_name {
            Some(v) => {
                py_friendly_name_repr = v
                    .bind(py)
                    .repr()?
                    .extract::<pyo3::pybacked::PyBackedStr>()?;
                &*py_friendly_name_repr
            }
            None => "None",
        };
        Ok(format!(
            "<PKCS12Certificate({}, friendly_name={})>",
            self.certificate.bind(py).str()?,
            friendly_name_repr
        ))
    }
}

pub(crate) fn symmetric_encrypt(
    py: pyo3::Python<'_>,
    algorithm: pyo3::Bound<'_, pyo3::PyAny>,
    mode: pyo3::Bound<'_, pyo3::PyAny>,
    data: &[u8],
) -> CryptographyResult<Vec<u8>> {
    let block_size = algorithm
        .getattr(pyo3::intern!(py, "block_size"))?
        .extract()?;

    let mut cipher =
        ciphers::CipherContext::new(py, algorithm, mode, openssl::symm::Mode::Encrypt)?;

    let mut ciphertext = vec![0; data.len() + (block_size / 8 * 2)];
    let n = cipher.update_into(py, data, &mut ciphertext)?;

    let mut padder = PKCS7PaddingContext::new(block_size);
    assert!(padder.update(CffiBuf::from_bytes(py, data))?.is_none());
    let padding = padder.finalize(py)?;

    let pad_n = cipher.update_into(py, padding.as_bytes(), &mut ciphertext[n..])?;
    let final_block = cipher.finalize(py)?;
    assert!(final_block.as_bytes().is_empty());
    ciphertext.truncate(n + pad_n);

    Ok(ciphertext)
}

enum EncryptionAlgorithm {
    PBESHA1And3KeyTripleDESCBC,
    PBESv2SHA256AndAES256CBC,
}

impl EncryptionAlgorithm {
    fn salt_length(&self) -> usize {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => 8,
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => 16,
        }
    }

    fn algorithm_identifier<'a>(
        &self,
        cipher_kdf_iter: u64,
        salt: &'a [u8],
        iv: &'a [u8],
    ) -> cryptography_x509::common::AlgorithmIdentifier<'a> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(cryptography_x509::common::Pkcs12PbeParams{
                        salt,
                        iterations: cipher_kdf_iter,
                    }),
                }
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let kdf_algorithm_identifier = cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbkdf2(
                        cryptography_x509::common::PBKDF2Params {
                            salt,
                            iteration_count: cipher_kdf_iter,
                            key_length: None,
                            prf: Box::new(cryptography_x509::common::AlgorithmIdentifier {
                                oid: asn1::DefinedByMarker::marker(),
                                params:
                                    cryptography_x509::common::AlgorithmParameters::HmacWithSha256(
                                        Some(()),
                                    ),
                            }),
                        },
                    ),
                };
                let encryption_algorithm_identifier =
                    cryptography_x509::common::AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: cryptography_x509::common::AlgorithmParameters::Aes256Cbc(
                            iv[..16].try_into().unwrap(),
                        ),
                    };

                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbes2(
                        cryptography_x509::common::PBES2Params {
                            key_derivation_func: Box::new(kdf_algorithm_identifier),
                            encryption_scheme: Box::new(encryption_algorithm_identifier),
                        },
                    ),
                }
            }
        }
    }

    fn encrypt(
        &self,
        py: pyo3::Python<'_>,
        password: &str,
        cipher_kdf_iter: u64,
        salt: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> CryptographyResult<Vec<u8>> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                let key = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_ENCRYPTION_KEY_ID,
                    cipher_kdf_iter,
                    24,
                    openssl::hash::MessageDigest::sha1(),
                )?;
                let iv = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_IV_ID,
                    cipher_kdf_iter,
                    8,
                    openssl::hash::MessageDigest::sha1(),
                )?;

                let triple_des = types::TRIPLE_DES
                    .get(py)?
                    .call1((pyo3::types::PyBytes::new(py, &key),))?;
                let cbc = types::CBC
                    .get(py)?
                    .call1((pyo3::types::PyBytes::new(py, &iv),))?;

                symmetric_encrypt(py, triple_des, cbc, data)
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let pass_buf = CffiBuf::from_bytes(py, password.as_bytes());
                let sha256 = types::SHA256.get(py)?.call0()?;

                let key = kdf::derive_pbkdf2_hmac(
                    py,
                    pass_buf,
                    &sha256,
                    salt,
                    cipher_kdf_iter.try_into().unwrap(),
                    32,
                )?;

                let aes256 = types::AES256.get(py)?.call1((key,))?;
                let cbc = types::CBC.get(py)?.call1((iv,))?;

                symmetric_encrypt(py, aes256, cbc, data)
            }
        }
    }
}

fn pkcs12_attributes<'a>(
    friendly_name: Option<&'a [u8]>,
    local_key_id: Option<&'a [u8]>,
    is_java_trusted_cert: bool,
) -> CryptographyResult<
    Option<
        asn1::SetOfWriter<
            'a,
            cryptography_x509::pkcs12::Attribute<'a>,
            Vec<cryptography_x509::pkcs12::Attribute<'a>>,
        >,
    >,
> {
    let mut attrs = vec![];
    if let Some(name) = friendly_name {
        let name_str = std::str::from_utf8(name).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("friendly_name must be valid UTF-8")
        })?;

        attrs.push(cryptography_x509::pkcs12::Attribute {
            _attr_id: asn1::DefinedByMarker::marker(),
            attr_values: cryptography_x509::pkcs12::AttributeSet::FriendlyName(
                asn1::SetOfWriter::new([Utf8StoredBMPString::new(name_str)]),
            ),
        });
    }
    if let Some(key_id) = local_key_id {
        attrs.push(cryptography_x509::pkcs12::Attribute {
            _attr_id: asn1::DefinedByMarker::marker(),
            attr_values: cryptography_x509::pkcs12::AttributeSet::LocalKeyId(
                asn1::SetOfWriter::new([key_id]),
            ),
        });
    }
    if is_java_trusted_cert {
        attrs.push(cryptography_x509::pkcs12::Attribute {
            _attr_id: asn1::DefinedByMarker::marker(),
            attr_values: cryptography_x509::pkcs12::AttributeSet::JDKTruststoreUsage(
                asn1::SetOfWriter::new([EKU_ANY_KEY_USAGE_OID]),
            ),
        });
    }

    if attrs.is_empty() {
        Ok(None)
    } else {
        Ok(Some(asn1::SetOfWriter::new(attrs)))
    }
}

fn cert_to_bag<'a>(
    cert: &'a Certificate,
    friendly_name: Option<&'a [u8]>,
    local_key_id: Option<&'a [u8]>,
    is_java_trusted_cert: bool,
) -> CryptographyResult<cryptography_x509::pkcs12::SafeBag<'a>> {
    Ok(cryptography_x509::pkcs12::SafeBag {
        _bag_id: asn1::DefinedByMarker::marker(),
        bag_value: asn1::Explicit::new(cryptography_x509::pkcs12::BagValue::CertBag(Box::new(
            cryptography_x509::pkcs12::CertBag {
                _cert_id: asn1::DefinedByMarker::marker(),
                cert_value: asn1::Explicit::new(cryptography_x509::pkcs12::CertType::X509(
                    asn1::OctetStringEncoded::new(cert.raw.borrow_dependent().clone()),
                )),
            },
        ))),
        attributes: pkcs12_attributes(friendly_name, local_key_id, is_java_trusted_cert)?,
    })
}

struct KeySerializationEncryption<'a> {
    password: pyo3::pybacked::PyBackedBytes,
    mac_algorithm: pyo3::Bound<'a, pyo3::PyAny>,
    mac_kdf_iter: u64,
    cipher_kdf_iter: u64,
    encryption_algorithm: Option<EncryptionAlgorithm>,
}

#[allow(clippy::type_complexity)]
fn decode_encryption_algorithm<'a>(
    py: pyo3::Python<'a>,
    encryption_algorithm: pyo3::Bound<'a, pyo3::PyAny>,
) -> CryptographyResult<KeySerializationEncryption<'a>> {
    let default_hmac_alg = types::SHA256.get(py)?.call0()?;
    let default_hmac_kdf_iter = 2048;
    let default_cipher_kdf_iter = 20000;

    if encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)? {
        Ok(KeySerializationEncryption {
            password: pyo3::types::PyBytes::new(py, b"").extract()?,
            mac_algorithm: default_hmac_alg,
            mac_kdf_iter: default_hmac_kdf_iter,
            cipher_kdf_iter: default_cipher_kdf_iter,
            encryption_algorithm: None,
        })
    } else if encryption_algorithm.is_instance(&types::ENCRYPTION_BUILDER.get(py)?)?
        && encryption_algorithm
            .getattr(pyo3::intern!(py, "_format"))?
            .is(&types::PRIVATE_FORMAT_PKCS12.get(py)?)
    {
        let key_cert_alg =
            encryption_algorithm.getattr(pyo3::intern!(py, "_key_cert_algorithm"))?;
        let cipher = if key_cert_alg.is(&types::PBES_PBESV1SHA1AND3KEYTRIPLEDESCBC.get(py)?) {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC
        } else if key_cert_alg.is(&types::PBES_PBESV2SHA256ANDAES256CBC.get(py)?) {
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC
        } else {
            assert!(key_cert_alg.is_none());
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC
        };

        let hmac_alg = if let Some(v) = encryption_algorithm
            .getattr(pyo3::intern!(py, "_hmac_hash"))?
            .extract()?
        {
            v
        } else {
            default_hmac_alg
        };

        let cipher_kdf_iter = if let Some(v) = encryption_algorithm
            .getattr(pyo3::intern!(py, "_kdf_rounds"))?
            .extract()?
        {
            v
        } else {
            default_cipher_kdf_iter
        };

        Ok(KeySerializationEncryption {
            password: encryption_algorithm
                .getattr(pyo3::intern!(py, "password"))?
                .extract()?,
            mac_algorithm: hmac_alg,
            mac_kdf_iter: default_hmac_kdf_iter,
            cipher_kdf_iter,
            encryption_algorithm: Some(cipher),
        })
    } else if encryption_algorithm.is_instance(&types::BEST_AVAILABLE_ENCRYPTION.get(py)?)? {
        Ok(KeySerializationEncryption {
            password: encryption_algorithm
                .getattr(pyo3::intern!(py, "password"))?
                .extract()?,
            mac_algorithm: default_hmac_alg,
            mac_kdf_iter: default_hmac_kdf_iter,
            cipher_kdf_iter: default_cipher_kdf_iter,
            encryption_algorithm: Some(EncryptionAlgorithm::PBESv2SHA256AndAES256CBC),
        })
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported key encryption type"),
        ))
    }
}

#[derive(pyo3::FromPyObject)]
enum CertificateOrPKCS12Certificate {
    Certificate(pyo3::Py<Certificate>),
    PKCS12Certificate(pyo3::Py<PKCS12Certificate>),
}

fn serialize_safebags<'p>(
    py: pyo3::Python<'p>,
    safebags: &[cryptography_x509::pkcs12::SafeBag<'_>],
    encryption_details: &KeySerializationEncryption<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let password = std::str::from_utf8(&encryption_details.password)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("password must be valid UTF-8"))?;
    let mut auth_safe_contents = vec![];
    let (
        plain_safebag_contents,
        shrouded_safebag_contents,
        auth_safe_salt,
        auth_safe_iv,
        auth_safe_ciphertext,
    );

    if let Some(e) = &encryption_details.encryption_algorithm {
        // When encryption is applied, safebags that have already been encrypted (ShroudedKeyBag)
        // should not be encrypted again, so they are placed in their own ContentInfo.
        // See RFC 7292 4.1
        let mut shrouded_safebags = vec![];
        let mut plain_safebags = vec![];
        for safebag in safebags {
            match safebag.bag_value.as_inner() {
                cryptography_x509::pkcs12::BagValue::ShroudedKeyBag(_) => {
                    shrouded_safebags.push(safebag)
                }
                _ => plain_safebags.push(safebag),
            }
        }
        if !plain_safebags.is_empty() {
            plain_safebag_contents =
                asn1::write_single(&asn1::SequenceOfWriter::new(plain_safebags))?;
            auth_safe_salt = crate::backend::rand::get_rand_bytes(py, e.salt_length())?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            auth_safe_iv = crate::backend::rand::get_rand_bytes(py, 16)?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            auth_safe_ciphertext = e.encrypt(
                py,
                password,
                encryption_details.cipher_kdf_iter,
                &auth_safe_salt,
                &auth_safe_iv,
                &plain_safebag_contents,
            )?;

            auth_safe_contents.push(cryptography_x509::pkcs7::ContentInfo {
                _content_type: asn1::DefinedByMarker::marker(),
                content: cryptography_x509::pkcs7::Content::EncryptedData(asn1::Explicit::new(
                    cryptography_x509::pkcs7::EncryptedData {
                        version: 0,
                        encrypted_content_info: cryptography_x509::pkcs7::EncryptedContentInfo {
                            content_type: cryptography_x509::pkcs7::PKCS7_DATA_OID,
                            content_encryption_algorithm: e.algorithm_identifier(
                                encryption_details.cipher_kdf_iter,
                                &auth_safe_salt,
                                &auth_safe_iv,
                            ),
                            encrypted_content: Some(&auth_safe_ciphertext),
                        },
                    },
                )),
            });
        }
        if !shrouded_safebags.is_empty() {
            shrouded_safebag_contents =
                asn1::write_single(&asn1::SequenceOfWriter::new(shrouded_safebags))?;
            auth_safe_contents.push(cryptography_x509::pkcs7::ContentInfo {
                _content_type: asn1::DefinedByMarker::marker(),
                content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                    &shrouded_safebag_contents,
                ))),
            });
        }
    } else {
        plain_safebag_contents = asn1::write_single(&asn1::SequenceOfWriter::new(safebags))?;
        auth_safe_contents.push(cryptography_x509::pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                &plain_safebag_contents,
            ))),
        });
    }

    let auth_safe_content = asn1::write_single(&asn1::SequenceOfWriter::new(auth_safe_contents))?;

    let salt =
        crate::backend::rand::get_rand_bytes(py, 8)?.extract::<pyo3::pybacked::PyBackedBytes>()?;
    let mac_algorithm_md =
        hashes::message_digest_from_algorithm(py, &encryption_details.mac_algorithm)?;
    let mac_key = cryptography_crypto::pkcs12::kdf(
        password,
        &salt,
        cryptography_crypto::pkcs12::KDF_MAC_KEY_ID,
        encryption_details.mac_kdf_iter,
        mac_algorithm_md.size(),
        mac_algorithm_md,
    )?;
    let mac_digest = {
        let mut h = hmac::Hmac::new_bytes(py, &mac_key, &encryption_details.mac_algorithm)?;
        h.update_bytes(&auth_safe_content)?;
        h.finalize(py)?
    };
    let mac_algorithm_identifier = crate::x509::ocsp::HASH_NAME_TO_ALGORITHM_IDENTIFIERS
        [&*encryption_details
            .mac_algorithm
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<pyo3::pybacked::PyBackedStr>()?]
        .clone();

    let p12 = cryptography_x509::pkcs12::Pfx {
        version: 3,
        auth_safe: cryptography_x509::pkcs7::ContentInfo {
            _content_type: asn1::DefinedByMarker::marker(),
            content: cryptography_x509::pkcs7::Content::Data(Some(asn1::Explicit::new(
                &auth_safe_content,
            ))),
        },
        mac_data: Some(cryptography_x509::pkcs12::MacData {
            mac: cryptography_x509::pkcs7::DigestInfo {
                algorithm: mac_algorithm_identifier,
                digest: mac_digest.as_bytes(),
            },
            salt: &salt,
            iterations: encryption_details.mac_kdf_iter,
        }),
    };
    Ok(pyo3::types::PyBytes::new(py, &asn1::write_single(&p12)?))
}

#[pyo3::pyfunction]
#[pyo3(signature = (pkcs12_certs, encryption_algorithm))]
fn serialize_java_truststore<'p>(
    py: pyo3::Python<'p>,
    pkcs12_certs: Vec<pyo3::Py<PKCS12Certificate>>,
    encryption_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let encryption_details = decode_encryption_algorithm(py, encryption_algorithm)?;
    let mut safebags = vec![];

    for cert in &pkcs12_certs {
        safebags.push(cert_to_bag(
            cert.get().certificate.get(),
            cert.get().friendly_name.as_ref().map(|v| v.as_bytes(py)),
            None,
            true,
        )?);
    }

    serialize_safebags(py, &safebags, &encryption_details)
}

#[pyo3::pyfunction]
#[pyo3(signature = (name, key, cert, cas, encryption_algorithm))]
fn serialize_key_and_certificates<'p>(
    py: pyo3::Python<'p>,
    name: Option<&[u8]>,
    key: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    cert: Option<&Certificate>,
    cas: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    encryption_algorithm: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let encryption_details = decode_encryption_algorithm(py, encryption_algorithm)?;
    let password = std::str::from_utf8(&encryption_details.password)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("password must be valid UTF-8"))?;

    let mut safebags = vec![];
    let (key_salt, key_iv, key_ciphertext, pkcs8_bytes);
    let mut ca_certs = vec![];
    let mut key_id = None;
    if cert.is_some() || cas.is_some() {
        if let Some(cert) = cert {
            if let Some(ref key) = key {
                if !cert
                    .public_key(py)?
                    .eq(key.call_method0(pyo3::intern!(py, "public_key"))?)?
                {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Certificate public key and provided private key do not match",
                        ),
                    ));
                }
                key_id = Some(cert.fingerprint(py, &types::SHA1.get(py)?.call0()?)?);
            }

            safebags.push(cert_to_bag(
                cert,
                name,
                key_id.as_ref().map(|v| v.as_bytes()),
                false,
            )?);
        }

        if let Some(cas) = cas {
            for cert in cas.try_iter()? {
                ca_certs.push(cert?.extract::<CertificateOrPKCS12Certificate>()?);
            }

            for cert in &ca_certs {
                let bag = match cert {
                    CertificateOrPKCS12Certificate::Certificate(c) => {
                        cert_to_bag(c.get(), None, None, false)?
                    }
                    CertificateOrPKCS12Certificate::PKCS12Certificate(c) => cert_to_bag(
                        c.get().certificate.get(),
                        c.get().friendly_name.as_ref().map(|v| v.as_bytes(py)),
                        None,
                        false,
                    )?,
                };
                safebags.push(bag);
            }
        }
    }

    if let Some(key) = key {
        let der = types::ENCODING_DER.get(py)?;
        let pkcs8 = types::PRIVATE_FORMAT_PKCS8.get(py)?;
        let no_encryption = types::NO_ENCRYPTION.get(py)?.call0()?;

        pkcs8_bytes = key
            .call_method1(
                pyo3::intern!(py, "private_bytes"),
                (der, pkcs8, no_encryption),
            )?
            .extract::<pyo3::pybacked::PyBackedBytes>()?;

        let key_bag = if let Some(ref e) = encryption_details.encryption_algorithm {
            key_salt = crate::backend::rand::get_rand_bytes(py, e.salt_length())?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            key_iv = crate::backend::rand::get_rand_bytes(py, 16)?
                .extract::<pyo3::pybacked::PyBackedBytes>()?;
            key_ciphertext = e.encrypt(
                py,
                password,
                encryption_details.cipher_kdf_iter,
                &key_salt,
                &key_iv,
                &pkcs8_bytes,
            )?;

            cryptography_x509::pkcs12::SafeBag {
                _bag_id: asn1::DefinedByMarker::marker(),
                bag_value: asn1::Explicit::new(
                    cryptography_x509::pkcs12::BagValue::ShroudedKeyBag(
                        cryptography_x509::pkcs8::EncryptedPrivateKeyInfo {
                            encryption_algorithm: e.algorithm_identifier(
                                encryption_details.cipher_kdf_iter,
                                &key_salt,
                                &key_iv,
                            ),
                            encrypted_data: &key_ciphertext,
                        },
                    ),
                ),
                attributes: pkcs12_attributes(name, key_id.as_ref().map(|v| v.as_bytes()), false)?,
            }
        } else {
            let pkcs8_tlv = asn1::parse_single(&pkcs8_bytes)?;

            cryptography_x509::pkcs12::SafeBag {
                _bag_id: asn1::DefinedByMarker::marker(),
                bag_value: asn1::Explicit::new(cryptography_x509::pkcs12::BagValue::KeyBag(
                    pkcs8_tlv,
                )),
                attributes: pkcs12_attributes(name, key_id.as_ref().map(|v| v.as_bytes()), false)?,
            }
        };

        safebags.push(key_bag);
    }

    serialize_safebags(py, &safebags, &encryption_details)
}

fn decode_p12(
    py: pyo3::Python<'_>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
) -> CryptographyResult<openssl::pkcs12::ParsedPkcs12_2> {
    let p12 = openssl::pkcs12::Pkcs12::from_der(data.as_bytes()).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("Could not deserialize PKCS12 data")
    })?;

    let password = if let Some(p) = password.as_ref() {
        std::str::from_utf8(p.as_bytes())
            .map_err(|_| pyo3::exceptions::PyUnicodeDecodeError::new_err(()))?
    } else {
        // Treat `password=None` the same as empty string. They're actually
        // not the same in PKCS#12, but OpenSSL transparently handles them the
        // same.
        ""
    };
    let parsed = p12
        .parse2(password)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid password or PKCS12 data"))?;

    if asn1::parse_single::<cryptography_x509::pkcs12::Pfx<'_>>(data.as_bytes()).is_err() {
        let warning_cls = pyo3::exceptions::PyUserWarning::type_object(py);
        let message = cstr_from_literal!("PKCS#12 bundle could not be parsed as DER, falling back to parsing as BER. Please file an issue at https://github.com/pyca/cryptography/issues explaining how your PKCS#12 bundle was created. In the future, this may become an exception.");
        pyo3::PyErr::warn(py, &warning_cls, message, 1)?;
    }

    Ok(parsed)
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, password, backend=None))]
fn load_key_and_certificates<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<(
    pyo3::Bound<'p, pyo3::PyAny>,
    Option<x509::certificate::Certificate>,
    pyo3::Bound<'p, pyo3::types::PyList>,
)> {
    let _ = backend;

    let p12 = decode_p12(py, data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        let pkey_bytes = pkey.private_key_to_pkcs8()?;
        keys::load_der_private_key_bytes(py, &pkey_bytes, None, false)?
    } else {
        py.None().into_bound(py)
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).unbind();
        Some(x509::certificate::load_der_x509_certificate(
            py, cert_der, None,
        )?)
    } else {
        None
    };
    let additional_certs = pyo3::types::PyList::empty(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).unbind();
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            additional_certs.append(cert)?;
        }
    }

    Ok((private_key, cert, additional_certs))
}

#[pyo3::pyfunction]
#[pyo3(signature = (data, password, backend=None))]
fn load_pkcs12<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
    password: Option<CffiBuf<'_>>,
    backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let _ = backend;

    let p12 = decode_p12(py, data, password)?;

    let private_key = if let Some(pkey) = p12.pkey {
        let pkey_bytes = pkey.private_key_to_pkcs8()?;
        keys::load_der_private_key_bytes(py, &pkey_bytes, None, false)?
    } else {
        py.None().into_bound(py)
    };
    let cert = if let Some(ossl_cert) = p12.cert {
        let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).unbind();
        let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
        let alias = ossl_cert
            .alias()
            .map(|a| pyo3::types::PyBytes::new(py, a).unbind());

        PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias)
            .into_pyobject(py)?
            .into_any()
            .unbind()
    } else {
        py.None()
    };
    let additional_certs = pyo3::types::PyList::empty(py);
    if let Some(ossl_certs) = p12.ca {
        cfg_if::cfg_if! {
            if #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_300_OR_GREATER, CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC
            ))] {
                let it = ossl_certs.iter();
            } else {
                let it = ossl_certs.iter().rev();
            }
        };

        for ossl_cert in it {
            let cert_der = pyo3::types::PyBytes::new(py, &ossl_cert.to_der()?).unbind();
            let cert = x509::certificate::load_der_x509_certificate(py, cert_der, None)?;
            let alias = ossl_cert
                .alias()
                .map(|a| pyo3::types::PyBytes::new(py, a).unbind());

            let p12_cert = PKCS12Certificate::new(pyo3::Py::new(py, cert)?, alias);
            additional_certs.append(p12_cert)?;
        }
    }

    Ok(types::PKCS12KEYANDCERTIFICATES
        .get(py)?
        .call1((private_key, cert, additional_certs))?)
}

#[pyo3::pymodule]
pub(crate) mod pkcs12 {
    #[pymodule_export]
    use super::{
        load_key_and_certificates, load_pkcs12, serialize_java_truststore,
        serialize_key_and_certificates, PKCS12Certificate,
    };
}
