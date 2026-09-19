// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::hashes::Hash;
use crate::error::{CryptographyError, CryptographyResult};
use crate::serialization::{Encoding, PrivateFormat, PublicFormat};
use crate::types;

#[allow(clippy::too_many_arguments)]
pub(crate) fn pkey_private_bytes<'p>(
    py: pyo3::Python<'p>,
    key_obj: &pyo3::Bound<'p, pyo3::PyAny>,
    pkey: &cryptography_key_parsing::PrivateKeyRef<'_>,
    encoding: Encoding,
    format: PrivateFormat,
    encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    openssh_allowed: bool,
    raw_allowed: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if !encryption_algorithm.is_instance(&types::KEY_SERIALIZATION_ENCRYPTION.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Encryption algorithm must be a KeySerializationEncryption instance",
            ),
        ));
    }

    if raw_allowed && (encoding == Encoding::Raw || format == PrivateFormat::Raw) {
        if encoding != Encoding::Raw
            || format != PrivateFormat::Raw
            || !encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)?
        {
            return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                )));
        }
        let raw_bytes = pkey.raw_bytes()?;
        return Ok(pyo3::types::PyBytes::new(py, raw_bytes.as_ref()));
    }

    let py_password;
    let password = if encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)? {
        b"" as &[u8]
    } else if encryption_algorithm.is_instance(&types::BEST_AVAILABLE_ENCRYPTION.get(py)?)?
        || (encryption_algorithm.is_instance(&types::ENCRYPTION_BUILDER.get(py)?)?
            && encryption_algorithm
                .getattr(pyo3::intern!(py, "_format"))?
                .extract::<PrivateFormat>()?
                == format)
    {
        py_password = encryption_algorithm
            .getattr(pyo3::intern!(py, "password"))?
            .extract::<pyo3::pybacked::PyBackedBytes>()?;
        &py_password
    } else {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported encryption type"),
        ));
    };

    if password.len() > 1023 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Passwords longer than 1023 bytes are not supported by this backend",
            ),
        ));
    }

    if format == PrivateFormat::PKCS8 {
        let parsed = *pkey;
        let (tag, der_bytes) = if password.is_empty() {
            (
                "PRIVATE KEY",
                cryptography_key_parsing::pkcs8::serialize_private_key(parsed)?,
            )
        } else {
            (
                "ENCRYPTED PRIVATE KEY",
                cryptography_key_parsing::pkcs8::serialize_encrypted_private_key(parsed, password)?,
            )
        };

        return crate::asn1::encode_der_data(py, tag.to_string(), der_bytes, encoding);
    }

    if format == PrivateFormat::TraditionalOpenSSL {
        if openssl_bridge::runtime::is_fips_enabled() && !password.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Encrypted traditional OpenSSL format is not supported in FIPS mode",
                ),
            ));
        }
        if let cryptography_key_parsing::PrivateKeyRef::Rsa(rsa) = pkey {
            let der_bytes = cryptography_key_parsing::rsa::serialize_pkcs1_private_key(*rsa)?;
            if encoding == Encoding::PEM {
                let pem_bytes = cryptography_key_parsing::pem::encrypt_pem(
                    "RSA PRIVATE KEY",
                    &der_bytes,
                    password,
                )?;
                return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
            } else if encoding == Encoding::DER {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
            }
        } else if let cryptography_key_parsing::PrivateKeyRef::Dsa(dsa) = pkey {
            let der_bytes = cryptography_key_parsing::dsa::serialize_pkcs1_private_key(dsa)?;
            if encoding == Encoding::PEM {
                let pem_bytes = cryptography_key_parsing::pem::encrypt_pem(
                    "DSA PRIVATE KEY",
                    &der_bytes,
                    password,
                )?;
                return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
            } else if encoding == Encoding::DER {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
            }
        } else if let cryptography_key_parsing::PrivateKeyRef::Ec(ec) = pkey {
            let der_bytes = cryptography_key_parsing::ec::serialize_pkcs1_private_key(ec, true)?;
            if encoding == Encoding::PEM {
                let pem_bytes = cryptography_key_parsing::pem::encrypt_pem(
                    "EC PRIVATE KEY",
                    &der_bytes,
                    password,
                )?;
                return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
            } else if encoding == Encoding::DER {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
            }
        }
    }

    // OpenSSH + PEM
    if openssh_allowed && format == PrivateFormat::OpenSSH {
        if encoding == Encoding::PEM {
            let raw_bytes = types::SERIALIZE_SSH_PRIVATE_KEY
                .get(py)?
                .call1((key_obj, password, encryption_algorithm))?
                .extract()?;
            return crate::asn1::encode_der_data(
                py,
                "OPENSSH PRIVATE KEY".to_string(),
                raw_bytes,
                encoding,
            );
        }

        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "OpenSSH private key format can only be used with PEM encoding",
            ),
        ));
    }

    Err(CryptographyError::from(
        pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
    ))
}

pub(crate) fn pkey_public_bytes<'p>(
    py: pyo3::Python<'p>,
    key_obj: &pyo3::Bound<'p, pyo3::PyAny>,
    pkey: &cryptography_key_parsing::PublicKeyRef<'_>,
    encoding: Encoding,
    format: PublicFormat,
    openssh_allowed: bool,
    raw_allowed: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if raw_allowed && (encoding == Encoding::Raw || format == PublicFormat::Raw) {
        if encoding != Encoding::Raw || format != PublicFormat::Raw {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw",
                ),
            ));
        }
        let raw_bytes = pkey.raw_bytes()?;
        return Ok(pyo3::types::PyBytes::new(py, raw_bytes.as_ref()));
    }

    // SubjectPublicKeyInfo + PEM/DER
    if format == PublicFormat::SubjectPublicKeyInfo {
        let der_bytes = cryptography_key_parsing::spki::serialize_public_key(*pkey)?;

        return crate::asn1::encode_der_data(py, "PUBLIC KEY".to_string(), der_bytes, encoding);
    }

    if let cryptography_key_parsing::PublicKeyRef::Ec(ec) = pkey {
        if encoding == Encoding::X962 {
            let point_form = match format {
                PublicFormat::UncompressedPoint => openssl_bridge::ec::PointEncoding::Uncompressed,
                PublicFormat::CompressedPoint => openssl_bridge::ec::PointEncoding::Compressed,
                _ => {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "X962 encoding must be used with CompressedPoint or UncompressedPoint format"
                        )
                    ));
                }
            };
            let data = ec.to_encoded(point_form)?;
            return Ok(pyo3::types::PyBytes::new(py, &data));
        }
    }

    if let cryptography_key_parsing::PublicKeyRef::Rsa(rsa) = pkey {
        if format == PublicFormat::PKCS1 {
            let der_bytes = cryptography_key_parsing::rsa::serialize_pkcs1_public_key(rsa)?;

            return crate::asn1::encode_der_data(
                py,
                "RSA PUBLIC KEY".to_string(),
                der_bytes,
                encoding,
            );
        }
    }

    // OpenSSH + OpenSSH
    if openssh_allowed && format == PublicFormat::OpenSSH {
        if encoding == Encoding::OpenSSH {
            return Ok(types::SERIALIZE_SSH_PUBLIC_KEY
                .get(py)?
                .call1((key_obj,))?
                .extract()?);
        }

        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "OpenSSH format must be used with OpenSSH encoding",
            ),
        ));
    }

    Err(CryptographyError::from(
        pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
    ))
}

pub(crate) enum BytesOrPyBytes<'a> {
    Bytes(&'a [u8]),
    PyBytes(pyo3::Bound<'a, pyo3::types::PyBytes>),
}

impl BytesOrPyBytes<'_> {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            BytesOrPyBytes::Bytes(v) => v,
            BytesOrPyBytes::PyBytes(v) => v.as_bytes(),
        }
    }
}

pub(crate) fn calculate_digest_and_algorithm<'p>(
    py: pyo3::Python<'p>,
    data: &'p [u8],
    algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<(BytesOrPyBytes<'p>, pyo3::Bound<'p, pyo3::PyAny>)> {
    let (algorithm, data) = if algorithm.is_instance(&types::PREHASHED.get(py)?)? {
        (
            algorithm.getattr("_algorithm")?,
            BytesOrPyBytes::Bytes(data),
        )
    } else {
        // Potential optimization: rather than allocate a PyBytes in
        // `h.finalize()`, have a way to get the `DigestBytes` directly.
        let mut h = Hash::new(py, algorithm, None)?;
        h.update_bytes(py, data)?;
        (algorithm.clone(), BytesOrPyBytes::PyBytes(h.finalize(py)?))
    };

    if data.as_bytes().len() != (algorithm.getattr("digest_size")?.extract::<usize>()?) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "The provided data must be the same length as the hash algorithm's digest size.",
            ),
        ));
    }

    Ok((data, algorithm))
}

pub(crate) fn py_int_to_bytes(
    py: pyo3::Python<'_>,
    value: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<openssl_bridge::secret::SecretBytes> {
    let size = value
        .call_method0(pyo3::intern!(py, "bit_length"))?
        .extract::<usize>()?
        .div_ceil(8);
    let bytes = value
        .call_method1(
            pyo3::intern!(py, "to_bytes"),
            (size, pyo3::intern!(py, "big")),
        )?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;
    Ok(bytes.to_vec().into())
}

pub(crate) fn bytes_to_py_int<'p>(
    py: pyo3::Python<'p>,
    bytes: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    Ok(py.get_type::<pyo3::types::PyInt>().call_method1(
        pyo3::intern!(py, "from_bytes"),
        (
            pyo3::types::PyBytes::new(py, bytes),
            pyo3::intern!(py, "big"),
        ),
    )?)
}
