// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::hashes::Hash;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{error, types};
use pyo3::types::{PyAnyMethods, PyBytesMethods};
use pyo3::ToPyObject;

pub(crate) fn py_int_to_bn(
    py: pyo3::Python<'_>,
    v: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<openssl::bn::BigNum> {
    let n = v
        .call_method0(pyo3::intern!(py, "bit_length"))?
        .extract::<usize>()?
        / 8
        + 1;
    let bytes = v
        .call_method1(pyo3::intern!(py, "to_bytes"), (n, pyo3::intern!(py, "big")))?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;

    Ok(openssl::bn::BigNum::from_slice(&bytes)?)
}

pub(crate) fn bn_to_py_int<'p>(
    py: pyo3::Python<'p>,
    b: &openssl::bn::BigNumRef,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    assert!(!b.is_negative());

    let int_type = py.get_type_bound::<pyo3::types::PyLong>();
    Ok(int_type.call_method1(
        pyo3::intern!(py, "from_bytes"),
        (b.to_vec(), pyo3::intern!(py, "big")),
    )?)
}

pub(crate) fn bn_to_big_endian_bytes(b: &openssl::bn::BigNumRef) -> CryptographyResult<Vec<u8>> {
    Ok(b.to_vec_padded(b.num_bits() / 8 + 1)?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn pkey_private_bytes<'p>(
    py: pyo3::Python<'p>,
    key_obj: &pyo3::Bound<'p, pyo3::PyAny>,
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    format: &pyo3::Bound<'p, pyo3::PyAny>,
    encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    openssh_allowed: bool,
    raw_allowed: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if !encoding.is_instance(&types::ENCODING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "encoding must be an item from the Encoding enum",
            ),
        ));
    }
    if !format.is_instance(&types::PRIVATE_FORMAT.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "format must be an item from the PrivateFormat enum",
            ),
        ));
    }
    if !encryption_algorithm.is_instance(&types::KEY_SERIALIZATION_ENCRYPTION.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Encryption algorithm must be a KeySerializationEncryption instance",
            ),
        ));
    }

    if raw_allowed
        && (encoding.is(&types::ENCODING_RAW.get(py)?)
            || format.is(&types::PRIVATE_FORMAT_RAW.get(py)?))
    {
        if !encoding.is(&types::ENCODING_RAW.get(py)?)
            || !format.is(&types::PRIVATE_FORMAT_RAW.get(py)?)
            || !encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)?
        {
            return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                )));
        }
        let raw_bytes = pkey.raw_private_key()?;
        return Ok(pyo3::types::PyBytes::new_bound(py, &raw_bytes));
    }

    let py_password;
    let password = if encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)? {
        b"" as &[u8]
    } else if encryption_algorithm.is_instance(&types::BEST_AVAILABLE_ENCRYPTION.get(py)?)?
        || (encryption_algorithm.is_instance(&types::ENCRYPTION_BUILDER.get(py)?)?
            && encryption_algorithm
                .getattr(pyo3::intern!(py, "_format"))?
                .is(format))
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

    if format.is(&types::PRIVATE_FORMAT_PKCS8.get(py)?) {
        if encoding.is(&types::ENCODING_PEM.get(py)?) {
            let pem_bytes = if password.is_empty() {
                pkey.private_key_to_pem_pkcs8()?
            } else {
                pkey.private_key_to_pem_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    password,
                )?
            };
            return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
        } else if encoding.is(&types::ENCODING_DER.get(py)?) {
            let der_bytes = if password.is_empty() {
                pkey.private_key_to_pkcs8()?
            } else {
                pkey.private_key_to_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    password,
                )?
            };
            return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
        }
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported encoding for PKCS8"),
        ));
    }

    if format.is(&types::PRIVATE_FORMAT_TRADITIONAL_OPENSSL.get(py)?) {
        if cryptography_openssl::fips::is_enabled() && !password.is_empty() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Encrypted traditional OpenSSL format is not supported in FIPS mode",
                ),
            ));
        }
        if let Ok(rsa) = pkey.rsa() {
            if encoding.is(&types::ENCODING_PEM.get(py)?) {
                let pem_bytes = if password.is_empty() {
                    rsa.private_key_to_pem()?
                } else {
                    rsa.private_key_to_pem_passphrase(
                        openssl::symm::Cipher::aes_256_cbc(),
                        password,
                    )?
                };
                return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
            } else if encoding.is(&types::ENCODING_DER.get(py)?) {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                let der_bytes = rsa.private_key_to_der()?;
                return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
            }
        } else if let Ok(dsa) = pkey.dsa() {
            if encoding.is(&types::ENCODING_PEM.get(py)?) {
                let pem_bytes = if password.is_empty() {
                    dsa.private_key_to_pem()?
                } else {
                    dsa.private_key_to_pem_passphrase(
                        openssl::symm::Cipher::aes_256_cbc(),
                        password,
                    )?
                };
                return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
            } else if encoding.is(&types::ENCODING_DER.get(py)?) {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                let der_bytes = dsa.private_key_to_der()?;
                return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
            }
        } else if let Ok(ec) = pkey.ec_key() {
            if encoding.is(&types::ENCODING_PEM.get(py)?) {
                let pem_bytes = if password.is_empty() {
                    ec.private_key_to_pem()?
                } else {
                    ec.private_key_to_pem_passphrase(
                        openssl::symm::Cipher::aes_256_cbc(),
                        password,
                    )?
                };
                return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
            } else if encoding.is(&types::ENCODING_DER.get(py)?) {
                if !password.is_empty() {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "Encryption is not supported for DER encoded traditional OpenSSL keys",
                        ),
                    ));
                }

                let der_bytes = ec.private_key_to_der()?;
                return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
            }
        }
    }

    // OpenSSH + PEM
    if openssh_allowed && format.is(&types::PRIVATE_FORMAT_OPENSSH.get(py)?) {
        if encoding.is(&types::ENCODING_PEM.get(py)?) {
            return Ok(types::SERIALIZE_SSH_PRIVATE_KEY
                .get(py)?
                .call1((key_obj, password, encryption_algorithm))?
                .extract()?);
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
    pkey: &openssl::pkey::PKey<openssl::pkey::Public>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
    format: &pyo3::Bound<'p, pyo3::PyAny>,
    openssh_allowed: bool,
    raw_allowed: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if !encoding.is_instance(&types::ENCODING.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "encoding must be an item from the Encoding enum",
            ),
        ));
    }
    if !format.is_instance(&types::PUBLIC_FORMAT.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "format must be an item from the PublicFormat enum",
            ),
        ));
    }

    if raw_allowed
        && (encoding.is(&types::ENCODING_RAW.get(py)?)
            || format.is(&types::PUBLIC_FORMAT_RAW.get(py)?))
    {
        if !encoding.is(&types::ENCODING_RAW.get(py)?)
            || !format.is(&types::PUBLIC_FORMAT_RAW.get(py)?)
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw",
                ),
            ));
        }
        let raw_bytes = pkey.raw_public_key()?;
        return Ok(pyo3::types::PyBytes::new_bound(py, &raw_bytes));
    }

    // SubjectPublicKeyInfo + PEM/DER
    if format.is(&types::PUBLIC_FORMAT_SUBJECT_PUBLIC_KEY_INFO.get(py)?) {
        if encoding.is(&types::ENCODING_PEM.get(py)?) {
            let pem_bytes = pkey.public_key_to_pem()?;
            return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
        } else if encoding.is(&types::ENCODING_DER.get(py)?) {
            let der_bytes = pkey.public_key_to_der()?;
            return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
        }
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "SubjectPublicKeyInfo works only with PEM or DER encoding",
            ),
        ));
    }

    if let Ok(ec) = pkey.ec_key() {
        if encoding.is(&types::ENCODING_X962.get(py)?) {
            let point_form = if format.is(&types::PUBLIC_FORMAT_UNCOMPRESSED_POINT.get(py)?) {
                openssl::ec::PointConversionForm::UNCOMPRESSED
            } else if format.is(&types::PUBLIC_FORMAT_COMPRESSED_POINT.get(py)?) {
                openssl::ec::PointConversionForm::COMPRESSED
            } else {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "X962 encoding must be used with CompressedPoint or UncompressedPoint format"
                    )
                ));
            };
            let mut bn_ctx = openssl::bn::BigNumContext::new()?;
            let data = ec
                .public_key()
                .to_bytes(ec.group(), point_form, &mut bn_ctx)?;
            return Ok(pyo3::types::PyBytes::new_bound(py, &data));
        }
    }

    if let Ok(rsa) = pkey.rsa() {
        if format.is(&types::PUBLIC_FORMAT_PKCS1.get(py)?) {
            if encoding.is(&types::ENCODING_PEM.get(py)?) {
                let pem_bytes = rsa.public_key_to_pem_pkcs1()?;
                return Ok(pyo3::types::PyBytes::new_bound(py, &pem_bytes));
            } else if encoding.is(&types::ENCODING_DER.get(py)?) {
                let der_bytes = rsa.public_key_to_der_pkcs1()?;
                return Ok(pyo3::types::PyBytes::new_bound(py, &der_bytes));
            }
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "PKCS1 works only with PEM or DER encoding",
                ),
            ));
        }
    }

    // OpenSSH + OpenSSH
    if openssh_allowed && format.is(&types::PUBLIC_FORMAT_OPENSSH.get(py)?) {
        if encoding.is(&types::ENCODING_OPENSSH.get(py)?) {
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
        h.update_bytes(data)?;
        (algorithm.clone(), BytesOrPyBytes::PyBytes(h.finalize(py)?))
    };

    if data.as_bytes().len() != algorithm.getattr("digest_size")?.extract()? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "The provided data must be the same length as the hash algorithm's digest size.",
            ),
        ));
    }

    Ok((data, algorithm))
}

pub(crate) enum PasswordCallbackStatus {
    Unused,
    Used,
    BufferTooSmall(usize),
}

pub(crate) fn password_callback<'a>(
    status: &'a mut PasswordCallbackStatus,
    password: Option<&'a [u8]>,
) -> impl FnOnce(&mut [u8]) -> Result<usize, openssl::error::ErrorStack> + 'a {
    move |buf| {
        *status = PasswordCallbackStatus::Used;
        match password.as_ref() {
            Some(p) if p.len() <= buf.len() => {
                buf[..p.len()].copy_from_slice(p);
                Ok(p.len())
            }
            Some(_) => {
                *status = PasswordCallbackStatus::BufferTooSmall(buf.len());
                Ok(0)
            }
            None => Ok(0),
        }
    }
}

pub(crate) fn handle_key_load_result<T>(
    py: pyo3::Python<'_>,
    pkey: Result<openssl::pkey::PKey<T>, openssl::error::ErrorStack>,
    status: PasswordCallbackStatus,
    password: Option<&[u8]>,
) -> CryptographyResult<openssl::pkey::PKey<T>> {
    match (pkey, status, password) {
        (Ok(k), PasswordCallbackStatus::Unused, None)
        | (Ok(k), PasswordCallbackStatus::Used, Some(_)) => Ok(k),

        (Ok(_), PasswordCallbackStatus::Unused, Some(_)) => Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Password was given but private key is not encrypted.",
            ),
        )),

        (_, PasswordCallbackStatus::Used, None | Some(b"")) => Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Password was not given but private key is encrypted",
            ),
        )),
        (_, PasswordCallbackStatus::BufferTooSmall(size), _) => Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "Passwords longer than {size} bytes are not supported"
            )),
        )),
        (Err(e), _, _) => {
            let errors = error::list_from_openssl_error(py, e);
            Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err((
                    "Could not deserialize key data. The data may be in an incorrect format, the provided password may be incorrect, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters).",
                    errors.to_object(py),
                ))
            ))
        }
    }
}
