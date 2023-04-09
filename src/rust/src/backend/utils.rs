// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};

pub(crate) fn pkey_private_bytes<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    encoding: &pyo3::PyAny,
    format: &pyo3::PyAny,
    encryption_algorithm: &pyo3::PyAny,
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    let serialization_mod = py.import("cryptography.hazmat.primitives.serialization")?;
    let encoding_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "Encoding"))?
        .extract()?;
    let private_format_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "PrivateFormat"))?
        .extract()?;
    let no_encryption_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "NoEncryption"))?
        .extract()?;
    let best_available_encryption_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "BestAvailableEncryption"))?
        .extract()?;

    if !encoding.is_instance(encoding_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "encoding must be an item from the Encoding enum",
            ),
        ));
    }
    if !format.is_instance(private_format_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "format must be an item from the PrivateFormat enum",
            ),
        ));
    }

    if encoding.is(encoding_class.getattr(pyo3::intern!(py, "Raw"))?)
        || format.is(private_format_class.getattr(pyo3::intern!(py, "Raw"))?)
    {
        if !encoding.is(encoding_class.getattr(pyo3::intern!(py, "Raw"))?)
            || !format.is(private_format_class.getattr(pyo3::intern!(py, "Raw"))?)
            || !encryption_algorithm.is_instance(no_encryption_class)?
        {
            return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                )));
        }
        let raw_bytes = pkey.raw_private_key()?;
        return Ok(pyo3::types::PyBytes::new(py, &raw_bytes));
    }

    let password = if encryption_algorithm.is_instance(no_encryption_class)? {
        b""
    } else if encryption_algorithm.is_instance(best_available_encryption_class)? {
        encryption_algorithm
            .getattr(pyo3::intern!(py, "password"))?
            .extract::<&[u8]>()?
    } else {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "Encryption algorithm must be a KeySerializationEncryption instance",
            ),
        ));
    };

    if password.len() > 1023 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "Passwords longer than 1023 bytes are not supported by this backend",
            ),
        ));
    }

    if format.is(private_format_class.getattr(pyo3::intern!(py, "PKCS8"))?) {
        if encoding.is(encoding_class.getattr(pyo3::intern!(py, "PEM"))?) {
            let pem_bytes = if password.is_empty() {
                pkey.private_key_to_pem_pkcs8()?
            } else {
                pkey.private_key_to_pem_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    password,
                )?
            };
            return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
        } else if encoding.is(encoding_class.getattr(pyo3::intern!(py, "DER"))?) {
            let der_bytes = if password.is_empty() {
                pkey.private_key_to_pkcs8()?
            } else {
                pkey.private_key_to_pkcs8_passphrase(
                    openssl::symm::Cipher::aes_256_cbc(),
                    password,
                )?
            };
            return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
        }
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported encoding for PKCS8"),
        ));
    }

    Err(CryptographyError::from(
        pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
    ))
}

pub(crate) fn pkey_public_bytes<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKey<openssl::pkey::Public>,
    encoding: &pyo3::PyAny,
    format: &pyo3::PyAny,
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    let serialization_mod = py.import("cryptography.hazmat.primitives.serialization")?;
    let encoding_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "Encoding"))?
        .extract()?;
    let public_format_class: &pyo3::types::PyType = serialization_mod
        .getattr(pyo3::intern!(py, "PublicFormat"))?
        .extract()?;

    if !encoding.is_instance(encoding_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "encoding must be an item from the Encoding enum",
            ),
        ));
    }
    if !format.is_instance(public_format_class)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err(
                "format must be an item from the PublicFormat enum",
            ),
        ));
    }

    if encoding.is(encoding_class.getattr(pyo3::intern!(py, "Raw"))?)
        || format.is(public_format_class.getattr(pyo3::intern!(py, "Raw"))?)
    {
        if !encoding.is(encoding_class.getattr(pyo3::intern!(py, "Raw"))?)
            || !format.is(public_format_class.getattr(pyo3::intern!(py, "Raw"))?)
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw",
                ),
            ));
        }
        let raw_bytes = pkey.raw_public_key()?;
        return Ok(pyo3::types::PyBytes::new(py, &raw_bytes));
    }

    // SubjectPublicKeyInfo + PEM/DER
    if format.is(public_format_class.getattr(pyo3::intern!(py, "SubjectPublicKeyInfo"))?) {
        if encoding.is(encoding_class.getattr(pyo3::intern!(py, "PEM"))?) {
            let pem_bytes = pkey.public_key_to_pem()?;
            return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
        } else if encoding.is(encoding_class.getattr(pyo3::intern!(py, "DER"))?) {
            let der_bytes = pkey.public_key_to_der()?;
            return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
        }
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "SubjectPublicKeyInfo works only with PEM or DER encoding",
            ),
        ));
    }

    Err(CryptographyError::from(
        pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
    ))
}
