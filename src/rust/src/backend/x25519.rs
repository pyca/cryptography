// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use foreign_types_shared::ForeignTypeRef;

#[pyo3::prelude::pyclass]
struct X25519PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass]
struct X25519PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::prelude::pyfunction]
fn generate_key() -> CryptographyResult<X25519PrivateKey> {
    Ok(X25519PrivateKey {
        pkey: openssl::pkey::PKey::generate_x25519()?,
    })
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(ptr: usize) -> X25519PrivateKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    X25519PrivateKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(ptr: usize) -> X25519PublicKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    X25519PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<X25519PrivateKey> {
    let pkey =
        openssl::pkey::PKey::private_key_from_raw_bytes(data.as_bytes(), openssl::pkey::Id::X25519)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "An X25519 private key is 32 bytes long: {}",
                    e
                ))
            })?;
    Ok(X25519PrivateKey { pkey })
}
#[pyo3::prelude::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<X25519PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::X25519)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An X25519 public key is 32 bytes long")
        })?;
    Ok(X25519PublicKey { pkey })
}

#[pyo3::prelude::pymethods]
impl X25519PrivateKey {
    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        public_key: &X25519PublicKey,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        deriver.set_peer(&public_key.pkey)?;

        Ok(pyo3::types::PyBytes::new_with(py, deriver.len()?, |b| {
            let n = deriver.derive(b).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Error computing shared key.")
            })?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn public_key(&self) -> CryptographyResult<X25519PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(X25519PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes(
                &raw_bytes,
                openssl::pkey::Id::X25519,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let raw_bytes = self.pkey.raw_private_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn private_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
        encryption_algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let serialization_mod = py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "Encoding"))?
            .extract()?;
        let private_format_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "PrivateFormat"))?
            .extract()?;
        let no_encryption_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "NoEncryption"))?
            .extract()?;
        let best_available_encryption_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "BestAvailableEncryption"))?
            .extract()?;

        if !encoding_class.is_instance(encoding)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "encoding must be an item from the Encoding enum",
                ),
            ));
        }
        if !private_format_class.is_instance(format)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "format must be an item from the PrivateFormat enum",
                ),
            ));
        }

        if encoding == encoding_class.getattr(crate::intern!(py, "Raw"))?
            || format == private_format_class.getattr(crate::intern!(py, "Raw"))?
        {
            if encoding != encoding_class.getattr(crate::intern!(py, "Raw"))?
                || format != private_format_class.getattr(crate::intern!(py, "Raw"))?
                || !no_encryption_class.is_instance(encryption_algorithm)?
            {
                return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                )));
            }
            let raw_bytes = self.pkey.raw_private_key()?;
            return Ok(pyo3::types::PyBytes::new(py, &raw_bytes));
        }

        let password = if no_encryption_class.is_instance(encryption_algorithm)? {
            b""
        } else if best_available_encryption_class.is_instance(encryption_algorithm)? {
            encryption_algorithm
                .getattr(crate::intern!(py, "password"))?
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

        if format == private_format_class.getattr(crate::intern!(py, "PKCS8"))? {
            if encoding == encoding_class.getattr(crate::intern!(py, "PEM"))? {
                let pem_bytes = if password.is_empty() {
                    self.pkey.private_key_to_pem_pkcs8()?
                } else {
                    self.pkey.private_key_to_pem_pkcs8_passphrase(
                        openssl::symm::Cipher::aes_256_cbc(),
                        password,
                    )?
                };
                return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
            } else if encoding == encoding_class.getattr(crate::intern!(py, "DER"))? {
                let der_bytes = if password.is_empty() {
                    self.pkey.private_key_to_pkcs8()?
                } else {
                    self.pkey.private_key_to_pkcs8_passphrase(
                        openssl::symm::Cipher::aes_256_cbc(),
                        password,
                    )?
                };
                return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
            } else {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err("Unsupported encoding for PKCS8"),
                ));
            }
        }

        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
        ))
    }
}

#[pyo3::prelude::pymethods]
impl X25519PublicKey {
    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let serialization_mod = py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "Encoding"))?
            .extract()?;
        let public_format_class: &pyo3::types::PyType = serialization_mod
            .getattr(crate::intern!(py, "PublicFormat"))?
            .extract()?;

        if !encoding_class.is_instance(encoding)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "encoding must be an item from the Encoding enum",
                ),
            ));
        }
        if !public_format_class.is_instance(format)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "format must be an item from the PublicFormat enum",
                ),
            ));
        }

        if encoding == encoding_class.getattr(crate::intern!(py, "Raw"))?
            || format == public_format_class.getattr(crate::intern!(py, "Raw"))?
        {
            if encoding != encoding_class.getattr(crate::intern!(py, "Raw"))?
                || format != public_format_class.getattr(crate::intern!(py, "Raw"))?
            {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "When using Raw both encoding and format must be Raw",
                    ),
                ));
            }
            let raw_bytes = self.pkey.raw_public_key()?;
            return Ok(pyo3::types::PyBytes::new(py, &raw_bytes));
        }

        // SubjectPublicKeyInfo + PEM/DER
        if format == public_format_class.getattr(crate::intern!(py, "SubjectPublicKeyInfo"))? {
            if encoding == encoding_class.getattr(crate::intern!(py, "PEM"))? {
                let pem_bytes = self.pkey.public_key_to_pem()?;
                return Ok(pyo3::types::PyBytes::new(py, &pem_bytes));
            } else if encoding == encoding_class.getattr(crate::intern!(py, "DER"))? {
                let der_bytes = self.pkey.public_key_to_der()?;
                return Ok(pyo3::types::PyBytes::new(py, &der_bytes));
            } else {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "SubjectPublicKeyInfo works only with PEM or DER encoding",
                    ),
                ));
            }
        }

        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
        ))
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "x25519")?;
    m.add_wrapped(pyo3::wrap_pyfunction!(generate_key))?;
    m.add_wrapped(pyo3::wrap_pyfunction!(private_key_from_ptr))?;
    m.add_wrapped(pyo3::wrap_pyfunction!(public_key_from_ptr))?;
    m.add_wrapped(pyo3::wrap_pyfunction!(from_private_bytes))?;
    m.add_wrapped(pyo3::wrap_pyfunction!(from_public_bytes))?;

    m.add_class::<X25519PrivateKey>()?;
    m.add_class::<X25519PublicKey>()?;

    Ok(m)
}
