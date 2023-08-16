// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
use foreign_types_shared::ForeignTypeRef;

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x25519")]
struct X25519PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x25519")]
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
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
        encryption_algorithm: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            false,
            true,
        )
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
        slf: &pyo3::PyCell<Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::PyAny,
        format: &pyo3::PyAny,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, false, true)
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, X25519PublicKey>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.pkey.public_eq(&other.pkey)),
            pyo3::basic::CompareOp::Ne => Ok(!self.pkey.public_eq(&other.pkey)),
            _ => Err(pyo3::exceptions::PyTypeError::new_err("Cannot be ordered")),
        }
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "x25519")?;
    m.add_function(pyo3::wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_bytes, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_bytes, m)?)?;

    m.add_class::<X25519PrivateKey>()?;
    m.add_class::<X25519PublicKey>()?;

    Ok(m)
}
