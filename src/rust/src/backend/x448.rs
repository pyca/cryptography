// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;
use foreign_types_shared::ForeignTypeRef;

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.x448")]
struct X448PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.x448")]
struct X448PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::prelude::pyfunction]
fn generate_key() -> CryptographyResult<X448PrivateKey> {
    Ok(X448PrivateKey {
        pkey: openssl::pkey::PKey::generate_x448()?,
    })
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(ptr: usize) -> X448PrivateKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    X448PrivateKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(ptr: usize) -> X448PublicKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    X448PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<X448PrivateKey> {
    let pkey =
        openssl::pkey::PKey::private_key_from_raw_bytes(data.as_bytes(), openssl::pkey::Id::X448)
            .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "An X448 private key is 56 bytes long: {}",
                e
            ))
        })?;
    Ok(X448PrivateKey { pkey })
}
#[pyo3::prelude::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<X448PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::X448)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An X448 public key is 32 bytes long")
        })?;
    Ok(X448PublicKey { pkey })
}

#[pyo3::prelude::pymethods]
impl X448PrivateKey {
    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        public_key: &X448PublicKey,
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

    fn public_key(&self) -> CryptographyResult<X448PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(X448PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes(
                &raw_bytes,
                openssl::pkey::Id::X448,
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
        )
    }
}

#[pyo3::prelude::pymethods]
impl X448PublicKey {
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
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, false)
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, X448PublicKey>,
        op: pyo3::basic::CompareOp,
    ) -> pyo3::PyResult<bool> {
        match op {
            pyo3::basic::CompareOp::Eq => Ok(self.pkey.public_eq(&other.pkey)),
            pyo3::basic::CompareOp::Ne => Ok(!self.pkey.public_eq(&other.pkey)),
            _ => Err(pyo3::exceptions::PyTypeError::new_err("Cannot be ordered")),
        }
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "x448")?;
    m.add_function(pyo3::wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_bytes, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_bytes, m)?)?;

    m.add_class::<X448PrivateKey>()?;
    m.add_class::<X448PublicKey>()?;

    Ok(m)
}
