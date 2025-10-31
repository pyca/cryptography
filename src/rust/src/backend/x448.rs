// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x448")]
pub(crate) struct X448PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x448")]
pub(crate) struct X448PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<X448PrivateKey> {
    Ok(X448PrivateKey {
        pkey: openssl::pkey::PKey::generate_x448()?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> X448PrivateKey {
    X448PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> X448PublicKey {
    X448PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<X448PrivateKey> {
    let pkey =
        openssl::pkey::PKey::private_key_from_raw_bytes(data.as_bytes(), openssl::pkey::Id::X448)
            .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "An X448 private key is 56 bytes long: {e}"
            ))
        })?;
    Ok(X448PrivateKey { pkey })
}
#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<X448PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::X448)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An X448 public key is 32 bytes long")
        })?;
    Ok(X448PublicKey { pkey })
}

#[pyo3::pymethods]
impl X448PrivateKey {
    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &X448PublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut deriver = openssl::derive::Deriver::new(&self.pkey)?;
        deriver.set_peer(&peer_public_key.pkey)?;

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
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_private_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
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

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::types::PyDict>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl X448PublicKey {
    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, false, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::types::PyDict>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod x448 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, X448PrivateKey, X448PublicKey,
    };
}
