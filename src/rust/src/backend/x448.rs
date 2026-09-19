// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x448")]
pub(crate) struct X448PrivateKey {
    pkey: openssl_bridge::curve448::X448SecretKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x448")]
pub(crate) struct X448PublicKey {
    pkey: openssl_bridge::curve448::X448PublicKey,
}

#[pyo3::pyfunction]
pub(crate) fn generate_key() -> CryptographyResult<X448PrivateKey> {
    Ok(X448PrivateKey {
        pkey: openssl_bridge::curve448::X448SecretKey::generate()?,
    })
}

// Temporary serialization boundary until the shared key parser is migrated.
pub(crate) fn private_key_from_key(
    key: openssl_bridge::curve448::X448SecretKey,
) -> CryptographyResult<X448PrivateKey> {
    Ok(X448PrivateKey { pkey: key })
}

pub(crate) fn public_key_from_key(
    key: openssl_bridge::curve448::X448PublicKey,
) -> CryptographyResult<X448PublicKey> {
    Ok(X448PublicKey { pkey: key })
}

impl X448PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::X448(&self.pkey))
    }
}
impl X448PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::X448(&self.pkey))
    }
}

// We don't reject all-zeros keys -- there's no threat model in which accepting
// them is a risk.
#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<X448PrivateKey> {
    let length_error =
        || pyo3::exceptions::PyValueError::new_err("An X448 private key is 56 bytes long");
    let bytes = data.as_bytes().try_into().map_err(|_| length_error())?;
    let pkey =
        openssl_bridge::curve448::X448SecretKey::from_bytes(bytes).map_err(|_| length_error())?;
    Ok(X448PrivateKey { pkey })
}

#[pyo3::pyfunction]
pub(crate) fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<X448PublicKey> {
    let length_error =
        || pyo3::exceptions::PyValueError::new_err("An X448 public key is 56 bytes long");
    let bytes = data.try_into().map_err(|_| length_error())?;
    let pkey =
        openssl_bridge::curve448::X448PublicKey::from_bytes(bytes).map_err(|_| length_error())?;
    Ok(X448PublicKey { pkey })
}

#[pyo3::pymethods]
impl X448PrivateKey {
    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &X448PublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let secret = self
            .pkey
            .exchange(&peer_public_key.pkey)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;
        Ok(pyo3::types::PyBytes::new(py, secret.as_ref()))
    }

    fn public_key(&self) -> CryptographyResult<X448PublicKey> {
        Ok(X448PublicKey {
            pkey: self.pkey.public_key()?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.to_bytes()?;
        Ok(pyo3::types::PyBytes::new(py, raw_bytes.as_ref()))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().serialization_key()?,
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
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
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
        let raw_bytes = self.pkey.to_bytes()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(
            py,
            slf,
            &slf.borrow().serialization_key()?,
            encoding,
            format,
            false,
            true,
        )
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> CryptographyResult<bool> {
        Ok(self.pkey.to_bytes()? == other.pkey.to_bytes()?)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
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
