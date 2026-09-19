// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
pub(crate) struct Ed448PrivateKey {
    pkey: openssl_bridge::curve448::Ed448SigningKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
pub(crate) struct Ed448PublicKey {
    pkey: openssl_bridge::curve448::Ed448VerifyingKey,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<Ed448PrivateKey> {
    Ok(Ed448PrivateKey {
        pkey: openssl_bridge::curve448::Ed448SigningKey::generate()?,
    })
}

// Temporary serialization boundary until the shared key parser is migrated.
pub(crate) fn private_key_from_key(
    key: openssl_bridge::curve448::Ed448SigningKey,
) -> CryptographyResult<Ed448PrivateKey> {
    Ok(Ed448PrivateKey { pkey: key })
}

pub(crate) fn public_key_from_key(
    key: openssl_bridge::curve448::Ed448VerifyingKey,
) -> CryptographyResult<Ed448PublicKey> {
    Ok(Ed448PublicKey { pkey: key })
}

impl Ed448PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::Ed448(&self.pkey))
    }
}
impl Ed448PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::Ed448(&self.pkey))
    }
}

// We don't reject all-zeros keys -- there's no threat model in which accepting
// them is a risk.
#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed448PrivateKey> {
    let length_error =
        || pyo3::exceptions::PyValueError::new_err("An Ed448 private key is 57 bytes long");
    let bytes = data.as_bytes().try_into().map_err(|_| length_error())?;
    let pkey =
        openssl_bridge::curve448::Ed448SigningKey::from_seed(bytes).map_err(|_| length_error())?;
    Ok(Ed448PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed448PublicKey> {
    let length_error =
        || pyo3::exceptions::PyValueError::new_err("An Ed448 public key is 57 bytes long");
    let bytes = data.try_into().map_err(|_| length_error())?;
    let pkey = openssl_bridge::curve448::Ed448VerifyingKey::from_bytes(bytes)
        .map_err(|_| length_error())?;
    Ok(Ed448PublicKey { pkey })
}

#[pyo3::pymethods]
impl Ed448PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = data.as_bytes();
        let signature = py.detach(|| self.pkey.sign(data))?;
        Ok(pyo3::types::PyBytes::new(py, &signature))
    }

    fn public_key(&self) -> CryptographyResult<Ed448PublicKey> {
        Ok(Ed448PublicKey {
            pkey: self.pkey.verifying_key()?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.to_seed()?;
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
            true,
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
impl Ed448PublicKey {
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let signature = signature.as_bytes();
        let data = data.as_bytes();
        let valid = py
            .detach(|| self.pkey.verify(data, signature))
            .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

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
            true,
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
pub(crate) mod ed448 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, Ed448PrivateKey, Ed448PublicKey,
    };
}
