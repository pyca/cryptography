// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM768PrivateKey"
)]
pub(crate) struct MlKem768PrivateKey {
    key: openssl_bridge::mlkem::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM768PublicKey"
)]
pub(crate) struct MlKem768PublicKey {
    key: openssl_bridge::mlkem::PublicKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM1024PrivateKey"
)]
pub(crate) struct MlKem1024PrivateKey {
    key: openssl_bridge::mlkem::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM1024PublicKey"
)]
pub(crate) struct MlKem1024PublicKey {
    key: openssl_bridge::mlkem::PublicKey,
}

pub(crate) fn mlkem768_private_key_from_key(
    key: openssl_bridge::mlkem::PrivateKey,
) -> CryptographyResult<MlKem768PrivateKey> {
    Ok(MlKem768PrivateKey { key })
}

pub(crate) fn mlkem768_public_key_from_key(
    key: openssl_bridge::mlkem::PublicKey,
) -> CryptographyResult<MlKem768PublicKey> {
    Ok(MlKem768PublicKey { key })
}

pub(crate) fn mlkem1024_private_key_from_key(
    key: openssl_bridge::mlkem::PrivateKey,
) -> CryptographyResult<MlKem1024PrivateKey> {
    Ok(MlKem1024PrivateKey { key })
}

pub(crate) fn mlkem1024_public_key_from_key(
    key: openssl_bridge::mlkem::PublicKey,
) -> CryptographyResult<MlKem1024PublicKey> {
    Ok(MlKem1024PublicKey { key })
}

#[pyo3::pyfunction]
fn generate_mlkem768_key() -> CryptographyResult<MlKem768PrivateKey> {
    Ok(MlKem768PrivateKey {
        key: openssl_bridge::mlkem::PrivateKey::generate(openssl_bridge::mlkem::Variant::MlKem768)?,
    })
}

#[pyo3::pyfunction]
fn from_mlkem768_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768PrivateKey> {
    let seed = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 seed is 64 bytes long")
    })?;
    let key = openssl_bridge::mlkem::PrivateKey::from_seed(
        openssl_bridge::mlkem::Variant::MlKem768,
        seed,
    )
    .map_err(|_| pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 seed is 64 bytes long"))?;
    Ok(MlKem768PrivateKey { key })
}

#[pyo3::pymethods]
impl MlKem768PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let shared_secret = self.key.decapsulate(ciphertext.as_bytes()).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-768 ciphertext")
        })?;
        Ok(pyo3::types::PyBytes::new(py, shared_secret.as_ref()))
    }

    fn public_key(&self) -> CryptographyResult<MlKem768PublicKey> {
        Ok(MlKem768PublicKey {
            key: self.key.public_key(),
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let seed = self.key.seed();
        Ok(pyo3::types::PyBytes::new(py, seed))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // Intercept Raw/Raw/NoEncryption so we return the seed.
        // The generic pkey_private_bytes raw path calls raw_private_key()
        // which returns the expanded key on AWS-LC, not the seed.
        if encoding == crate::serialization::Encoding::Raw
            && format == crate::serialization::PrivateFormat::Raw
            && encryption_algorithm.is_instance(&crate::types::NO_ENCRYPTION.get(py)?)?
        {
            return slf.borrow().private_bytes_raw(py);
        }
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().serialization_key()?,
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
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

#[pyo3::pyfunction]
fn from_mlkem768_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768PublicKey> {
    let key = openssl_bridge::mlkem::PublicKey::from_bytes(
        openssl_bridge::mlkem::Variant::MlKem768,
        data.as_bytes(),
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 public key is 1184 bytes long")
    })?;
    Ok(MlKem768PublicKey { key })
}

#[pyo3::pymethods]
impl MlKem768PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ciphertext, shared_secret) = self.key.encapsulate().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("ML-KEM-768 encapsulation failed")
        })?;
        let ss = pyo3::types::PyBytes::new(py, shared_secret.as_ref());
        let ct = pyo3::types::PyBytes::new(py, &ciphertext);
        Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.key.as_bytes();
        Ok(pyo3::types::PyBytes::new(py, raw_bytes))
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

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
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

#[pyo3::pyfunction]
fn generate_mlkem1024_key() -> CryptographyResult<MlKem1024PrivateKey> {
    Ok(MlKem1024PrivateKey {
        key: openssl_bridge::mlkem::PrivateKey::generate(
            openssl_bridge::mlkem::Variant::MlKem1024,
        )?,
    })
}

#[pyo3::pyfunction]
fn from_mlkem1024_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem1024PrivateKey> {
    let seed = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-1024 seed is 64 bytes long")
    })?;
    let key = openssl_bridge::mlkem::PrivateKey::from_seed(
        openssl_bridge::mlkem::Variant::MlKem1024,
        seed,
    )
    .map_err(|_| pyo3::exceptions::PyValueError::new_err("An ML-KEM-1024 seed is 64 bytes long"))?;
    Ok(MlKem1024PrivateKey { key })
}

#[pyo3::pymethods]
impl MlKem1024PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let shared_secret = self.key.decapsulate(ciphertext.as_bytes()).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-1024 ciphertext")
        })?;
        Ok(pyo3::types::PyBytes::new(py, shared_secret.as_ref()))
    }

    fn public_key(&self) -> CryptographyResult<MlKem1024PublicKey> {
        Ok(MlKem1024PublicKey {
            key: self.key.public_key(),
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let seed = self.key.seed();
        Ok(pyo3::types::PyBytes::new(py, seed))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // Intercept Raw/Raw/NoEncryption so we return the seed.
        // The generic pkey_private_bytes raw path calls raw_private_key()
        // which returns the expanded key on AWS-LC, not the seed.
        if encoding == crate::serialization::Encoding::Raw
            && format == crate::serialization::PrivateFormat::Raw
            && encryption_algorithm.is_instance(&crate::types::NO_ENCRYPTION.get(py)?)?
        {
            return slf.borrow().private_bytes_raw(py);
        }
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().serialization_key()?,
            encoding,
            format,
            encryption_algorithm,
            true,
            false,
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

#[pyo3::pyfunction]
fn from_mlkem1024_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem1024PublicKey> {
    let key = openssl_bridge::mlkem::PublicKey::from_bytes(
        openssl_bridge::mlkem::Variant::MlKem1024,
        data.as_bytes(),
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-KEM-1024 public key is 1568 bytes long")
    })?;
    Ok(MlKem1024PublicKey { key })
}

#[pyo3::pymethods]
impl MlKem1024PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ciphertext, shared_secret) = self.key.encapsulate().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("ML-KEM-1024 encapsulation failed")
        })?;
        let ss = pyo3::types::PyBytes::new(py, shared_secret.as_ref());
        let ct = pyo3::types::PyBytes::new(py, &ciphertext);
        Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.key.as_bytes();
        Ok(pyo3::types::PyBytes::new(py, raw_bytes))
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

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
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
pub(crate) mod mlkem {
    #[pymodule_export]
    use super::{
        from_mlkem1024_public_bytes, from_mlkem1024_seed_bytes, from_mlkem768_public_bytes,
        from_mlkem768_seed_bytes, generate_mlkem1024_key, generate_mlkem768_key,
        MlKem1024PrivateKey, MlKem1024PublicKey, MlKem768PrivateKey, MlKem768PublicKey,
    };
}

impl MlKem768PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::MlKem(&self.key))
    }
}
impl MlKem768PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::MlKem(&self.key))
    }
}

impl MlKem1024PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::MlKem(&self.key))
    }
}
impl MlKem1024PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::MlKem(&self.key))
    }
}
