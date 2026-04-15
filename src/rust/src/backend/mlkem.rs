// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use cryptography_openssl::mlkem::MlKemVariant;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::CryptographyResult;

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM768PrivateKey"
)]
pub(crate) struct MlKem768PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM768PublicKey"
)]
pub(crate) struct MlKem768PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM1024PrivateKey"
)]
pub(crate) struct MlKem1024PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
    name = "MLKEM1024PublicKey"
)]
pub(crate) struct MlKem1024PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mlkem768_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlKem768PrivateKey {
    MlKem768PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mlkem768_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlKem768PublicKey {
    MlKem768PublicKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mlkem1024_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlKem1024PrivateKey {
    MlKem1024PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mlkem1024_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlKem1024PublicKey {
    MlKem1024PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mlkem768_key() -> CryptographyResult<MlKem768PrivateKey> {
    let mut seed = [0u8; 64];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mlkem::new_raw_private_key(MlKemVariant::MlKem768, &seed)?;
    Ok(MlKem768PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mlkem768_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem768PrivateKey> {
    let pkey =
        cryptography_openssl::mlkem::new_raw_private_key(MlKemVariant::MlKem768, data.as_bytes())
            .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An ML-KEM-768 seed is 64 bytes long")
        })?;
    Ok(MlKem768PrivateKey { pkey })
}

#[pyo3::pymethods]
impl MlKem768PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let shared_secret =
            cryptography_openssl::mlkem::decapsulate(&self.pkey, ciphertext.as_bytes()).map_err(
                |_| pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-768 ciphertext"),
            )?;
        Ok(pyo3::types::PyBytes::new(py, &shared_secret))
    }

    fn public_key(&self) -> CryptographyResult<MlKem768PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlKem768PublicKey {
            pkey: cryptography_openssl::mlkem::new_raw_public_key(
                MlKemVariant::MlKem768,
                &raw_bytes,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let cryptography_key_parsing::pkcs8::MlKemPrivateKey::Seed(seed) =
            cryptography_key_parsing::pkcs8::mlkem_seed_from_pkey(&self.pkey)?;
        Ok(pyo3::types::PyBytes::new(py, &seed))
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
            &slf.borrow().pkey,
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
    let pkey =
        cryptography_openssl::mlkem::new_raw_public_key(MlKemVariant::MlKem768, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-KEM-768 public key is 1184 bytes long",
                )
            })?;
    Ok(MlKem768PublicKey { pkey })
}

#[pyo3::pymethods]
impl MlKem768PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ciphertext, shared_secret) = cryptography_openssl::mlkem::encapsulate(&self.pkey)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("ML-KEM-768 encapsulation failed")
            })?;
        let ss = pyo3::types::PyBytes::new(py, &shared_secret);
        let ct = pyo3::types::PyBytes::new(py, &ciphertext);
        Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
    }

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
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
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
    let mut seed = [0u8; 64];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mlkem::new_raw_private_key(MlKemVariant::MlKem1024, &seed)?;
    Ok(MlKem1024PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mlkem1024_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlKem1024PrivateKey> {
    let pkey =
        cryptography_openssl::mlkem::new_raw_private_key(MlKemVariant::MlKem1024, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-KEM-1024 seed is 64 bytes long")
            })?;
    Ok(MlKem1024PrivateKey { pkey })
}

#[pyo3::pymethods]
impl MlKem1024PrivateKey {
    fn decapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
        ciphertext: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let shared_secret =
            cryptography_openssl::mlkem::decapsulate(&self.pkey, ciphertext.as_bytes()).map_err(
                |_| pyo3::exceptions::PyValueError::new_err("Invalid ML-KEM-1024 ciphertext"),
            )?;
        Ok(pyo3::types::PyBytes::new(py, &shared_secret))
    }

    fn public_key(&self) -> CryptographyResult<MlKem1024PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlKem1024PublicKey {
            pkey: cryptography_openssl::mlkem::new_raw_public_key(
                MlKemVariant::MlKem1024,
                &raw_bytes,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let cryptography_key_parsing::pkcs8::MlKemPrivateKey::Seed(seed) =
            cryptography_key_parsing::pkcs8::mlkem_seed_from_pkey(&self.pkey)?;
        Ok(pyo3::types::PyBytes::new(py, &seed))
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
            &slf.borrow().pkey,
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
    let pkey =
        cryptography_openssl::mlkem::new_raw_public_key(MlKemVariant::MlKem1024, data.as_bytes())
            .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An ML-KEM-1024 public key is 1568 bytes long")
        })?;
    Ok(MlKem1024PublicKey { pkey })
}

#[pyo3::pymethods]
impl MlKem1024PublicKey {
    fn encapsulate<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
        let (ciphertext, shared_secret) = cryptography_openssl::mlkem::encapsulate(&self.pkey)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("ML-KEM-1024 encapsulation failed")
            })?;
        let ss = pyo3::types::PyBytes::new(py, &shared_secret);
        let ct = pyo3::types::PyBytes::new(py, &ciphertext);
        Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
    }

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
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
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
