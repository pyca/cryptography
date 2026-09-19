// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const MAX_CONTEXT_BYTES: usize = 255;

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA44PrivateKey"
)]
pub(crate) struct MlDsa44PrivateKey {
    key: openssl_bridge::mldsa::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA44PublicKey"
)]
pub(crate) struct MlDsa44PublicKey {
    key: openssl_bridge::mldsa::PublicKey,
}

pub(crate) fn mldsa44_private_key_from_key(
    key: openssl_bridge::mldsa::PrivateKey,
) -> CryptographyResult<MlDsa44PrivateKey> {
    Ok(MlDsa44PrivateKey { key })
}

pub(crate) fn mldsa44_public_key_from_key(
    key: openssl_bridge::mldsa::PublicKey,
) -> CryptographyResult<MlDsa44PublicKey> {
    Ok(MlDsa44PublicKey { key })
}

#[pyo3::pyfunction]
fn generate_mldsa44_key() -> CryptographyResult<MlDsa44PrivateKey> {
    Ok(MlDsa44PrivateKey {
        key: openssl_bridge::mldsa::PrivateKey::generate(openssl_bridge::mldsa::Variant::MlDsa44)?,
    })
}

#[pyo3::pyfunction]
fn from_mldsa44_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PrivateKey> {
    let seed = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-44 seed is 32 bytes long")
    })?;
    let key =
        openssl_bridge::mldsa::PrivateKey::from_seed(openssl_bridge::mldsa::Variant::MlDsa44, seed)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-44 seed is 32 bytes long")
            })?;
    Ok(MlDsa44PrivateKey { key })
}

#[pyo3::pyfunction]
fn from_mldsa44_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PublicKey> {
    let key = openssl_bridge::mldsa::PublicKey::from_bytes(
        openssl_bridge::mldsa::Variant::MlDsa44,
        data.as_bytes(),
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-44 public key is 1312 bytes long")
    })?;
    Ok(MlDsa44PublicKey { key })
}

#[pyo3::pymethods]
impl MlDsa44PrivateKey {
    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let sig = py.detach(|| self.key.sign(&data_bytes, &ctx_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn sign_mu<'p>(
        &self,
        py: pyo3::Python<'p>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let sig = py.detach(|| self.key.sign_mu(&mu_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa44PublicKey> {
        Ok(MlDsa44PublicKey {
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

#[pyo3::pymethods]
impl MlDsa44PublicKey {
    fn verify_mu(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let valid = py
            .detach(|| self.key.verify_mu(&mu_bytes, &sig_bytes))
            .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let valid = py
            .detach(|| self.key.verify(&data_bytes, &ctx_bytes, &sig_bytes))
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

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PrivateKey"
)]
pub(crate) struct MlDsa65PrivateKey {
    key: openssl_bridge::mldsa::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PublicKey"
)]
pub(crate) struct MlDsa65PublicKey {
    key: openssl_bridge::mldsa::PublicKey,
}

pub(crate) fn mldsa65_private_key_from_key(
    key: openssl_bridge::mldsa::PrivateKey,
) -> CryptographyResult<MlDsa65PrivateKey> {
    Ok(MlDsa65PrivateKey { key })
}

pub(crate) fn mldsa65_public_key_from_key(
    key: openssl_bridge::mldsa::PublicKey,
) -> CryptographyResult<MlDsa65PublicKey> {
    Ok(MlDsa65PublicKey { key })
}

#[pyo3::pyfunction]
fn generate_mldsa65_key() -> CryptographyResult<MlDsa65PrivateKey> {
    Ok(MlDsa65PrivateKey {
        key: openssl_bridge::mldsa::PrivateKey::generate(openssl_bridge::mldsa::Variant::MlDsa65)?,
    })
}

#[pyo3::pyfunction]
fn from_mldsa65_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PrivateKey> {
    let seed = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 seed is 32 bytes long")
    })?;
    let key =
        openssl_bridge::mldsa::PrivateKey::from_seed(openssl_bridge::mldsa::Variant::MlDsa65, seed)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 seed is 32 bytes long")
            })?;
    Ok(MlDsa65PrivateKey { key })
}

#[pyo3::pyfunction]
fn from_mldsa65_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PublicKey> {
    let key = openssl_bridge::mldsa::PublicKey::from_bytes(
        openssl_bridge::mldsa::Variant::MlDsa65,
        data.as_bytes(),
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 public key is 1952 bytes long")
    })?;
    Ok(MlDsa65PublicKey { key })
}

#[pyo3::pymethods]
impl MlDsa65PrivateKey {
    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let sig = py.detach(|| self.key.sign(&data_bytes, &ctx_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn sign_mu<'p>(
        &self,
        py: pyo3::Python<'p>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let sig = py.detach(|| self.key.sign_mu(&mu_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa65PublicKey> {
        Ok(MlDsa65PublicKey {
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

#[pyo3::pymethods]
impl MlDsa65PublicKey {
    fn verify_mu(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let valid = py
            .detach(|| self.key.verify_mu(&mu_bytes, &sig_bytes))
            .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let valid = py
            .detach(|| self.key.verify(&data_bytes, &ctx_bytes, &sig_bytes))
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

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PrivateKey"
)]
pub(crate) struct MlDsa87PrivateKey {
    key: openssl_bridge::mldsa::PrivateKey,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PublicKey"
)]
pub(crate) struct MlDsa87PublicKey {
    key: openssl_bridge::mldsa::PublicKey,
}

pub(crate) fn mldsa87_private_key_from_key(
    key: openssl_bridge::mldsa::PrivateKey,
) -> CryptographyResult<MlDsa87PrivateKey> {
    Ok(MlDsa87PrivateKey { key })
}

pub(crate) fn mldsa87_public_key_from_key(
    key: openssl_bridge::mldsa::PublicKey,
) -> CryptographyResult<MlDsa87PublicKey> {
    Ok(MlDsa87PublicKey { key })
}

#[pyo3::pyfunction]
fn generate_mldsa87_key() -> CryptographyResult<MlDsa87PrivateKey> {
    Ok(MlDsa87PrivateKey {
        key: openssl_bridge::mldsa::PrivateKey::generate(openssl_bridge::mldsa::Variant::MlDsa87)?,
    })
}

#[pyo3::pyfunction]
fn from_mldsa87_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PrivateKey> {
    let seed = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-87 seed is 32 bytes long")
    })?;
    let key =
        openssl_bridge::mldsa::PrivateKey::from_seed(openssl_bridge::mldsa::Variant::MlDsa87, seed)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-87 seed is 32 bytes long")
            })?;
    Ok(MlDsa87PrivateKey { key })
}

#[pyo3::pyfunction]
fn from_mldsa87_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PublicKey> {
    let key = openssl_bridge::mldsa::PublicKey::from_bytes(
        openssl_bridge::mldsa::Variant::MlDsa87,
        data.as_bytes(),
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An ML-DSA-87 public key is 2592 bytes long")
    })?;
    Ok(MlDsa87PublicKey { key })
}

#[pyo3::pymethods]
impl MlDsa87PrivateKey {
    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let sig = py.detach(|| self.key.sign(&data_bytes, &ctx_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn sign_mu<'p>(
        &self,
        py: pyo3::Python<'p>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let sig = py.detach(|| self.key.sign_mu(&mu_bytes))?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa87PublicKey> {
        Ok(MlDsa87PublicKey {
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

#[pyo3::pymethods]
impl MlDsa87PublicKey {
    fn verify_mu(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        mu: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        if mu.as_bytes().len() != 64 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let mu_bytes: [u8; 64] = mu
            .as_bytes()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("mu must be 64 bytes"))?;
        let valid = py
            .detach(|| self.key.verify_mu(&mu_bytes, &sig_bytes))
            .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let sig_bytes = signature.as_bytes().to_vec();
        let data_bytes = data.as_bytes().to_vec();
        let ctx_bytes = ctx_bytes.to_vec();
        let valid = py
            .detach(|| self.key.verify(&data_bytes, &ctx_bytes, &sig_bytes))
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

/// Extract the raw public key bytes from any ML-DSA public key object.
fn mldsa_public_key_raw(public_key: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    if let Ok(k) = public_key.cast::<MlDsa44PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else if let Ok(k) = public_key.cast::<MlDsa65PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else if let Ok(k) = public_key.cast::<MlDsa87PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("public_key must be an ML-DSA public key."),
        ))
    }
}

/// Build a SHAKE256 hasher pre-loaded with the fixed part of the pure-ML-DSA
/// mu input: `SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx`. The message is
/// absorbed later by [`MlDsaMuHasher::update`]. SHAKE256 is unavailable through
/// the EVP interface on BoringSSL/LibreSSL, so this is only compiled elsewhere.
#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
fn mu_hasher_init(
    raw_pk: &[u8],
    context: &[u8],
) -> CryptographyResult<openssl_bridge::hash::Hasher> {
    let md = openssl_bridge::hash::Algorithm::from_name("shake256")?;
    // tr = SHAKE256(pk, 64)
    let mut tr = [0; 64];
    openssl_bridge::hash::digest_xof(md, raw_pk, &mut tr)?;
    let mut ctx = openssl_bridge::hash::Hasher::new(md)?;
    ctx.update(&tr)?;
    // Pure-ML-DSA M' prefix: domain separator 0x00, then the context.
    ctx.update(&[0x00])?;
    ctx.update(&[context.len() as u8])?;
    ctx.update(context)?;
    Ok(ctx)
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSAMuHasher"
)]
pub(crate) struct MlDsaMuHasher {
    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    ctx: Option<openssl_bridge::hash::Hasher>,
}

#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
impl MlDsaMuHasher {
    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut openssl_bridge::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }

    fn get_ctx(&self) -> CryptographyResult<&openssl_bridge::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

#[pyo3::pymethods]
impl MlDsaMuHasher {
    #[new]
    #[pyo3(signature = (public_key, context=None))]
    fn new(
        public_key: &pyo3::Bound<'_, pyo3::PyAny>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<MlDsaMuHasher> {
        let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
        if ctx_bytes.len() > MAX_CONTEXT_BYTES {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
            ));
        }
        let raw_pk = mldsa_public_key_raw(public_key)?;
        cfg_if::cfg_if! {
            if #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))] {
                Ok(MlDsaMuHasher {
                    ctx: Some(mu_hasher_init(&raw_pk, ctx_bytes)?),
                })
            } else {
                let _ = raw_pk;
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "ML-DSA external mu computation is not supported on \
                         this backend.",
                        exceptions::Reasons::UNSUPPORTED_HASH,
                    )),
                ))
            }
        }
    }

    // On backends where construction always fails (no SHAKE256 through the
    // EVP interface), no instance can exist, so the methods below aren't
    // compiled at all.
    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data.as_bytes())?;
        Ok(())
    }

    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    fn copy(&self) -> CryptographyResult<MlDsaMuHasher> {
        Ok(MlDsaMuHasher {
            ctx: Some(self.get_ctx()?.try_clone()?),
        })
    }

    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = self
            .ctx
            .take()
            .ok_or_else(exceptions::already_finalized_error)?;
        let mut result = [0; 64];
        ctx.finish_xof(&mut result)?;
        Ok(pyo3::types::PyBytes::new(py, &result))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mldsa {
    #[pymodule_export]
    use super::{
        from_mldsa44_public_bytes, from_mldsa44_seed_bytes, from_mldsa65_public_bytes,
        from_mldsa65_seed_bytes, from_mldsa87_public_bytes, from_mldsa87_seed_bytes,
        generate_mldsa44_key, generate_mldsa65_key, generate_mldsa87_key, MlDsa44PrivateKey,
        MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey, MlDsa87PublicKey,
        MlDsaMuHasher,
    };
}

impl MlDsa44PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::MlDsa(&self.key))
    }
}
impl MlDsa44PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::MlDsa(&self.key))
    }
}

impl MlDsa65PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::MlDsa(&self.key))
    }
}
impl MlDsa65PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::MlDsa(&self.key))
    }
}

impl MlDsa87PrivateKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PrivateKeyRef<'_>> {
        Ok(cryptography_key_parsing::PrivateKeyRef::MlDsa(&self.key))
    }
}
impl MlDsa87PublicKey {
    fn serialization_key(&self) -> CryptographyResult<cryptography_key_parsing::PublicKeyRef<'_>> {
        Ok(cryptography_key_parsing::PublicKeyRef::MlDsa(&self.key))
    }
}
