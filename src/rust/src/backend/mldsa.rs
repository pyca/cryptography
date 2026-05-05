// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_openssl::mldsa::MlDsaVariant;
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
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA44PublicKey"
)]
pub(crate) struct MlDsa44PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa44_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa44PrivateKey {
    MlDsa44PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa44_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa44PublicKey {
    MlDsa44PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa44_key() -> CryptographyResult<MlDsa44PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa44, &seed)?;
    Ok(MlDsa44PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa44_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa44, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-44 seed is 32 bytes long")
            })?;
    Ok(MlDsa44PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa44_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa44, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-44 public key is 1312 bytes long",
                )
            })?;
    Ok(MlDsa44PublicKey { pkey })
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
        let sig = cryptography_openssl::mldsa::sign(&self.pkey, data.as_bytes(), ctx_bytes)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa44PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa44PublicKey {
            pkey: cryptography_openssl::mldsa::new_raw_public_key(
                MlDsaVariant::MlDsa44,
                &raw_bytes,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let cryptography_key_parsing::pkcs8::MlDsaPrivateKey::Seed(seed) =
            cryptography_key_parsing::pkcs8::mldsa_seed_from_pkey(&self.pkey)?;
        Ok(pyo3::types::PyBytes::new(py, &seed))
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

#[pyo3::pymethods]
impl MlDsa44PublicKey {
    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
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
        let valid = cryptography_openssl::mldsa::verify(
            &self.pkey,
            signature.as_bytes(),
            data.as_bytes(),
            ctx_bytes,
        )
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

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PrivateKey"
)]
pub(crate) struct MlDsa65PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PublicKey"
)]
pub(crate) struct MlDsa65PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa65_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa65PrivateKey {
    MlDsa65PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa65_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa65PublicKey {
    MlDsa65PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa65_key() -> CryptographyResult<MlDsa65PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa65, &seed)?;
    Ok(MlDsa65PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa65_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa65, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 seed is 32 bytes long")
            })?;
    Ok(MlDsa65PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa65_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa65, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-65 public key is 1952 bytes long",
                )
            })?;
    Ok(MlDsa65PublicKey { pkey })
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
        let sig = cryptography_openssl::mldsa::sign(&self.pkey, data.as_bytes(), ctx_bytes)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa65PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa65PublicKey {
            pkey: cryptography_openssl::mldsa::new_raw_public_key(
                MlDsaVariant::MlDsa65,
                &raw_bytes,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let cryptography_key_parsing::pkcs8::MlDsaPrivateKey::Seed(seed) =
            cryptography_key_parsing::pkcs8::mldsa_seed_from_pkey(&self.pkey)?;
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

#[pyo3::pymethods]
impl MlDsa65PublicKey {
    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
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
        let valid = cryptography_openssl::mldsa::verify(
            &self.pkey,
            signature.as_bytes(),
            data.as_bytes(),
            ctx_bytes,
        )
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

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PrivateKey"
)]
pub(crate) struct MlDsa87PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PublicKey"
)]
pub(crate) struct MlDsa87PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa87_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa87PrivateKey {
    MlDsa87PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa87_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa87PublicKey {
    MlDsa87PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa87_key() -> CryptographyResult<MlDsa87PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa87, &seed)?;
    Ok(MlDsa87PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa87_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa87, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-87 seed is 32 bytes long")
            })?;
    Ok(MlDsa87PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa87_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa87, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-87 public key is 2592 bytes long",
                )
            })?;
    Ok(MlDsa87PublicKey { pkey })
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
        let sig = cryptography_openssl::mldsa::sign(&self.pkey, data.as_bytes(), ctx_bytes)?;
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa87PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa87PublicKey {
            pkey: cryptography_openssl::mldsa::new_raw_public_key(
                MlDsaVariant::MlDsa87,
                &raw_bytes,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let cryptography_key_parsing::pkcs8::MlDsaPrivateKey::Seed(seed) =
            cryptography_key_parsing::pkcs8::mldsa_seed_from_pkey(&self.pkey)?;
        Ok(pyo3::types::PyBytes::new(py, &seed))
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

#[pyo3::pymethods]
impl MlDsa87PublicKey {
    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
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
        let valid = cryptography_openssl::mldsa::verify(
            &self.pkey,
            signature.as_bytes(),
            data.as_bytes(),
            ctx_bytes,
        )
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
pub(crate) mod mldsa {
    #[pymodule_export]
    use super::{
        from_mldsa44_public_bytes, from_mldsa44_seed_bytes, from_mldsa65_public_bytes,
        from_mldsa65_seed_bytes, from_mldsa87_public_bytes, from_mldsa87_seed_bytes,
        generate_mldsa44_key, generate_mldsa65_key, generate_mldsa87_key, MlDsa44PrivateKey,
        MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey, MlDsa87PublicKey,
    };
}
