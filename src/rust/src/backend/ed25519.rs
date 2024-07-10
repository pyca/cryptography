// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<Ed25519PrivateKey> {
    Ok(Ed25519PrivateKey {
        pkey: openssl::pkey::PKey::generate_ed25519()?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Ed25519PrivateKey {
    Ed25519PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Ed25519PublicKey {
    Ed25519PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed25519PrivateKey> {
    let pkey = openssl::pkey::PKey::private_key_from_raw_bytes(
        data.as_bytes(),
        openssl::pkey::Id::ED25519,
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed25519 private key is 32 bytes long")
    })?;
    Ok(Ed25519PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed25519PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::ED25519)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An Ed25519 public key is 32 bytes long")
        })?;
    Ok(Ed25519PublicKey { pkey })
}

#[pyo3::pymethods]
impl Ed25519PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        let len = signer.len()?;
        Ok(pyo3::types::PyBytes::new_bound_with(py, len, |b| {
            let n = signer
                .sign_oneshot(b, data.as_bytes())
                .map_err(CryptographyError::from)?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn public_key(&self) -> CryptographyResult<Ed25519PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(Ed25519PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes(
                &raw_bytes,
                openssl::pkey::Id::ED25519,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_private_key()?;
        Ok(pyo3::types::PyBytes::new_bound(py, &raw_bytes))
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
            true,
            true,
        )
    }
}

#[pyo3::pymethods]
impl Ed25519PublicKey {
    fn verify(&self, signature: CffiBuf<'_>, data: CffiBuf<'_>) -> CryptographyResult<()> {
        let valid = openssl::sign::Verifier::new_without_digest(&self.pkey)?
            .verify_oneshot(signature.as_bytes(), data.as_bytes())
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
        Ok(pyo3::types::PyBytes::new_bound(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: &pyo3::Bound<'p, pyo3::PyAny>,
        format: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }
}

#[pyo3::pymodule]
pub(crate) mod ed25519 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, Ed25519PrivateKey, Ed25519PublicKey,
    };
}
