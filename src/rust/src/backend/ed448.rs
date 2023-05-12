// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use foreign_types_shared::ForeignTypeRef;

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
struct Ed448PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
struct Ed448PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::prelude::pyfunction]
fn generate_key() -> CryptographyResult<Ed448PrivateKey> {
    Ok(Ed448PrivateKey {
        pkey: openssl::pkey::PKey::generate_ed448()?,
    })
}

#[pyo3::prelude::pyfunction]
fn private_key_from_ptr(ptr: usize) -> Ed448PrivateKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    Ed448PrivateKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn public_key_from_ptr(ptr: usize) -> Ed448PublicKey {
    let pkey = unsafe { openssl::pkey::PKeyRef::from_ptr(ptr as *mut _) };
    Ed448PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::prelude::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed448PrivateKey> {
    let pkey =
        openssl::pkey::PKey::private_key_from_raw_bytes(data.as_bytes(), openssl::pkey::Id::ED448)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An Ed448 private key is 56 bytes long")
            })?;
    Ok(Ed448PrivateKey { pkey })
}

#[pyo3::prelude::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed448PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::ED448)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An Ed448 public key is 57 bytes long")
        })?;
    Ok(Ed448PublicKey { pkey })
}

#[pyo3::prelude::pymethods]
impl Ed448PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        Ok(pyo3::types::PyBytes::new_with(py, signer.len()?, |b| {
            let n = signer
                .sign_oneshot(b, data)
                .map_err(CryptographyError::from)?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn public_key(&self) -> CryptographyResult<Ed448PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(Ed448PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes(
                &raw_bytes,
                openssl::pkey::Id::ED448,
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
            true,
        )
    }
}

#[pyo3::prelude::pymethods]
impl Ed448PublicKey {
    fn verify(&self, signature: &[u8], data: &[u8]) -> CryptographyResult<()> {
        let valid = openssl::sign::Verifier::new_without_digest(&self.pkey)?
            .verify_oneshot(signature, data)?;

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
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true)
    }

    fn __richcmp__(
        &self,
        other: pyo3::PyRef<'_, Ed448PublicKey>,
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
    let m = pyo3::prelude::PyModule::new(py, "ed448")?;
    m.add_function(pyo3::wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(private_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(public_key_from_ptr, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_private_bytes, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(from_public_bytes, m)?)?;

    m.add_class::<Ed448PrivateKey>()?;
    m.add_class::<Ed448PublicKey>()?;

    Ok(m)
}
