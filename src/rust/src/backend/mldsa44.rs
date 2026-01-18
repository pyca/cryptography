// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa44")]
pub(crate) struct MlDsa44PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa44")]
pub(crate) struct MlDsa44PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<MlDsa44PrivateKey> {
    Ok(MlDsa44PrivateKey {
        pkey: openssl::pkey::PKey::generate_ml_dsa(openssl::pkey_ml_dsa::Variant::MlDsa44)?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa44PrivateKey {
    MlDsa44PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa44PublicKey {
    MlDsa44PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PrivateKey> {
    let pkey = openssl::pkey::PKey::private_key_from_seed(
        openssl::pkey_ml_dsa::Variant::MlDsa44,
        data.as_bytes(),
    )
    .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-DSA-44 private key"))?;
    Ok(MlDsa44PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<MlDsa44PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes_ex(data, "ML-DSA-44")
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid ML-DSA-44 public key"))?;
    Ok(MlDsa44PublicKey { pkey })
}

#[pyo3::pymethods]
impl MlDsa44PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        let len = signer.len()?;
        Ok(pyo3::types::PyBytes::new_with(py, len, |b| {
            let n = signer
                .sign_oneshot(b, data.as_bytes())
                .map_err(CryptographyError::from)?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    fn sign_with_context<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let signature = openssl::pkey_ml_dsa::sign_with_context(
            &self.pkey,
            openssl::pkey_ml_dsa::Variant::MlDsa44,
            data.as_bytes(),
            context.as_bytes(),
        )?;
        Ok(pyo3::types::PyBytes::new(py, &signature))
    }

    fn public_key(&self) -> CryptographyResult<MlDsa44PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(MlDsa44PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes_ex(&raw_bytes, "ML-DSA-44")?,
        })
    }

    fn seed_bytes<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // Serialize to DER to extract the seed (RFC 9881 Section 6)
        // The seed is stored in the privateKey OCTET STRING as [0] IMPLICIT OCTET STRING (SIZE (32))
        let der = self.pkey.private_key_to_der()?;

        // The seed is in the last 34 bytes of the DER encoding
        // Structure: ... OCTET STRING { [0] tag (0x80) + length (0x20) + 32-byte seed }
        if der.len() < 34 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Invalid ML-DSA-44 private key DER encoding",
                ),
            ));
        }

        // Skip the tag (0x80) and length (0x20) bytes to get the 32-byte seed
        let seed = &der[der.len() - 32..];
        Ok(pyo3::types::PyBytes::new(py, seed))
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

    fn verify_with_context(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let valid = openssl::pkey_ml_dsa::verify_with_context(
            &self.pkey,
            openssl::pkey_ml_dsa::Variant::MlDsa44,
            data.as_bytes(),
            signature.as_bytes(),
            context.as_bytes(),
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

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mldsa44 {
    #[pymodule_export]
    use super::{
        from_public_bytes, from_seed_bytes, generate_key, MlDsa44PrivateKey, MlDsa44PublicKey,
    };
}
