// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

// ML-DSA-44 (OpenSSL 3.5+)

#[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa")]
pub(crate) struct MlDsa44PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa")]
pub(crate) struct MlDsa44PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
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
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
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

#[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
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

// ML-DSA-65 (AWS-LC)

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
const MAX_CONTEXT_BYTES: usize = 255;

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa")]
pub(crate) struct MlDsa65PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.mldsa")]
pub(crate) struct MlDsa65PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
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
            pkey: cryptography_openssl::mldsa::new_raw_public_key(&raw_bytes)?,
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

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
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

// Unified constructor functions — use #[cfg] internally to return the
// appropriate ML-DSA variant for the active backend, following the same
// pattern as private_key_from_pkey / public_key_from_pkey below.

#[pyo3::pyfunction]
fn generate_key<'p>(py: pyo3::Python<'p>) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    use pyo3::IntoPyObject;

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    {
        return Ok(MlDsa44PrivateKey {
            pkey: openssl::pkey::PKey::generate_ml_dsa(openssl::pkey_ml_dsa::Variant::MlDsa44)?,
        }
        .into_pyobject(py)?
        .into_any());
    }
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    {
        let mut seed = [0u8; cryptography_openssl::mldsa::MLDSA65_SEED_BYTES];
        cryptography_openssl::rand::rand_bytes(&mut seed)?;
        let pkey = cryptography_openssl::mldsa::new_raw_private_key(&seed)?;
        return Ok(MlDsa65PrivateKey { pkey }.into_pyobject(py)?.into_any());
    }
    #[allow(unreachable_code)]
    Err(CryptographyError::from(
        crate::exceptions::UnsupportedAlgorithm::new_err("Unsupported ML-DSA backend."),
    ))
}

#[pyo3::pyfunction]
fn from_seed_bytes<'p>(
    py: pyo3::Python<'p>,
    data: CffiBuf<'_>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    use pyo3::IntoPyObject;

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    {
        let pkey = openssl::pkey::PKey::private_key_from_seed(
            openssl::pkey_ml_dsa::Variant::MlDsa44,
            data.as_bytes(),
        )
        .map_err(|_| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "An ML-DSA-44 seed is 32 bytes long",
            ))
        })?;
        return Ok(MlDsa44PrivateKey { pkey }.into_pyobject(py)?.into_any());
    }
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    {
        let pkey =
            cryptography_openssl::mldsa::new_raw_private_key(data.as_bytes()).map_err(|_| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-65 seed is 32 bytes long",
                ))
            })?;
        return Ok(MlDsa65PrivateKey { pkey }.into_pyobject(py)?.into_any());
    }
    #[allow(unreachable_code)]
    Err(CryptographyError::from(
        crate::exceptions::UnsupportedAlgorithm::new_err("Unsupported ML-DSA backend."),
    ))
}

#[pyo3::pyfunction]
fn from_public_bytes<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    use pyo3::IntoPyObject;

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    {
        let pkey =
            openssl::pkey::PKey::public_key_from_raw_bytes_ex(data, "ML-DSA-44").map_err(|_| {
                CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "Invalid ML-DSA-44 public key",
                ))
            })?;
        return Ok(MlDsa44PublicKey { pkey }.into_pyobject(py)?.into_any());
    }
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    {
        let pkey = cryptography_openssl::mldsa::new_raw_public_key(data).map_err(|_| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "An ML-DSA-65 public key is 1952 bytes long",
            ))
        })?;
        return Ok(MlDsa65PublicKey { pkey }.into_pyobject(py)?.into_any());
    }
    #[allow(unreachable_code)]
    Err(CryptographyError::from(
        crate::exceptions::UnsupportedAlgorithm::new_err("Unsupported ML-DSA backend."),
    ))
}

pub(crate) fn private_key_from_pkey<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    use pyo3::IntoPyObject;

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    {
        return Ok(MlDsa44PrivateKey {
            pkey: pkey.to_owned(),
        }
        .into_pyobject(py)?
        .into_any());
    }
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    {
        return Ok(MlDsa65PrivateKey {
            pkey: pkey.to_owned(),
        }
        .into_pyobject(py)?
        .into_any());
    }
    #[allow(unreachable_code)]
    Err(CryptographyError::from(
        crate::exceptions::UnsupportedAlgorithm::new_err("Unsupported ML-DSA backend."),
    ))
}

pub(crate) fn public_key_from_pkey<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    use pyo3::IntoPyObject;

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    {
        return Ok(MlDsa44PublicKey {
            pkey: pkey.to_owned(),
        }
        .into_pyobject(py)?
        .into_any());
    }
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    {
        return Ok(MlDsa65PublicKey {
            pkey: pkey.to_owned(),
        }
        .into_pyobject(py)?
        .into_any());
    }
    #[allow(unreachable_code)]
    Err(CryptographyError::from(
        crate::exceptions::UnsupportedAlgorithm::new_err("Unsupported ML-DSA backend."),
    ))
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mldsa {
    #[pymodule_export]
    use super::{from_public_bytes, from_seed_bytes, generate_key};

    #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
    #[pymodule_export]
    use super::{MlDsa44PrivateKey, MlDsa44PublicKey};

    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    #[pymodule_export]
    use super::{MlDsa65PrivateKey, MlDsa65PublicKey};
}
