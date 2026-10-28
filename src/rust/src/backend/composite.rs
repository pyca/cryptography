// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::serialization::{Encoding, PrivateFormat, PublicFormat};
use crate::{exceptions, types};

// Composite ML-DSA, draft-ietf-lamps-pq-composite-sigs
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const MLDSA44_ED25519_LABEL: &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
const MLDSA44_SIGNATURE_LENGTH: usize = 2420;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const MAX_CONTEXT_BYTES: usize = 255;

// M' = Prefix || Label || len(ctx) || ctx || PH(M)
fn composite_message(
    label: &[u8],
    data: &[u8],
    context: Option<&CffiBuf<'_>>,
) -> CryptographyResult<Vec<u8>> {
    let ctx = context.map_or(&[][..], |c| c.as_bytes());
    if ctx.len() > MAX_CONTEXT_BYTES {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
        ));
    }
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha512(), data)?;

    let mut m_prime =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + ctx.len() + digest.len());
    m_prime.extend_from_slice(COMPOSITE_PREFIX);
    m_prime.extend_from_slice(label);
    // MAX_CONTEXT_BYTES guarantees this fits in a u8.
    m_prime.push(ctx.len() as u8);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(&digest);
    Ok(m_prime)
}

// NO-COVERAGE-START
#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.composite",
    name = "MLDSA44Ed25519PrivateKey"
)]
// NO-COVERAGE-END
pub(crate) struct MlDsa44Ed25519PrivateKey {
    mldsa_key: pyo3::Py<pyo3::PyAny>,
    ed25519_key: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pymethods]
impl MlDsa44Ed25519PrivateKey {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        mldsa_key: pyo3::Py<pyo3::PyAny>,
        ed25519_key: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<Self> {
        if !mldsa_key
            .bind(py)
            .is_instance(&types::MLDSA44_PRIVATE_KEY.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err("Expected MLDSA44PrivateKey for mldsa_key"),
            ));
        }
        if !ed25519_key
            .bind(py)
            .is_instance(&types::ED25519_PRIVATE_KEY.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected Ed25519PrivateKey for ed25519_key",
                ),
            ));
        }
        Ok(MlDsa44Ed25519PrivateKey {
            mldsa_key,
            ed25519_key,
        })
    }

    #[pyo3(signature = (data, context=None))]
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let m_prime = pyo3::types::PyBytes::new(
            py,
            &composite_message(MLDSA44_ED25519_LABEL, data.as_bytes(), context.as_ref())?,
        );

        let mldsa_sig = self
            .mldsa_key
            .bind(py)
            .call_method1(
                pyo3::intern!(py, "sign"),
                (
                    &m_prime,
                    pyo3::types::PyBytes::new(py, MLDSA44_ED25519_LABEL),
                ),
            )?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;
        let ed25519_sig = self
            .ed25519_key
            .bind(py)
            .call_method1(pyo3::intern!(py, "sign"), (&m_prime,))?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;

        let mldsa_sig = mldsa_sig.as_bytes();
        let ed25519_sig = ed25519_sig.as_bytes();
        Ok(pyo3::types::PyBytes::new_with(
            py,
            mldsa_sig.len() + ed25519_sig.len(),
            |buf| {
                buf[..mldsa_sig.len()].copy_from_slice(mldsa_sig);
                buf[mldsa_sig.len()..].copy_from_slice(ed25519_sig);
                Ok(())
            },
        )?)
    }

    // mldsa44_seed || ed25519_seed, as in OpenSSH and the composite
    // private key encoding of draft-ietf-lamps-pq-composite-sigs.
    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mldsa_raw = self
            .mldsa_key
            .bind(py)
            .call_method0(pyo3::intern!(py, "private_bytes_raw"))?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;
        let ed25519_raw = self
            .ed25519_key
            .bind(py)
            .call_method0(pyo3::intern!(py, "private_bytes_raw"))?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;
        Ok(pyo3::types::PyBytes::new(
            py,
            &[mldsa_raw.as_bytes(), ed25519_raw.as_bytes()].concat(),
        ))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if !encryption_algorithm.is_instance(&types::KEY_SERIALIZATION_ENCRYPTION.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Encryption algorithm must be a KeySerializationEncryption instance",
                ),
            ));
        }

        if encoding == Encoding::Raw || format == PrivateFormat::Raw {
            if encoding != Encoding::Raw
                || format != PrivateFormat::Raw
                || !encryption_algorithm.is_instance(&types::NO_ENCRYPTION.get(py)?)?
            {
                return Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                    "When using Raw both encoding and format must be Raw and encryption_algorithm must be NoEncryption()"
                )));
            }
            return slf.get().private_bytes_raw(py);
        }

        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
        ))
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> CryptographyResult<MlDsa44Ed25519PublicKey> {
        Ok(MlDsa44Ed25519PublicKey {
            mldsa_key: self
                .mldsa_key
                .bind(py)
                .call_method0(pyo3::intern!(py, "public_key"))?
                .unbind(),
            ed25519_key: self
                .ed25519_key
                .bind(py)
                .call_method0(pyo3::intern!(py, "public_key"))?
                .unbind(),
        })
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.composite",
    name = "MLDSA44Ed25519PublicKey"
)]
pub(crate) struct MlDsa44Ed25519PublicKey {
    mldsa_key: pyo3::Py<pyo3::PyAny>,
    ed25519_key: pyo3::Py<pyo3::PyAny>,
}

impl MlDsa44Ed25519PublicKey {
    fn raw_bytes(&self, py: pyo3::Python<'_>) -> CryptographyResult<Vec<u8>> {
        let mldsa_raw = self
            .mldsa_key
            .bind(py)
            .call_method0(pyo3::intern!(py, "public_bytes_raw"))?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;
        let ed25519_raw = self
            .ed25519_key
            .bind(py)
            .call_method0(pyo3::intern!(py, "public_bytes_raw"))?
            .extract::<pyo3::Bound<'_, pyo3::types::PyBytes>>()?;
        Ok([mldsa_raw.as_bytes(), ed25519_raw.as_bytes()].concat())
    }
}

#[pyo3::pymethods]
impl MlDsa44Ed25519PublicKey {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        mldsa_key: pyo3::Py<pyo3::PyAny>,
        ed25519_key: pyo3::Py<pyo3::PyAny>,
    ) -> CryptographyResult<Self> {
        if !mldsa_key
            .bind(py)
            .is_instance(&types::MLDSA44_PUBLIC_KEY.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err("Expected MLDSA44PublicKey for mldsa_key"),
            ));
        }
        if !ed25519_key
            .bind(py)
            .is_instance(&types::ED25519_PUBLIC_KEY.get(py)?)?
        {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err("Expected Ed25519PublicKey for ed25519_key"),
            ));
        }
        Ok(MlDsa44Ed25519PublicKey {
            mldsa_key,
            ed25519_key,
        })
    }

    #[pyo3(signature = (signature, data, context=None))]
    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let signature = signature.as_bytes();
        if signature.len() != MLDSA44_SIGNATURE_LENGTH + ED25519_SIGNATURE_LENGTH {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }
        let (mldsa_sig, ed25519_sig) = signature.split_at(MLDSA44_SIGNATURE_LENGTH);
        let m_prime = pyo3::types::PyBytes::new(
            py,
            &composite_message(MLDSA44_ED25519_LABEL, data.as_bytes(), context.as_ref())?,
        );

        // Both component signatures must be valid; each verify() raises
        // InvalidSignature otherwise.
        self.mldsa_key.bind(py).call_method1(
            pyo3::intern!(py, "verify"),
            (
                pyo3::types::PyBytes::new(py, mldsa_sig),
                &m_prime,
                pyo3::types::PyBytes::new(py, MLDSA44_ED25519_LABEL),
            ),
        )?;
        self.ed25519_key.bind(py).call_method1(
            pyo3::intern!(py, "verify"),
            (pyo3::types::PyBytes::new(py, ed25519_sig), &m_prime),
        )?;
        Ok(())
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new(py, &self.raw_bytes(py)?))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: Encoding,
        format: PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if encoding == Encoding::Raw || format == PublicFormat::Raw {
            if encoding != Encoding::Raw || format != PublicFormat::Raw {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "When using Raw both encoding and format must be Raw",
                    ),
                ));
            }
            return slf.get().public_bytes_raw(py);
        }

        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
        ))
    }

    fn __eq__(
        &self,
        py: pyo3::Python<'_>,
        other: pyo3::PyRef<'_, Self>,
    ) -> CryptographyResult<bool> {
        Ok(self.raw_bytes(py)? == other.raw_bytes(py)?)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod composite {
    #[pymodule_export]
    use super::{MlDsa44Ed25519PrivateKey, MlDsa44Ed25519PublicKey};
}
