// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Ed448 on verified-garbage (`verified_garbage::ed448`).

use verified_garbage::ed448::{SigningKey, VerifyingKey};

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const KEY_SIZE: usize = 57;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
pub(crate) struct Ed448PrivateKey {
    key: SigningKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed448")]
pub(crate) struct Ed448PublicKey {
    key: VerifyingKey,
}

impl Ed448PrivateKey {
    fn raw(&self) -> cryptography_key_parsing::raw::PrivateKey {
        cryptography_key_parsing::raw::PrivateKey::Ed448(*self.key.seed())
    }
}

impl Ed448PublicKey {
    fn raw(&self) -> cryptography_key_parsing::raw::PublicKey {
        cryptography_key_parsing::raw::PublicKey::Ed448(*self.key.as_bytes())
    }
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<Ed448PrivateKey> {
    let mut seed = [0u8; KEY_SIZE];
    getrandom::fill(&mut seed)
        .map_err(|_| CryptographyError::VerifiedGarbage("random number generator failed"))?;
    let key = SigningKey::from_seed(&seed);
    seed.fill(0);
    std::hint::black_box(&seed);
    Ok(Ed448PrivateKey { key })
}

/// The private key object of a parsed raw private key.
pub(crate) fn private_key_from_raw_bytes(seed: &[u8; KEY_SIZE]) -> Ed448PrivateKey {
    Ed448PrivateKey {
        key: SigningKey::from_seed(seed),
    }
}

/// The public key object of a parsed raw public key.
pub(crate) fn public_key_from_raw_bytes(bytes: &[u8; KEY_SIZE]) -> Ed448PublicKey {
    Ed448PublicKey {
        key: VerifyingKey::from_bytes(bytes),
    }
}

// We don't reject all-zeros keys -- there's no threat model in which accepting
// them is a risk.
#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed448PrivateKey> {
    let seed: &[u8; KEY_SIZE] = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed448 private key is 57 bytes long")
    })?;
    Ok(private_key_from_raw_bytes(seed))
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed448PublicKey> {
    let bytes: &[u8; KEY_SIZE] = data.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed448 public key is 57 bytes long")
    })?;
    Ok(public_key_from_raw_bytes(bytes))
}

#[pyo3::pymethods]
impl Ed448PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        let sig = py.detach(|| self.key.sign(data_bytes));
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> Ed448PublicKey {
        Ed448PublicKey {
            key: *self.key.verifying_key(),
        }
    }

    fn private_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, self.key.seed())
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::raw_private_bytes(
            py,
            slf,
            &slf.get().raw(),
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
        let sig_bytes = signature.as_bytes();
        let data_bytes = data.as_bytes();
        py.detach(|| self.key.verify(data_bytes, sig_bytes))
            .map_err(|_| CryptographyError::from(exceptions::InvalidSignature::new_err(())))
    }

    fn public_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, self.key.as_bytes())
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::raw_public_bytes(py, slf, &slf.get().raw(), encoding, format, true, true)
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
pub(crate) mod ed448 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, Ed448PrivateKey, Ed448PublicKey,
    };
}

#[cfg(test)]
mod tests {
    use pyo3::types::PyBytesMethods;

    use super::{from_private_bytes, from_public_bytes, generate_key};
    use crate::backend::vg_test_vectors::{load_nist_vectors, read, unhex, Check};
    use crate::buf::CffiBuf;

    #[test]
    fn test_rfc8032_vectors() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let data = read("asymmetric/Ed448/rfc8032.txt");
            let vectors = load_nist_vectors(&data, usize::MAX);
            assert!(!vectors.is_empty());
            // cryptography does not expose Ed448 contexts.
            for vector in vectors.iter().filter(|v| !v.contains_key("context")) {
                let sk = unhex(&vector["secret"]);
                let pk = unhex(&vector["public"]);
                let msg = unhex(&vector["message"]);
                let sig = unhex(&vector["signature"]);

                let key = from_private_bytes(CffiBuf::from_bytes(py, &sk)).check();
                assert_eq!(key.private_bytes_raw(py).as_bytes(), &sk[..]);
                let computed = key.sign(py, CffiBuf::from_bytes(py, &msg)).check();
                assert_eq!(computed.as_bytes(), &sig[..]);
                assert_eq!(key.public_key().public_bytes_raw(py).as_bytes(), &pk[..]);

                let loaded = from_public_bytes(&pk).check();
                loaded
                    .verify(
                        py,
                        CffiBuf::from_bytes(py, &sig),
                        CffiBuf::from_bytes(py, &msg),
                    )
                    .check();
                let mut bad = msg.clone();
                bad.push(0);
                assert!(loaded
                    .verify(
                        py,
                        CffiBuf::from_bytes(py, &sig),
                        CffiBuf::from_bytes(py, &bad),
                    )
                    .is_err());
                assert!(loaded
                    .verify(
                        py,
                        CffiBuf::from_bytes(py, &sig[..64]),
                        CffiBuf::from_bytes(py, &msg),
                    )
                    .is_err());
            }
        });
    }

    #[test]
    fn test_generate_and_lengths() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let key = generate_key().check();
            let msg = b"test data";
            let sig = key.sign(py, CffiBuf::from_bytes(py, msg)).check();
            key.public_key()
                .verify(
                    py,
                    CffiBuf::from_bytes(py, sig.as_bytes()),
                    CffiBuf::from_bytes(py, msg),
                )
                .check();
            assert!(from_private_bytes(CffiBuf::from_bytes(py, &[0; 32])).is_err());
            assert!(from_public_bytes(&[0; 32]).is_err());
        });
    }
}
