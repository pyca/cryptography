// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Ed25519 on verified-garbage (`verified_garbage::ed25519`).

use verified_garbage::ed25519::{SigningKey, VerifyingKey};

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const KEY_SIZE: usize = 32;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PrivateKey {
    key: SigningKey,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PublicKey {
    key: VerifyingKey,
}

impl Ed25519PrivateKey {
    fn raw(&self) -> cryptography_key_parsing::raw::PrivateKey {
        cryptography_key_parsing::raw::PrivateKey::Ed25519(*self.key.seed())
    }
}

impl Ed25519PublicKey {
    fn raw(&self) -> cryptography_key_parsing::raw::PublicKey {
        cryptography_key_parsing::raw::PublicKey::Ed25519(*self.key.as_bytes())
    }
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<Ed25519PrivateKey> {
    let mut seed = [0u8; KEY_SIZE];
    getrandom::fill(&mut seed)
        .map_err(|_| CryptographyError::VerifiedGarbage("random number generator failed"))?;
    let key = SigningKey::from_seed(&seed);
    seed.fill(0);
    std::hint::black_box(&seed);
    Ok(Ed25519PrivateKey { key })
}

/// The private key object of a parsed raw private key.
pub(crate) fn private_key_from_raw_bytes(seed: &[u8; KEY_SIZE]) -> Ed25519PrivateKey {
    Ed25519PrivateKey {
        key: SigningKey::from_seed(seed),
    }
}

/// The public key object of a parsed raw public key.
pub(crate) fn public_key_from_raw_bytes(bytes: &[u8; KEY_SIZE]) -> Ed25519PublicKey {
    Ed25519PublicKey {
        key: VerifyingKey::from_bytes(bytes),
    }
}

// We don't reject all-zeros keys -- there's no threat model in which accepting
// them is a risk.
#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed25519PrivateKey> {
    let seed: &[u8; KEY_SIZE] = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed25519 private key is 32 bytes long")
    })?;
    Ok(private_key_from_raw_bytes(seed))
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed25519PublicKey> {
    let bytes: &[u8; KEY_SIZE] = data.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed25519 public key is 32 bytes long")
    })?;
    Ok(public_key_from_raw_bytes(bytes))
}

#[pyo3::pymethods]
impl Ed25519PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data_bytes = data.as_bytes();
        let sig = py.detach(|| self.key.sign(data_bytes));
        Ok(pyo3::types::PyBytes::new(py, &sig))
    }

    fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
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
impl Ed25519PublicKey {
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
pub(crate) mod ed25519 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, Ed25519PrivateKey, Ed25519PublicKey,
    };
}

#[cfg(test)]
mod tests {
    use pyo3::types::PyBytesMethods;

    use super::{from_private_bytes, from_public_bytes, generate_key};
    use crate::backend::vg_test_vectors::{read, unhex, Check};
    use crate::buf::CffiBuf;

    #[test]
    fn test_sign_input_vectors() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            // Each line: sk || pk : pk : message : signature || message :
            let data = read("asymmetric/Ed25519/sign.input");
            for line in data.lines().take(64) {
                let fields: Vec<&str> = line.split(':').collect();
                let sk = unhex(&fields[0][..64]);
                let pk = unhex(fields[1]);
                let msg = unhex(fields[2]);
                let sig = unhex(&fields[3][..128]);

                let key = from_private_bytes(CffiBuf::from_bytes(py, &sk)).check();
                assert_eq!(key.private_bytes_raw(py).as_bytes(), &sk[..]);
                let computed = key.sign(py, CffiBuf::from_bytes(py, &msg)).check();
                assert_eq!(computed.as_bytes(), &sig[..]);

                let public = key.public_key();
                assert_eq!(public.public_bytes_raw(py).as_bytes(), &pk[..]);
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
                        CffiBuf::from_bytes(py, &sig[..63]),
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
            let a = generate_key().check();
            let b = generate_key().check();
            assert_ne!(
                a.private_bytes_raw(py).as_bytes(),
                b.private_bytes_raw(py).as_bytes()
            );
            assert!(from_private_bytes(CffiBuf::from_bytes(py, &[0; 31])).is_err());
            assert!(from_public_bytes(&[0; 33]).is_err());
        });
    }
}
