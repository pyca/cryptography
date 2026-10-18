// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! X25519 on verified-garbage (`verified_garbage::x25519`).

use verified_garbage::x25519::PrivateKey;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};

const KEY_SIZE: usize = 32;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x25519")]
pub(crate) struct X25519PrivateKey {
    key: PrivateKey,
    public: [u8; KEY_SIZE],
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.x25519")]
pub(crate) struct X25519PublicKey {
    bytes: [u8; KEY_SIZE],
}

impl X25519PrivateKey {
    fn new(key: PrivateKey) -> Self {
        let public = key.public_key();
        X25519PrivateKey { key, public }
    }

    fn raw(&self) -> cryptography_key_parsing::raw::PrivateKey {
        cryptography_key_parsing::raw::PrivateKey::X25519(*self.key.as_bytes())
    }
}

impl X25519PublicKey {
    fn raw(&self) -> cryptography_key_parsing::raw::PublicKey {
        cryptography_key_parsing::raw::PublicKey::X25519(self.bytes)
    }
}

#[pyo3::pyfunction]
pub(crate) fn generate_key() -> CryptographyResult<X25519PrivateKey> {
    let key = PrivateKey::generate()
        .map_err(|_| CryptographyError::VerifiedGarbage("random number generator failed"))?;
    Ok(X25519PrivateKey::new(key))
}

/// The private key object of a parsed raw private key.
pub(crate) fn private_key_from_raw_bytes(bytes: &[u8; KEY_SIZE]) -> X25519PrivateKey {
    X25519PrivateKey::new(PrivateKey::from_bytes(bytes))
}

/// The public key object of a parsed raw public key.
pub(crate) fn public_key_from_raw_bytes(bytes: &[u8; KEY_SIZE]) -> X25519PublicKey {
    X25519PublicKey { bytes: *bytes }
}

// We don't reject all-zeros keys -- there's no threat model in which accepting
// them is a risk.
#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<X25519PrivateKey> {
    let bytes: &[u8; KEY_SIZE] = data.as_bytes().try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An X25519 private key is 32 bytes long")
    })?;
    Ok(private_key_from_raw_bytes(bytes))
}

#[pyo3::pyfunction]
pub(crate) fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<X25519PublicKey> {
    let bytes: &[u8; KEY_SIZE] = data.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An X25519 public key is 32 bytes long")
    })?;
    Ok(public_key_from_raw_bytes(bytes))
}

#[pyo3::pymethods]
impl X25519PrivateKey {
    fn exchange<'p>(
        &self,
        py: pyo3::Python<'p>,
        peer_public_key: &X25519PublicKey,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        // `diffie_hellman` rejects the all-zero shared secret of a
        // small-order peer key (RFC 7748 §6.1), as OpenSSL does.
        let shared = self
            .key
            .diffie_hellman(&peer_public_key.bytes)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Error computing shared key."))?;
        Ok(pyo3::types::PyBytes::new(py, &shared))
    }

    fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey { bytes: self.public }
    }

    fn private_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, self.key.as_bytes())
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
            false,
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
impl X25519PublicKey {
    fn public_bytes_raw<'p>(&self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.bytes)
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::raw_public_bytes(py, slf, &slf.get().raw(), encoding, format, false, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.bytes == other.bytes
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
pub(crate) mod x25519 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, X25519PrivateKey, X25519PublicKey,
    };
}

#[cfg(test)]
mod tests {
    use pyo3::types::PyBytesMethods;

    use super::{from_private_bytes, from_public_bytes, generate_key};
    use crate::backend::vg_test_vectors::{load_nist_vectors, read, unhex, Check};
    use crate::buf::CffiBuf;

    #[test]
    fn test_rfc7748_vectors() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let data = read("asymmetric/X25519/rfc7748.txt");
            let vectors = load_nist_vectors(&data, usize::MAX);
            assert!(!vectors.is_empty());
            for vector in &vectors {
                let scalar = unhex(&vector["input_scalar"]);
                let u = unhex(&vector["input_u"]);
                let expected = unhex(&vector["output_u"]);
                let key = from_private_bytes(CffiBuf::from_bytes(py, &scalar)).check();
                assert_eq!(key.private_bytes_raw(py).as_bytes(), &scalar[..]);
                let peer = from_public_bytes(&u).check();
                let shared = key.exchange(py, &peer).check();
                assert_eq!(shared.as_bytes(), &expected[..]);
            }
        });
    }

    #[test]
    fn test_exchange_agrees_and_rejects_zero() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let a = generate_key().check();
            let b = generate_key().check();
            let ab = a.exchange(py, &b.public_key()).check();
            let ba = b.exchange(py, &a.public_key()).check();
            assert_eq!(ab.as_bytes(), ba.as_bytes());
            // The point 0 has small order: the shared secret is all zero.
            let zero = from_public_bytes(&[0; 32]).check();
            assert!(a.exchange(py, &zero).is_err());
            assert!(from_private_bytes(CffiBuf::from_bytes(py, &[0; 31])).is_err());
            assert!(from_public_bytes(&[0; 33]).is_err());
        });
    }
}
