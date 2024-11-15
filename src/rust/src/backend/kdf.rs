// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
use pyo3::types::PyBytesMethods;

use crate::backend::hashes;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyfunction]
pub(crate) fn derive_pbkdf2_hmac<'p>(
    py: pyo3::Python<'p>,
    key_material: CffiBuf<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    salt: &[u8],
    iterations: usize,
    length: usize,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let md = hashes::message_digest_from_algorithm(py, algorithm)?;

    Ok(pyo3::types::PyBytes::new_with(py, length, |b| {
        openssl::pkcs5::pbkdf2_hmac(key_material.as_bytes(), salt, iterations, md, b).unwrap();
        Ok(())
    })?)
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.scrypt")]
struct Scrypt {
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    salt: pyo3::Py<pyo3::types::PyBytes>,
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    length: usize,
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    n: u64,
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    r: u64,
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    p: u64,

    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    used: bool,
}

#[pyo3::pymethods]
impl Scrypt {
    #[new]
    #[pyo3(signature = (salt, length, n, r, p, backend=None))]
    fn new(
        salt: pyo3::Py<pyo3::types::PyBytes>,
        length: usize,
        n: u64,
        r: u64,
        p: u64,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        cfg_if::cfg_if! {
            if #[cfg(CRYPTOGRAPHY_IS_LIBRESSL)] {
                _ = salt;
                _ = length;
                _ = n;
                _ = r;
                _ = p;

                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err(
                        "This version of OpenSSL does not support scrypt"
                    ),
                ))
            } else {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err(
                            "This version of OpenSSL does not support scrypt"
                        ),
                    ));
                }

                if n < 2 || (n & (n - 1)) != 0 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "n must be greater than 1 and be a power of 2."
                        ),
                    ));
                }
                if r < 1 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "r must be greater than or equal to 1."
                        ),
                    ));
                }
                if p < 1 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "p must be greater than or equal to 1."
                        ),
                    ));
                }

                Ok(Scrypt{
                    salt,
                    length,
                    n,
                    r,
                    p,
                    used: false,
                })
            }
        }
    }

    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        Ok(pyo3::types::PyBytes::new_with(py, self.length, |b| {
            openssl::pkcs5::scrypt(key_material.as_bytes(), self.salt.as_bytes(py), self.n, self.r, self.p, (usize::MAX / 2).try_into().unwrap(), b).map_err(|_| {
                // memory required formula explained here:
                // https://blog.filippo.io/the-scrypt-parameters/
                let min_memory = 128 * self.n * self.r / (1024 * 1024);
                pyo3::exceptions::PyMemoryError::new_err(format!(
                    "Not enough memory to derive key. These parameters require {min_memory}MB of memory."
                ))
            })
        })?)
    }

    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let actual = self.derive(py, key_material)?;
        let actual_bytes = actual.as_bytes();
        let expected_bytes = expected_key.as_bytes();

        if actual_bytes.len() != expected_bytes.len()
            || !openssl::memcmp::eq(actual_bytes, expected_bytes)
        {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.argon2")]
struct Argon2id {
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    salt: pyo3::Py<pyo3::types::PyBytes>,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    length: usize,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    iterations: u32,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    lanes: u32,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    memory_cost: u32,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    ad: Option<pyo3::Py<pyo3::types::PyBytes>>,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    secret: Option<pyo3::Py<pyo3::types::PyBytes>>,
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    used: bool,
}

#[pyo3::pymethods]
impl Argon2id {
    #[new]
    #[pyo3(signature = (salt, length, iterations, lanes, memory_cost, ad=None, secret=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: pyo3::Python<'_>,
        salt: pyo3::Py<pyo3::types::PyBytes>,
        length: usize,
        iterations: u32,
        lanes: u32,
        memory_cost: u32,
        ad: Option<pyo3::Py<pyo3::types::PyBytes>>,
        secret: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> CryptographyResult<Self> {
        cfg_if::cfg_if! {
            if #[cfg(not(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER))] {
                _ = py;
                _ = salt;
                _ = length;
                _ = iterations;
                _ = lanes;
                _ = memory_cost;
                _ = ad;
                _ = secret;

                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err(
                        "This version of OpenSSL does not support argon2id"
                    ),
                ))
            } else {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err(
                            "This version of OpenSSL does not support argon2id"
                        ),
                    ));
                }

                if salt.as_bytes(py).len() < 8 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "salt must be at least 8 bytes"
                        ),
                    ));
                }
                if length < 4 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "length must be greater than or equal to 4."
                        ),
                    ));
                }
                if iterations < 1 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "iterations must be greater than or equal to 1."
                        ),
                    ));
                }
                if lanes < 1 {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "lanes must be greater than or equal to 1."
                        ),
                    ));
                }

                if memory_cost / 8 < lanes {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyValueError::new_err(
                            "memory_cost must be an integer >= 8 * lanes."
                        ),
                    ));
                }


                Ok(Argon2id{
                    salt,
                    length,
                    iterations,
                    lanes,
                    memory_cost,
                    ad,
                    secret,
                    used: false,
                })
            }
        }
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |b| {
            openssl::kdf::argon2id(
                None,
                key_material.as_bytes(),
                self.salt.as_bytes(py),
                self.ad.as_ref().map(|ad| ad.as_bytes(py)),
                self.secret.as_ref().map(|secret| secret.as_bytes(py)),
                self.iterations,
                self.lanes,
                self.memory_cost,
                b,
            )
            .map_err(CryptographyError::from)?;
            Ok(())
        })?)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let actual = self.derive(py, key_material)?;
        let actual_bytes = actual.as_bytes();
        let expected_bytes = expected_key.as_bytes();

        if actual_bytes.len() != expected_bytes.len()
            || !openssl::memcmp::eq(actual_bytes, expected_bytes)
        {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }
}

#[pyo3::pymodule]
pub(crate) mod kdf {
    #[pymodule_export]
    use super::derive_pbkdf2_hmac;
    #[pymodule_export]
    use super::Argon2id;
    #[pymodule_export]
    use super::Scrypt;
}
