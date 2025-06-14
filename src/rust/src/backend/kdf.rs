// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use base64::engine::general_purpose::STANDARD_NO_PAD;
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use base64::engine::Engine;
use cryptography_crypto::constant_time;
use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::hashes;
use crate::backend::hmac::Hmac;
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

        if !constant_time::bytes_eq(actual_bytes, expected_bytes) {
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

        if !constant_time::bytes_eq(actual_bytes, expected_bytes) {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_phc_encoded<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyString>> {
        let derived_key = self.derive(py, key_material)?;
        let salt_bytes = self.salt.as_bytes(py);

        let salt_b64 = STANDARD_NO_PAD.encode(salt_bytes);
        let hash_b64 = STANDARD_NO_PAD.encode(derived_key.as_bytes());

        // Format the PHC string
        let phc_string = format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            self.memory_cost, self.iterations, self.lanes, salt_b64, hash_b64
        );

        Ok(pyo3::types::PyString::new(py, &phc_string))
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    #[staticmethod]
    #[pyo3(signature = (key_material, phc_encoded, secret=None))]
    fn verify_phc_encoded(
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        phc_encoded: &str,
        secret: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> CryptographyResult<()> {
        let parts: Vec<_> = phc_encoded.split('$').collect();

        if parts.len() != 6 || !parts[0].is_empty() || parts[1] != "argon2id" {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid PHC string format.",
            )));
        }

        if parts[2] != "v=19" {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid version in PHC string.",
            )));
        }

        // Parse parameters
        let param_parts: Vec<&str> = parts[3].split(',').collect();
        if param_parts.len() != 3 {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid parameters in PHC string.",
            )));
        }

        // Check parameters are in correct order: m, t, p
        if !param_parts[0].starts_with("m=")
            || !param_parts[1].starts_with("t=")
            || !param_parts[2].starts_with("p=")
        {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Parameters must be in order: m, t, p.",
            )));
        }

        // Parse memory cost (m)
        let memory_cost = param_parts[0][2..].parse::<u32>().map_err(|_| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid memory cost in PHC string.",
            ))
        })?;

        // Parse iterations (t)
        let iterations = param_parts[1][2..].parse::<u32>().map_err(|_| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid iterations in PHC string.",
            ))
        })?;

        // Parse lanes/parallelism (p)
        let lanes = param_parts[2][2..].parse::<u32>().map_err(|_| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid parallelism in PHC string.",
            ))
        })?;

        let salt_bytes = STANDARD_NO_PAD.decode(parts[4]).map_err(|_| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid base64 salt in PHC string.",
            ))
        })?;

        let hash_bytes = STANDARD_NO_PAD.decode(parts[5]).map_err(|_| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid base64 hash in PHC string.",
            ))
        })?;

        let salt = pyo3::types::PyBytes::new(py, &salt_bytes);
        let mut argon2 = Argon2id::new(
            py,
            salt.into(),
            hash_bytes.len(),
            iterations,
            lanes,
            memory_cost,
            None,
            secret,
        )?;

        let derived_key = argon2.derive(py, key_material)?;
        let derived_bytes = derived_key.as_bytes();

        if !constant_time::bytes_eq(derived_bytes, &hash_bytes) {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.hkdf", name = "HKDF")]
struct Hkdf {
    algorithm: pyo3::Py<pyo3::PyAny>,
    salt: pyo3::Py<pyo3::types::PyBytes>,
    info: Option<pyo3::Py<pyo3::types::PyBytes>>,
    length: usize,
    used: bool,
}

#[pyo3::pymethods]
impl Hkdf {
    #[new]
    #[pyo3(signature = (algorithm, length, salt=None, info=None, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        length: usize,
        salt: Option<pyo3::Py<pyo3::types::PyBytes>>,
        info: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        let digest_size = algorithm
            .bind(py)
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let max_length = 255usize.checked_mul(digest_size).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "Digest size too large, would cause overflow in max length calculation",
            )
        })?;
        if length > max_length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Cannot derive keys larger than {max_length} octets."
                )),
            ));
        }

        let salt = if let Some(salt) = salt {
            salt
        } else {
            pyo3::types::PyBytes::new_with(py, digest_size, |_| Ok(()))?.into()
        };

        Ok(Hkdf {
            algorithm,
            salt,
            info,
            length,
            used: false,
        })
    }

    fn _extract<'p>(
        &self,
        py: pyo3::Python<'p>,
        key_material: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let algorithm_bound = self.algorithm.bind(py);
        let mut hmac = Hmac::new_bytes(py, self.salt.as_bytes(py), algorithm_bound)?;
        hmac.update_bytes(key_material)?;
        hmac.finalize(py)
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        let prk = self._extract(py, key_material.as_bytes())?;
        let mut hkdf_expand = HkdfExpand::new(
            py,
            self.algorithm.clone_ref(py),
            self.length,
            self.info.as_ref().map(|i| i.clone_ref(py)),
            None,
        )?;
        let prk_bytes = prk.as_bytes();
        let cffi_buf = CffiBuf::from_bytes(py, prk_bytes);
        hkdf_expand.derive(py, cffi_buf)
    }

    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let actual = self.derive(py, key_material)?;
        let actual_bytes = actual.as_bytes();
        let expected_bytes = expected_key.as_bytes();

        if !constant_time::bytes_eq(actual_bytes, expected_bytes) {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.hkdf",
    name = "HKDFExpand"
)]
struct HkdfExpand {
    algorithm: pyo3::Py<pyo3::PyAny>,
    info: pyo3::Py<pyo3::types::PyBytes>,
    length: usize,
    used: bool,
}

#[pyo3::pymethods]
impl HkdfExpand {
    #[new]
    #[pyo3(signature = (algorithm, length, info, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        length: usize,
        info: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        let digest_size = algorithm
            .bind(py)
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let max_length = 255usize.checked_mul(digest_size).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "Digest size too large, would cause overflow in max length calculation",
            )
        })?;
        if length > max_length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Cannot derive keys larger than {max_length} octets."
                )),
            ));
        }

        let info = if let Some(info) = info {
            info
        } else {
            pyo3::types::PyBytes::new(py, b"").into()
        };

        Ok(HkdfExpand {
            algorithm,
            info,
            length,
            used: false,
        })
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        let algorithm_bound = self.algorithm.bind(py);
        let h_prime = Hmac::new_bytes(py, key_material.as_bytes(), algorithm_bound)?;
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            let mut pos = 0usize;
            let mut counter = 0u8;

            while pos < self.length {
                counter += 1;
                let mut h = h_prime.copy(py)?;

                let start = pos.saturating_sub(digest_size);
                h.update_bytes(&output[start..pos])?;

                h.update_bytes(self.info.as_bytes(py))?;
                h.update_bytes(&[counter])?;

                let block = h.finalize(py)?;
                let block_bytes = block.as_bytes();

                let copy_len = (self.length - pos).min(digest_size);
                output[pos..pos + copy_len].copy_from_slice(&block_bytes[..copy_len]);
                pos += copy_len;
            }

            Ok(())
        })?)
    }

    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let actual = self.derive(py, key_material)?;
        let actual_bytes = actual.as_bytes();
        let expected_bytes = expected_key.as_bytes();

        if !constant_time::bytes_eq(actual_bytes, expected_bytes) {
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
    use super::Hkdf;
    #[pymodule_export]
    use super::HkdfExpand;
    #[pymodule_export]
    use super::Scrypt;
}
