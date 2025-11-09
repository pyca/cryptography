// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use base64::engine::general_purpose::STANDARD_NO_PAD;
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use base64::engine::Engine;
use cryptography_crypto::constant_time;
use pyo3::types::{PyAnyMethods, PyBytesMethods, PyTypeMethods};

use crate::asn1::py_uint_to_be_bytes_with_length;
use crate::backend::hmac::Hmac;
use crate::backend::{cmac, hashes};
use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use crate::types;

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.pbkdf2",
    name = "PBKDF2HMAC"
)]
// NO-COVERAGE-END
struct Pbkdf2Hmac {
    md: openssl::hash::MessageDigest,
    salt: pyo3::Py<pyo3::types::PyBytes>,
    iterations: usize,
    length: usize,
    used: bool,
}

impl Pbkdf2Hmac {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        openssl::pkcs5::pbkdf2_hmac(
            key_material,
            self.salt.as_bytes(py),
            self.iterations,
            self.md,
            output,
        )
        .unwrap();

        Ok(self.length)
    }
}

#[pyo3::pymethods]
impl Pbkdf2Hmac {
    #[new]
    #[pyo3(signature = (algorithm, length, salt, iterations, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        length: usize,
        salt: pyo3::Py<pyo3::types::PyBytes>,
        iterations: usize,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;
        let md = hashes::message_digest_from_algorithm(py, &algorithm)?;

        Ok(Pbkdf2Hmac {
            md,
            salt,
            iterations,
            length,
            used: false,
        })
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

impl Scrypt {
    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        openssl::pkcs5::scrypt(
            key_material,
            self.salt.as_bytes(py),
            self.n,
            self.r,
            self.p,
            (usize::MAX / 2).try_into().unwrap(),
            output,
        )
        .map_err(|_| {
            // memory required formula explained here:
            // https://blog.filippo.io/the-scrypt-parameters/
            let min_memory = 128 * self.n * self.r / (1024 * 1024);
            CryptographyError::from(pyo3::exceptions::PyMemoryError::new_err(format!(
                "Not enough memory to derive key. These parameters require {min_memory}MB of memory."
            )))
        })?;

        Ok(self.length)
    }
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
    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    #[cfg(not(CRYPTOGRAPHY_IS_LIBRESSL))]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
            Ok(())
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

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
#[derive(Debug, PartialEq)]
enum Argon2Variant {
    Argon2d,
    Argon2i,
    Argon2id,
}

struct BaseArgon2 {
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

impl BaseArgon2 {
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        variant: &Argon2Variant,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let derive_fn = match &variant {
            Argon2Variant::Argon2d => openssl::kdf::argon2d,
            Argon2Variant::Argon2i => openssl::kdf::argon2i,
            Argon2Variant::Argon2id => openssl::kdf::argon2id,
        };

        (derive_fn)(
            None,
            key_material,
            self.salt.as_bytes(py),
            self.ad.as_ref().map(|ad| ad.as_bytes(py)),
            self.secret.as_ref().map(|secret| secret.as_bytes(py)),
            self.iterations,
            self.lanes,
            self.memory_cost,
            output,
        )
        .map_err(CryptographyError::from)?;

        Ok(self.length)
    }

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
                        "This version of OpenSSL does not support argon2"
                    ),
                ))
            } else {
                if cryptography_openssl::fips::is_enabled() {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err(
                            "This version of OpenSSL does not support argon2"
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

                Ok(Self{
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
        variant: &Argon2Variant,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, variant, key_material.as_bytes(), output)?;
            Ok(())
        })?)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        variant: &Argon2Variant,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let actual = self.derive(py, variant, key_material)?;
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
        variant: &Argon2Variant,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyString>> {
        let derived_key = self.derive(py, variant, key_material)?;
        let salt_bytes = self.salt.as_bytes(py);

        let salt_b64 = STANDARD_NO_PAD.encode(salt_bytes);
        let hash_b64 = STANDARD_NO_PAD.encode(derived_key.as_bytes());

        let variant_id: &str = match variant {
            Argon2Variant::Argon2d => "argon2d",
            Argon2Variant::Argon2i => "argon2i",
            Argon2Variant::Argon2id => "argon2id",
        };

        // Format the PHC string
        let phc_string = format!(
            "${}$v=19$m={},t={},p={}${}${}",
            variant_id, self.memory_cost, self.iterations, self.lanes, salt_b64, hash_b64
        );

        Ok(pyo3::types::PyString::new(py, &phc_string))
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify_phc_encoded(
        py: pyo3::Python<'_>,
        variant: &Argon2Variant,
        key_material: CffiBuf<'_>,
        phc_encoded: &str,
        secret: Option<pyo3::Py<pyo3::types::PyBytes>>,
    ) -> CryptographyResult<()> {
        let parts: Vec<_> = phc_encoded.split('$').collect();

        if parts.len() != 6 || !parts[0].is_empty() {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid PHC string format.",
            )));
        }

        let requested_variant: Option<&Argon2Variant> = match parts[1] {
            "argon2d" => Some(&Argon2Variant::Argon2d),
            "argon2i" => Some(&Argon2Variant::Argon2i),
            "argon2id" => Some(&Argon2Variant::Argon2id),
            _ => None,
        };

        let requested_variant = requested_variant.ok_or_else(|| {
            CryptographyError::from(exceptions::InvalidKey::new_err(
                "Invalid PHC string format.",
            ))
        })?;

        if requested_variant != variant {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                format!(
                    "Incorrect variant in PHC string, did you mean to use {:?}?",
                    requested_variant
                ),
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
        let mut argon2 = BaseArgon2::new(
            py,
            salt.into(),
            hash_bytes.len(),
            iterations,
            lanes,
            memory_cost,
            None,
            secret,
        )?;

        let derived_key = argon2.derive(py, variant, key_material)?;
        let derived_bytes = derived_key.as_bytes();

        if !constant_time::bytes_eq(derived_bytes, &hash_bytes) {
            return Err(CryptographyError::from(exceptions::InvalidKey::new_err(
                "Keys do not match.",
            )));
        }

        Ok(())
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.argon2")]
struct Argon2d {
    _base: BaseArgon2,
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.argon2")]
struct Argon2i {
    _base: BaseArgon2,
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.argon2")]
struct Argon2id {
    _base: BaseArgon2,
}

#[pyo3::pymethods]
impl Argon2d {
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
        Ok({
            Self {
                _base: BaseArgon2::new(
                    py,
                    salt,
                    length,
                    iterations,
                    lanes,
                    memory_cost,
                    ad,
                    secret,
                )?,
            }
        })
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self._base.derive_into_buffer(
            py,
            &Argon2Variant::Argon2d,
            key_material.as_bytes(),
            buf.as_mut_bytes(),
        )
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self._base.derive(py, &Argon2Variant::Argon2d, key_material)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        self._base
            .verify(py, &Argon2Variant::Argon2d, key_material, expected_key)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_phc_encoded<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyString>> {
        self._base
            .derive_phc_encoded(py, &Argon2Variant::Argon2d, key_material)
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
        BaseArgon2::verify_phc_encoded(
            py,
            &Argon2Variant::Argon2d,
            key_material,
            phc_encoded,
            secret,
        )
    }
}

#[pyo3::pymethods]
impl Argon2i {
    #[new]
    #[pyo3(signature = (salt, length, iterations, lanes, memory_cost, ad=None, secret=None))]
    #[allow(clippy::too_many_arguments)]
    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
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
        Ok({
            Self {
                _base: BaseArgon2::new(
                    py,
                    salt,
                    length,
                    iterations,
                    lanes,
                    memory_cost,
                    ad,
                    secret,
                )?,
            }
        })
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self._base.derive_into_buffer(
            py,
            &Argon2Variant::Argon2i,
            key_material.as_bytes(),
            buf.as_mut_bytes(),
        )
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self._base.derive(py, &Argon2Variant::Argon2i, key_material)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        self._base
            .verify(py, &Argon2Variant::Argon2i, key_material, expected_key)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_phc_encoded<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyString>> {
        self._base
            .derive_phc_encoded(py, &Argon2Variant::Argon2i, key_material)
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
        BaseArgon2::verify_phc_encoded(
            py,
            &Argon2Variant::Argon2i,
            key_material,
            phc_encoded,
            secret,
        )
    }
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
        Ok({
            Self {
                _base: BaseArgon2::new(
                    py,
                    salt,
                    length,
                    iterations,
                    lanes,
                    memory_cost,
                    ad,
                    secret,
                )?,
            }
        })
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self._base.derive_into_buffer(
            py,
            &Argon2Variant::Argon2id,
            key_material.as_bytes(),
            buf.as_mut_bytes(),
        )
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self._base
            .derive(py, &Argon2Variant::Argon2id, key_material)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn verify(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        expected_key: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        self._base
            .verify(py, &Argon2Variant::Argon2id, key_material, expected_key)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    fn derive_phc_encoded<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyString>> {
        self._base
            .derive_phc_encoded(py, &Argon2Variant::Argon2id, key_material)
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
        BaseArgon2::verify_phc_encoded(
            py,
            &Argon2Variant::Argon2id,
            key_material,
            phc_encoded,
            secret,
        )
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.primitives.kdf.hkdf", name = "HKDF")]
struct Hkdf {
    algorithm: pyo3::Py<pyo3::PyAny>,
    salt: Option<pyo3::Py<pyo3::types::PyBytes>>,
    info: Option<pyo3::Py<pyo3::types::PyBytes>>,
    length: usize,
    used: bool,
}

fn hkdf_extract(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Py<pyo3::PyAny>,
    salt: Option<&pyo3::Py<pyo3::types::PyBytes>>,
    key_material: &CffiBuf<'_>,
) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
    let algorithm_bound = algorithm.bind(py);
    let digest_size = algorithm_bound
        .getattr(pyo3::intern!(py, "digest_size"))?
        .extract::<usize>()?;
    let salt_bound = salt.map(|s| s.bind(py));
    let default_salt = vec![0; digest_size];
    let salt_bytes: &[u8] = if let Some(bound) = salt_bound {
        bound.as_bytes()
    } else {
        &default_salt
    };

    let mut hmac = Hmac::new_bytes(py, salt_bytes, algorithm_bound)?;
    hmac.update_bytes(key_material.as_bytes())?;
    hmac.finalize_bytes()
}

impl Hkdf {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let buf = CffiBuf::from_bytes(py, key_material);
        let prk = hkdf_extract(py, &self.algorithm, self.salt.as_ref(), &buf)?;
        let mut hkdf_expand = HkdfExpand::new(
            py,
            self.algorithm.clone_ref(py),
            self.length,
            self.info.as_ref().map(|i| i.clone_ref(py)),
            None,
        )?;
        hkdf_expand.derive_into_buffer(py, &prk, output)
    }
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

        Ok(Hkdf {
            algorithm,
            salt,
            info,
            length,
            used: false,
        })
    }

    #[staticmethod]
    fn extract<'p>(
        py: pyo3::Python<'p>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        salt: Option<pyo3::Py<pyo3::types::PyBytes>>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let prk = hkdf_extract(py, &algorithm, salt.as_ref(), &key_material)?;
        Ok(pyo3::types::PyBytes::new(py, &prk))
    }

    fn _extract<'p>(
        &self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let prk = hkdf_extract(py, &self.algorithm, self.salt.as_ref(), &key_material)?;
        Ok(pyo3::types::PyBytes::new(py, &prk))
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.hkdf",
    name = "HKDFExpand"
)]
// NO-COVERAGE-END
struct HkdfExpand {
    algorithm: pyo3::Py<pyo3::PyAny>,
    info: pyo3::Py<pyo3::types::PyBytes>,
    length: usize,
    used: bool,
}

impl HkdfExpand {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let algorithm_bound = self.algorithm.bind(py);
        let h_prime = Hmac::new_bytes(py, key_material, algorithm_bound)?;
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

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

        Ok(self.length)
    }
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

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.x963kdf",
    name = "X963KDF"
)]
// NO-COVERAGE-END
struct X963Kdf {
    algorithm: pyo3::Py<pyo3::PyAny>,
    length: usize,
    sharedinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
    used: bool,
}

impl X963Kdf {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let algorithm_bound = self.algorithm.bind(py);
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let mut pos = 0usize;
        let mut counter = 1u32;

        while pos < self.length {
            let mut hash_obj = hashes::Hash::new(py, algorithm_bound, None)?;
            hash_obj.update_bytes(key_material)?;
            hash_obj.update_bytes(&counter.to_be_bytes())?;
            if let Some(ref sharedinfo) = self.sharedinfo {
                hash_obj.update_bytes(sharedinfo.as_bytes(py))?;
            }
            let block = hash_obj.finalize(py)?;
            let block_bytes = block.as_bytes();

            let copy_len = (self.length - pos).min(digest_size);
            output[pos..pos + copy_len].copy_from_slice(&block_bytes[..copy_len]);
            pos += copy_len;
            counter += 1;
        }

        Ok(self.length)
    }
}

#[pyo3::pymethods]
impl X963Kdf {
    #[new]
    #[pyo3(signature = (algorithm, length, sharedinfo, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        length: usize,
        sharedinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        let digest_size = algorithm
            .bind(py)
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let max_len = digest_size.saturating_mul(u32::MAX as usize);

        if length > max_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Cannot derive keys larger than {max_len} bits."
                )),
            ));
        }

        Ok(X963Kdf {
            algorithm,
            length,
            sharedinfo,
            used: false,
        })
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.concatkdf",
    name = "ConcatKDFHash"
)]
// NO-COVERAGE-END
struct ConcatKdfHash {
    algorithm: pyo3::Py<pyo3::PyAny>,
    length: usize,
    otherinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
    used: bool,
}

impl ConcatKdfHash {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let algorithm_bound = self.algorithm.bind(py);
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let mut pos = 0usize;
        let mut counter = 1u32;

        while pos < self.length {
            let mut hash_obj = hashes::Hash::new(py, algorithm_bound, None)?;
            hash_obj.update_bytes(&counter.to_be_bytes())?;
            hash_obj.update_bytes(key_material)?;
            if let Some(ref otherinfo) = self.otherinfo {
                hash_obj.update_bytes(otherinfo.as_bytes(py))?;
            }
            let block = hash_obj.finalize(py)?;
            let block_bytes = block.as_bytes();

            let copy_len = (self.length - pos).min(digest_size);
            output[pos..pos + copy_len].copy_from_slice(&block_bytes[..copy_len]);
            pos += copy_len;
            counter += 1;
        }

        Ok(self.length)
    }
}

#[pyo3::pymethods]
impl ConcatKdfHash {
    #[new]
    #[pyo3(signature = (algorithm, length, otherinfo, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        length: usize,
        otherinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        let algorithm_bound = algorithm.bind(py);
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let max_len = digest_size.saturating_mul(u32::MAX as usize);
        if length > max_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Cannot derive keys larger than {max_len} bits."
                )),
            ));
        }

        Ok(ConcatKdfHash {
            algorithm,
            length,
            otherinfo,
            used: false,
        })
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.concatkdf",
    name = "ConcatKDFHMAC"
)]
// NO-COVERAGE-END
struct ConcatKdfHmac {
    algorithm: pyo3::Py<pyo3::PyAny>,
    length: usize,
    salt: pyo3::Py<pyo3::types::PyBytes>,
    otherinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
    used: bool,
}

impl ConcatKdfHmac {
    fn derive_into_buffer(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: &[u8],
        output: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;

        if output.len() != self.length {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be {} bytes",
                    self.length
                )),
            ));
        }

        let algorithm_bound = self.algorithm.bind(py);
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let mut pos = 0usize;
        let mut counter = 1u32;

        while pos < self.length {
            let mut hmac = Hmac::new_bytes(py, self.salt.as_bytes(py), algorithm_bound)?;
            hmac.update_bytes(&counter.to_be_bytes())?;
            hmac.update_bytes(key_material)?;
            if let Some(ref otherinfo) = self.otherinfo {
                hmac.update_bytes(otherinfo.as_bytes(py))?;
            }
            let result = hmac.finalize_bytes()?;

            let copy_len = (self.length - pos).min(digest_size);
            output[pos..pos + copy_len].copy_from_slice(&result[..copy_len]);
            pos += copy_len;
            counter += 1;
        }

        Ok(self.length)
    }
}

#[pyo3::pymethods]
impl ConcatKdfHmac {
    #[new]
    #[pyo3(signature = (algorithm, length, salt, otherinfo, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        length: usize,
        salt: Option<pyo3::Py<pyo3::types::PyBytes>>,
        otherinfo: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        let algorithm_bound = algorithm.bind(py);
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;

        let max_len = digest_size.saturating_mul(u32::MAX as usize);
        if length > max_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Cannot derive keys larger than {max_len} bits."
                )),
            ));
        }

        let block_size = algorithm_bound.getattr(pyo3::intern!(py, "block_size"))?;
        if block_size.is_none() {
            let name = algorithm_bound
                .getattr(pyo3::intern!(py, "name"))?
                .extract::<String>()?;
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{name} is unsupported for ConcatKDF"
                )),
            ));
        }

        let block_size_val = block_size.extract::<usize>()?;

        // Default salt to zeros of block_size length
        let salt_bytes = if let Some(s) = salt {
            s
        } else {
            pyo3::types::PyBytes::new_with(py, block_size_val, |_| Ok(()))?.into()
        };

        Ok(ConcatKdfHmac {
            algorithm,
            length,
            salt: salt_bytes,
            otherinfo,
            used: false,
        })
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.derive_into_buffer(py, key_material.as_bytes(), buf.as_mut_bytes())
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            self.derive_into_buffer(py, key_material.as_bytes(), output)?;
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.kbkdf",
    name = "KBKDFHMAC"
)]
// NO-COVERAGE-END
struct KbkdfHmac {
    algorithm: pyo3::Py<pyo3::PyAny>,
    digest_size: usize,
    length: usize,
    params: KbkdfParams,
    used: bool,
}

#[allow(clippy::enum_variant_names)]
#[derive(PartialEq)]
enum CounterLocation {
    BeforeFixed,
    AfterFixed,
    MiddleFixed(usize),
}

struct KbkdfParams {
    rlen: usize,
    llen: Option<usize>,
    location: CounterLocation,
    label: Option<pyo3::Py<pyo3::types::PyBytes>>,
    context: Option<pyo3::Py<pyo3::types::PyBytes>>,
    fixed: Option<pyo3::Py<pyo3::types::PyBytes>>,
}

#[allow(clippy::too_many_arguments)]
fn validate_kbkdf_parameters(
    py: pyo3::Python<'_>,
    mode: pyo3::Py<pyo3::PyAny>,
    rlen: usize,
    llen: Option<usize>,
    location: pyo3::Py<pyo3::PyAny>,
    label: Option<pyo3::Py<pyo3::types::PyBytes>>,
    context: Option<pyo3::Py<pyo3::types::PyBytes>>,
    fixed: Option<pyo3::Py<pyo3::types::PyBytes>>,
    break_location: Option<usize>,
) -> CryptographyResult<KbkdfParams> {
    let mode_bound = mode.bind(py);
    let mode_type = crate::types::KBKDF_MODE.get(py)?;
    if !mode_bound.is_instance(&mode_type)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("mode must be of type Mode"),
        ));
    }

    let location_bound = location.bind(py);
    let counter_location = crate::types::KBKDF_COUNTER_LOCATION.get(py)?;
    if !location_bound.is_instance(&counter_location)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("location must be of type CounterLocation"),
        ));
    }

    let counter_location_before_fixed =
        counter_location.getattr(pyo3::intern!(py, "BeforeFixed"))?;
    let counter_location_after_fixed = counter_location.getattr(pyo3::intern!(py, "AfterFixed"))?;
    let rust_location = if location_bound.eq(&counter_location_before_fixed)? {
        CounterLocation::BeforeFixed
    } else if location_bound.eq(&counter_location_after_fixed)? {
        CounterLocation::AfterFixed
    } else {
        // There are only 3 options so this is MiddleFixed
        match break_location {
            Some(break_location) => CounterLocation::MiddleFixed(break_location),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err("Please specify a break_location"),
                ))
            }
        }
    };

    if break_location.is_some() && !matches!(rust_location, CounterLocation::MiddleFixed(_)) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "break_location is ignored when location is not CounterLocation.MiddleFixed",
            ),
        ));
    }

    if (label.is_some() || context.is_some()) && fixed.is_some() {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "When supplying fixed data, label and context are ignored.",
            ),
        ));
    }

    if !(1..=4).contains(&rlen) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("rlen must be between 1 and 4"),
        ));
    }

    if fixed.is_none() && llen.is_none() {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Please specify an llen"),
        ));
    }

    if llen == Some(0) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("llen must be non-zero"),
        ));
    }

    Ok(KbkdfParams {
        rlen,
        llen,
        location: rust_location,
        label,
        context,
        fixed,
    })
}

// Generic KBKDF derivation function that works with any PRF
fn kbkdf_derive_into_buffer<F>(
    py: pyo3::Python<'_>,
    length: usize,
    prf_output_size: usize,
    params: &KbkdfParams,
    output: &mut [u8],
    mut prf_fn: F,
) -> CryptographyResult<usize>
where
    F: FnMut(&[u8]) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes>,
{
    if output.len() != length {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!("buffer must be {} bytes", length)),
        ));
    }

    let fixed = generate_fixed_input(py, length, params)?;

    let (data_before_ctr, data_after_ctr) = match params.location {
        CounterLocation::BeforeFixed => (&b""[..], &fixed[..]),
        CounterLocation::AfterFixed => (&fixed[..], &b""[..]),
        CounterLocation::MiddleFixed(break_location) => {
            if break_location > fixed.len() {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err("break_location offset > len(fixed)"),
                ));
            }
            (&fixed[..break_location], &fixed[break_location..])
        }
    };

    let mut pos = 0usize;
    let rounds = length.div_ceil(prf_output_size);
    for i in 1..=rounds {
        let py_i = pyo3::types::PyInt::new(py, i);
        let counter = py_uint_to_be_bytes_with_length(py, py_i, params.rlen)?;

        let mut input_data = Vec::new();
        input_data.extend_from_slice(data_before_ctr);
        input_data.extend_from_slice(counter.as_ref());
        input_data.extend_from_slice(data_after_ctr);

        let result = prf_fn(&input_data)?;

        let copy_len = (length - pos).min(prf_output_size);
        output[pos..pos + copy_len].copy_from_slice(&result[..copy_len]);
        pos += copy_len;
    }

    Ok(length)
}

fn generate_fixed_input(
    py: pyo3::Python<'_>,
    length: usize,
    params: &KbkdfParams,
) -> CryptographyResult<Vec<u8>> {
    if let Some(ref fixed_data) = params.fixed {
        return Ok(fixed_data.as_bytes(py).to_vec());
    }

    // llen will exist if fixed data is not provided
    let py_bitlength = pyo3::types::PyInt::new(
        py,
        length
            .checked_mul(8)
            .ok_or(pyo3::exceptions::PyOverflowError::new_err(
                "Length too large, would cause overflow in bit length calculation",
            ))?,
    );
    let l_val = py_uint_to_be_bytes_with_length(py, py_bitlength, params.llen.unwrap())?;

    let mut result = Vec::new();
    let label: &[u8] = params.label.as_ref().map_or(b"", |l| l.as_bytes(py));
    result.extend_from_slice(label);
    result.push(0x00);
    let context: &[u8] = params.context.as_ref().map_or(b"", |l| l.as_bytes(py));
    result.extend_from_slice(context);
    result.extend_from_slice(l_val.as_ref());

    Ok(result)
}

#[pyo3::pymethods]
impl KbkdfHmac {
    #[new]
    #[pyo3(signature = (algorithm, mode, length, rlen, llen, location, label, context, fixed, backend=None, *, break_location=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        mode: pyo3::Py<pyo3::PyAny>,
        length: usize,
        rlen: usize,
        llen: Option<usize>,
        location: pyo3::Py<pyo3::PyAny>,
        label: Option<pyo3::Py<pyo3::types::PyBytes>>,
        context: Option<pyo3::Py<pyo3::types::PyBytes>>,
        fixed: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
        break_location: Option<usize>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        // Validate common KBKDF parameters
        let params = validate_kbkdf_parameters(
            py,
            mode,
            rlen,
            llen,
            location,
            label,
            context,
            fixed,
            break_location,
        )?;

        let algorithm_bound = algorithm.bind(py);
        let _md = hashes::message_digest_from_algorithm(py, algorithm_bound)?;
        let digest_size = algorithm_bound
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;
        let rounds = length.div_ceil(digest_size);
        if rounds as u64 > (1u64 << (params.rlen * 8)) - 1 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("There are too many iterations."),
            ));
        }

        Ok(KbkdfHmac {
            algorithm,
            digest_size,
            length,
            params,
            used: false,
        })
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            let buf = CffiMutBuf::from_bytes(py, output);
            self.derive_into(py, key_material, buf)?;
            Ok(())
        })?)
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;
        let hmac_base = Hmac::new_bytes(py, key_material.as_bytes(), self.algorithm.bind(py))?;
        kbkdf_derive_into_buffer(
            py,
            self.length,
            self.digest_size,
            &self.params,
            buf.as_mut_bytes(),
            |data| {
                let mut hmac = hmac_base.copy(py)?;
                hmac.update_bytes(data)?;
                hmac.finalize_bytes()
            },
        )
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

// NO-COVERAGE-START
#[pyo3::pyclass(
    module = "cryptography.hazmat.primitives.kdf.kbkdf",
    name = "KBKDFCMAC"
)]
// NO-COVERAGE-END
struct KbkdfCmac {
    algorithm: pyo3::Py<pyo3::PyAny>,
    prf_output_size: usize,
    length: usize,
    params: KbkdfParams,
    used: bool,
}

#[pyo3::pymethods]
impl KbkdfCmac {
    #[new]
    #[pyo3(signature = (algorithm, mode, length, rlen, llen, location, label, context, fixed, backend=None, *, break_location=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Py<pyo3::PyAny>,
        mode: pyo3::Py<pyo3::PyAny>,
        length: usize,
        rlen: usize,
        llen: Option<usize>,
        location: pyo3::Py<pyo3::PyAny>,
        label: Option<pyo3::Py<pyo3::types::PyBytes>>,
        context: Option<pyo3::Py<pyo3::types::PyBytes>>,
        fixed: Option<pyo3::Py<pyo3::types::PyBytes>>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
        break_location: Option<usize>,
    ) -> CryptographyResult<Self> {
        _ = backend;

        // Validate common KBKDF parameters
        let params = validate_kbkdf_parameters(
            py,
            mode,
            rlen,
            llen,
            location,
            label,
            context,
            fixed,
            break_location,
        )?;

        if !algorithm
            .bind(py)
            .cast::<pyo3::types::PyType>()?
            .is_subclass(&types::BLOCK_CIPHER_ALGORITHM.get(py)?)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Algorithm must be a block cipher.",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                )),
            ));
        }
        let block_size = algorithm.getattr(py, "block_size")?.extract::<usize>(py)?;
        let prf_output_size = block_size / 8;

        let rounds = length.div_ceil(prf_output_size);
        if rounds as u64 > (1u64 << (params.rlen * 8)) - 1 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("There are too many iterations."),
            ));
        }

        Ok(KbkdfCmac {
            algorithm,
            prf_output_size,
            length,
            params,
            used: false,
        })
    }

    fn derive<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        key_material: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Ok(pyo3::types::PyBytes::new_with(py, self.length, |output| {
            let buf = CffiMutBuf::from_bytes(py, output);
            self.derive_into(py, key_material, buf)?;
            Ok(())
        })?)
    }

    fn derive_into(
        &mut self,
        py: pyo3::Python<'_>,
        key_material: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        if self.used {
            return Err(exceptions::already_finalized_error());
        }
        self.used = true;
        let alg = self.algorithm.bind(py).call1((key_material.as_bytes(),))?;
        let cmac_base = cmac::Cmac::new_with_algorithm(py, &alg)?;
        kbkdf_derive_into_buffer(
            py,
            self.length,
            self.prf_output_size,
            &self.params,
            buf.as_mut_bytes(),
            |data| {
                let mut cmac = cmac_base.copy()?;
                cmac.update_bytes(data)?;
                cmac.finalize_bytes()
            },
        )
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

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod kdf {
    #[pymodule_export]
    use super::{
        Argon2d, Argon2i, Argon2id, ConcatKdfHash, ConcatKdfHmac, Hkdf, HkdfExpand, KbkdfCmac,
        KbkdfHmac, Pbkdf2Hmac, Scrypt, X963Kdf,
    };
}
