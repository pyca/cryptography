// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.hashes")]
pub(crate) struct Hash {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: Option<openssl_bridge::hash::Hasher>,
}

impl Hash {
    fn get_ctx(&self) -> CryptographyResult<&openssl_bridge::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(exceptions::already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut openssl_bridge::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

fn algorithm_name(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<String> {
    if !algorithm.is_instance(&types::HASH_ALGORITHM.get(py)?)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Expected instance of hashes.HashAlgorithm.",
        )
        .into());
    }
    let name = algorithm
        .getattr(pyo3::intern!(py, "name"))?
        .extract::<pyo3::pybacked::PyBackedStr>()?;
    if name == "blake2b" || name == "blake2s" {
        let size = algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;
        Ok(format!("{name}{}", size * 8))
    } else {
        Ok(name.to_string())
    }
}

pub(crate) fn bridge_digest_from_algorithm(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<openssl_bridge::hash::Algorithm> {
    let name = algorithm_name(py, algorithm)?;
    openssl_bridge::hash::Algorithm::from_name(&name).map_err(|_| {
        exceptions::UnsupportedAlgorithm::new_err((
            format!("{name} is not a supported hash on this backend"),
            exceptions::Reasons::UNSUPPORTED_HASH,
        ))
        .into()
    })
}

#[pyo3::pyfunction]
fn hash_supported(py: pyo3::Python<'_>, algorithm: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    bridge_digest_from_algorithm(py, &algorithm).is_ok()
}

impl Hash {
    pub(crate) fn update_bytes(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
    ) -> CryptographyResult<()> {
        let ctx = self.get_mut_ctx()?;
        crate::backend::run_with_gil_detached(py, data.len(), || ctx.update(data))?;
        Ok(())
    }
}

#[pyo3::pymethods]
impl Hash {
    #[new]
    #[pyo3(signature = (algorithm, backend=None))]
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Hash> {
        let _ = backend;

        let md = bridge_digest_from_algorithm(py, algorithm)?;
        let ctx = openssl_bridge::hash::Hasher::new(md)?;

        Ok(Hash {
            algorithm: algorithm.clone().unbind(),
            ctx: Some(ctx),
        })
    }

    fn update(&mut self, py: pyo3::Python<'_>, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.update_bytes(py, data.as_bytes())
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        {
            let algorithm = self.algorithm.clone_ref(py);
            let algorithm = algorithm.bind(py);
            if algorithm.is_instance(&types::EXTENDABLE_OUTPUT_FUNCTION.get(py)?)? {
                let ctx = self
                    .ctx
                    .take()
                    .ok_or_else(exceptions::already_finalized_error)?;
                let digest_size = algorithm
                    .getattr(pyo3::intern!(py, "digest_size"))?
                    .extract::<usize>()?;
                let result = pyo3::types::PyBytes::new_with(py, digest_size, |b| {
                    ctx.finish_xof(b).map_err(CryptographyError::from)?;
                    Ok(())
                })?;
                self.ctx = None;
                return Ok(result);
            }
        }

        let data = self
            .ctx
            .take()
            .ok_or_else(exceptions::already_finalized_error)?
            .finish()?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<Hash> {
        Ok(Hash {
            algorithm: self.algorithm.clone_ref(py),
            ctx: Some(self.get_ctx()?.try_clone()?),
        })
    }

    #[staticmethod]
    fn hash<'p>(
        py: pyo3::Python<'p>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let md = bridge_digest_from_algorithm(py, algorithm)?;

        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        {
            if algorithm.is_instance(&types::EXTENDABLE_OUTPUT_FUNCTION.get(py)?)? {
                let digest_size = algorithm
                    .getattr(pyo3::intern!(py, "digest_size"))?
                    .extract::<usize>()?;
                let result = pyo3::types::PyBytes::new_with(py, digest_size, |b| {
                    openssl_bridge::hash::digest_xof(md, data.as_bytes(), b)
                        .map_err(CryptographyError::from)?;
                    Ok(())
                })?;
                return Ok(result);
            }
        }

        let data = data.as_bytes();
        let digest = crate::backend::run_with_gil_detached(py, data.len(), || {
            openssl_bridge::hash::digest(md, data)
        })?;
        Ok(pyo3::types::PyBytes::new(py, &digest))
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.hashes")]
pub(crate) struct XOFHash {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: openssl_bridge::hash::Hasher,
    bytes_remaining: u64,
    squeezed: bool,
}

impl XOFHash {
    pub(crate) fn update_bytes(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
    ) -> CryptographyResult<()> {
        let ctx = &mut self.ctx;
        crate::backend::run_with_gil_detached(py, data.len(), || ctx.update(data))?;
        Ok(())
    }
}

#[pyo3::pymethods]
impl XOFHash {
    #[new]
    #[pyo3(signature = (algorithm))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<XOFHash> {
        cfg_if::cfg_if! {
            if #[cfg(not(any(
                CRYPTOGRAPHY_OPENSSL_330_OR_GREATER,
                CRYPTOGRAPHY_IS_AWSLC
            )))] {
                let _ = py;
                let _ = algorithm;
                Err(CryptographyError::from(
                    exceptions::UnsupportedAlgorithm::new_err((
                        "Extendable output functions are not supported on this backend.",
                    )),
                ))
            } else {
                if !algorithm.is_instance(&types::EXTENDABLE_OUTPUT_FUNCTION.get(py)?)? {
                    return Err(CryptographyError::from(
                        pyo3::exceptions::PyTypeError::new_err(
                            "Expected instance of an extendable output function.",
                        ),
                    ));
                }
                let md = bridge_digest_from_algorithm(py, algorithm)?;
                let ctx = openssl_bridge::hash::Hasher::new(md)?;
                // We treat digest_size as the maximum total output for this API
                let bytes_remaining = algorithm
                    .getattr(pyo3::intern!(py, "digest_size"))?
                    .extract::<u64>()?;

                Ok(XOFHash {
                    algorithm: algorithm.clone().unbind(),
                    ctx,
                    bytes_remaining,
                    squeezed: false,
                })
            }
        }
    }

    fn update(&mut self, py: pyo3::Python<'_>, data: CffiBuf<'_>) -> CryptographyResult<()> {
        if self.squeezed {
            return Err(CryptographyError::from(
                exceptions::AlreadyFinalized::new_err("Context was already squeezed."),
            ));
        }
        self.update_bytes(py, data.as_bytes())
    }
    #[cfg(any(CRYPTOGRAPHY_OPENSSL_330_OR_GREATER, CRYPTOGRAPHY_IS_AWSLC))]
    fn squeeze<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.squeezed = true;
        // We treat digest_size as the maximum total output for this API
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(length.try_into().unwrap())
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "Exceeded maximum squeeze limit specified by digest_size.",
                )
            })?;
        let result = pyo3::types::PyBytes::new_with(py, length, |b| {
            self.ctx.squeeze_xof(b).map_err(CryptographyError::from)?;
            Ok(())
        })?;
        Ok(result)
    }

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<XOFHash> {
        Ok(XOFHash {
            algorithm: self.algorithm.clone_ref(py),
            ctx: self.ctx.try_clone()?,
            bytes_remaining: self.bytes_remaining,
            squeezed: self.squeezed,
        })
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod hashes {
    #[pymodule_export]
    use super::{hash_supported, Hash, XOFHash};
}
