// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;

use crate::backend::hashes::message_digest_from_algorithm;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.hashes")]
pub(crate) struct XOFHash {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: openssl::hash::Hasher,
    bytes_remaining: u64,
    squeezed: bool,
}

impl XOFHash {
    pub(crate) fn update_bytes(&mut self, data: &[u8]) -> CryptographyResult<()> {
        self.ctx.update(data)?;
        Ok(())
    }
}

#[pyo3::pymethods]
impl XOFHash {
    #[new]
    #[pyo3(signature = (algorithm, backend=None))]
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        backend: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<XOFHash> {
        let _ = backend;

        #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))]
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "Extendable output functions are not supported on LibreSSL or BoringSSL.",
                )),
            ));
        }
        if !algorithm.is_instance(&types::EXTENDABLE_OUTPUT_FUNCTION.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of an extendable output function.",
                ),
            ));
        }
        let md = message_digest_from_algorithm(py, algorithm)?;
        let ctx = openssl::hash::Hasher::new(md)?;
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

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        if self.squeezed {
            return Err(CryptographyError::from(
                exceptions::AlreadyFinalized::new_err("Context was already squeezed."),
            ));
        }
        self.update_bytes(data.as_bytes())
    }

    pub(crate) fn squeeze<'p>(
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
            self.ctx.squeeze_xof(b).unwrap();
            Ok(())
        })?;
        Ok(result)
    }

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<XOFHash> {
        Ok(XOFHash {
            algorithm: self.algorithm.clone_ref(py),
            ctx: self.ctx.clone(),
            bytes_remaining: self.bytes_remaining,
            squeezed: self.squeezed,
        })
    }
}

#[pyo3::pyfunction]
fn xofhash_supported(py: pyo3::Python<'_>, algorithm: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))]
    {
        return false;
    }
    message_digest_from_algorithm(py, &algorithm).is_ok()
}

#[pyo3::pymodule]
pub(crate) mod xofhash {
    #[pymodule_export]
    use super::{xofhash_supported, XOFHash};
}
