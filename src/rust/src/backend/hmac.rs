// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_crypto::constant_time;
use pyo3::types::PyBytesMethods;

use crate::backend::hashes::message_digest_from_algorithm;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.hmac",
    name = "HMAC"
)]
pub(crate) struct Hmac {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: Option<cryptography_openssl::hmac::Hmac>,
}

impl Hmac {
    pub(crate) fn new_bytes(
        py: pyo3::Python<'_>,
        key: &[u8],
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<Hmac> {
        let md = message_digest_from_algorithm(py, algorithm)?;
        let ctx = cryptography_openssl::hmac::Hmac::new(key, md).map_err(|_| {
            exceptions::UnsupportedAlgorithm::new_err((
                "Digest is not supported for HMAC",
                exceptions::Reasons::UNSUPPORTED_HASH,
            ))
        })?;

        Ok(Hmac {
            ctx: Some(ctx),
            algorithm: algorithm.clone().unbind(),
        })
    }

    pub(crate) fn update_bytes(&mut self, data: &[u8]) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data)?;
        Ok(())
    }

    fn get_ctx(&self) -> CryptographyResult<&cryptography_openssl::hmac::Hmac> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(exceptions::already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut cryptography_openssl::hmac::Hmac> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

#[pyo3::pymethods]
impl Hmac {
    #[new]
    #[pyo3(signature = (key, algorithm, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Hmac> {
        let _ = backend;

        Hmac::new_bytes(py, key.as_bytes(), algorithm)
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.update_bytes(data.as_bytes())
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = self.get_mut_ctx()?.finish()?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn verify(&mut self, py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual_bound = self.finalize(py)?;
        let actual = actual_bound.as_bytes();
        if !constant_time::bytes_eq(actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Signature did not match digest."),
            ));
        }

        Ok(())
    }

    pub(crate) fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<Hmac> {
        Ok(Hmac {
            ctx: Some(self.get_ctx()?.copy()?),
            algorithm: self.algorithm.clone_ref(py),
        })
    }
}

#[pyo3::pymodule]
pub(crate) mod hmac {
    #[pymodule_export]
    use super::Hmac;
}
