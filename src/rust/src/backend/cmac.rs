// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_crypto::constant_time;
use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::cipher_registry;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

pub struct CmacContext {
    ctx: Option<cryptography_openssl::cmac::Cmac>,
}

impl CmacContext {
    pub fn new(
        key: &[u8],
        cipher: &openssl::cipher::CipherRef,
    ) -> CryptographyResult<Self> {
        let ctx = cryptography_openssl::cmac::Cmac::new(key, cipher)?;
        Ok(CmacContext { ctx: Some(ctx) })
    }

    pub fn update(&mut self, data: &[u8]) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data)?;
        Ok(())
    }

    pub fn finalize(&mut self) -> CryptographyResult<Vec<u8>> {
        let data = self.get_mut_ctx()?.finish()?;
        self.ctx = None;
        Ok(data.as_slice().to_vec())
    }

    pub fn verify(&mut self, signature: &[u8]) -> CryptographyResult<()> {
        let actual = self.finalize()?;
        if !constant_time::bytes_eq(&actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Signature did not match digest."),
            ));
        }
        Ok(())
    }

    pub fn copy(&self) -> CryptographyResult<Self> {
        Ok(CmacContext {
            ctx: Some(self.get_ctx()?.copy()?),
        })
    }

    fn get_ctx(&self) -> CryptographyResult<&cryptography_openssl::cmac::Cmac> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut cryptography_openssl::cmac::Cmac> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

/// Python wrapper for CMAC functionality.
/// This struct provides the Python interface while delegating to `CmacContext`.
#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.cmac",
    name = "CMAC"
)]
struct Cmac {
    ctx: CmacContext,
}

#[pyo3::pymethods]
impl Cmac {
    #[new]
    #[pyo3(signature = (algorithm, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        backend: Option<pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> CryptographyResult<Self> {
        let _ = backend;

        if !algorithm.is_instance(&types::BLOCK_CIPHER_ALGORITHM.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of BlockCipherAlgorithm.",
                ),
            ));
        }

        let cipher = cipher_registry::get_cipher(py, algorithm.clone(), types::CBC.get(py)?)?
            .ok_or_else(|| {
                exceptions::UnsupportedAlgorithm::new_err((
                    "CMAC is not supported with this algorithm",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                ))
            })?;

        let key = algorithm
            .getattr(pyo3::intern!(py, "key"))?
            .extract::<CffiBuf<'_>>()?;

        let ctx = CmacContext::new(key.as_bytes(), cipher)?;
        Ok(Cmac { ctx })
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.ctx.update(data.as_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = self.ctx.finalize()?;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn verify(&mut self, _py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        self.ctx.verify(signature)
    }

    fn copy(&self) -> CryptographyResult<Cmac> {
        Ok(Cmac {
            ctx: self.ctx.copy()?,
        })
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod cmac {
    #[pymodule_export]
    use super::Cmac;
}
