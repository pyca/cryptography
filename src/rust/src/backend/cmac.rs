// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_crypto::constant_time;
use pyo3::types::PyAnyMethods;

use crate::backend::cipher_registry;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.cmac",
    name = "CMAC"
)]
pub(crate) struct Cmac {
    ctx: Option<cryptography_openssl::cmac::Cmac>,
}

impl Cmac {
    pub(crate) fn new_bytes(
        key: &[u8],
        cipher: &openssl::cipher::CipherRef,
    ) -> CryptographyResult<Self> {
        let ctx = cryptography_openssl::cmac::Cmac::new(key, cipher)?;
        Ok(Cmac { ctx: Some(ctx) })
    }

    pub(crate) fn new_with_algorithm(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<Self> {
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

        Cmac::new_bytes(key.as_bytes(), cipher)
    }

    pub(crate) fn update_bytes(&mut self, data: &[u8]) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data)?;
        Ok(())
    }

    pub(crate) fn finalize_bytes(
        &mut self,
    ) -> CryptographyResult<cryptography_openssl::hmac::DigestBytes> {
        let data = self.get_mut_ctx()?.finish()?;
        self.ctx = None;
        Ok(data)
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

        Cmac::new_with_algorithm(py, &algorithm)
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.update_bytes(data.as_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let data = self.finalize_bytes()?;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn verify(&mut self, _py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual = self.finalize_bytes()?;
        if !constant_time::bytes_eq(&actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Signature did not match digest."),
            ));
        }
        Ok(())
    }

    pub(crate) fn copy(&self) -> CryptographyResult<Cmac> {
        Ok(Cmac {
            ctx: Some(self.get_ctx()?.copy()?),
        })
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod cmac {
    #[pymodule_export]
    use super::Cmac;
}
