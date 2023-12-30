// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::cipher_registry;
use crate::backend::hashes::already_finalized_error;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::prelude::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.cmac",
    name = "CMAC"
)]
struct Cmac {
    ctx: Option<cryptography_openssl::cmac::Cmac>,
}

impl Cmac {
    fn get_ctx(&self) -> CryptographyResult<&cryptography_openssl::cmac::Cmac> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut cryptography_openssl::cmac::Cmac> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(already_finalized_error())
    }
}

#[pyo3::pymethods]
impl Cmac {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::PyAny,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<Self> {
        let _ = backend;

        if !algorithm.is_instance(types::BLOCK_CIPHER_ALGORITHM.get(py)?)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of BlockCipherAlgorithm.",
                ),
            ));
        }

        let cipher =
            cipher_registry::get_cipher(py, algorithm, types::CBC.get(py)?)?.ok_or_else(|| {
                exceptions::UnsupportedAlgorithm::new_err((
                    "CMAC is not supported with this algorithm",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                ))
            })?;

        let key = algorithm
            .getattr(pyo3::intern!(py, "key"))?
            .extract::<CffiBuf<'_>>()?;
        let ctx = cryptography_openssl::cmac::Cmac::new(key.as_bytes(), cipher)?;
        Ok(Cmac { ctx: Some(ctx) })
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data.as_bytes())?;
        Ok(())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let data = self.get_mut_ctx()?.finish()?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn verify(&mut self, py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual = self.finalize(py)?.as_bytes();
        if actual.len() != signature.len() || !openssl::memcmp::eq(actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Signature did not match digest."),
            ));
        }

        Ok(())
    }

    fn copy(&self) -> CryptographyResult<Cmac> {
        Ok(Cmac {
            ctx: Some(self.get_ctx()?.copy()?),
        })
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "cmac")?;

    m.add_class::<Cmac>()?;

    Ok(m)
}
