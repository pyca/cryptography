// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::hashes::{already_finalized_error, message_digest_from_algorithm};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::prelude::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.hmac",
    name = "HMAC"
)]
struct Hmac {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: Option<cryptography_openssl::hmac::Hmac>,
}

impl Hmac {
    fn get_ctx(&self) -> CryptographyResult<&cryptography_openssl::hmac::Hmac> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut cryptography_openssl::hmac::Hmac> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(already_finalized_error())
    }
}

#[pyo3::pymethods]
impl Hmac {
    #[new]
    #[pyo3(signature = (key, algorithm, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        algorithm: &pyo3::PyAny,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<Hmac> {
        let _ = backend;

        let md = message_digest_from_algorithm(py, algorithm)?;
        let ctx = cryptography_openssl::hmac::Hmac::new(key.as_bytes(), md)?;

        Ok(Hmac {
            ctx: Some(ctx),
            algorithm: algorithm.into(),
        })
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

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<Hmac> {
        Ok(Hmac {
            ctx: Some(self.get_ctx()?.copy()?),
            algorithm: self.algorithm.clone_ref(py),
        })
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "hmac")?;
    m.add_class::<Hmac>()?;

    Ok(m)
}
