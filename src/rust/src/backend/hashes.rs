// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use std::borrow::Cow;

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.hashes")]
struct Hash {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: Option<openssl::hash::Hasher>,
}

impl Hash {
    fn get_ctx(&self, py: pyo3::Python<'_>) -> CryptographyResult<&openssl::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(CryptographyError::from(pyo3::PyErr::from_value(
            py.import(pyo3::intern!(py, "cryptography.exceptions"))?
                .call_method1(
                    pyo3::intern!(py, "AlreadyFinalized"),
                    ("Context was already finalized.",),
                )?,
        )))
    }

    fn get_mut_ctx(
        &mut self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<&mut openssl::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(CryptographyError::from(pyo3::PyErr::from_value(
            py.import(pyo3::intern!(py, "cryptography.exceptions"))?
                .call_method1(
                    pyo3::intern!(py, "AlreadyFinalized"),
                    ("Context was already finalized.",),
                )?,
        )))
    }
}

#[pyo3::pymethods]
impl Hash {
    #[new]
    #[pyo3(signature = (algorithm, backend=None))]
    fn new(
        py: pyo3::Python<'_>,
        algorithm: &pyo3::PyAny,
        backend: Option<&pyo3::PyAny>,
    ) -> CryptographyResult<Hash> {
        let _ = backend;
        let hash_algorithm_class = py
            .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
            .getattr(pyo3::intern!(py, "HashAlgorithm"))?;
        if !algorithm.is_instance(hash_algorithm_class)? {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyTypeError::new_err(
                    "Expected instance of hashes.HashAlgorithm.",
                ),
            ));
        }

        let name = algorithm
            .getattr(pyo3::intern!(py, "name"))?
            .extract::<&str>()?;
        let openssl_name = if name == "blake2b" || name == "blake2s" {
            let digest_size = algorithm
                .getattr(pyo3::intern!(py, "digest_size"))?
                .extract::<usize>()?;
            Cow::Owned(format!("{}{}", name, digest_size * 8))
        } else {
            Cow::Borrowed(name)
        };

        let md = match openssl::hash::MessageDigest::from_name(&openssl_name) {
            Some(md) => md,
            None => {
                let exceptions_module = py.import(pyo3::intern!(py, "cryptography.exceptions"))?;
                let reason = exceptions_module
                    .getattr(pyo3::intern!(py, "_Reasons"))?
                    .getattr(pyo3::intern!(py, "UNSUPPORTED_HASH"))?;
                return Err(CryptographyError::from(pyo3::PyErr::from_value(
                    exceptions_module.call_method1(
                        pyo3::intern!(py, "UnsupportedAlgorithm"),
                        (
                            format!("{} is not a supported hash on this backend", name),
                            reason,
                        ),
                    )?,
                )));
            }
        };
        let ctx = openssl::hash::Hasher::new(md)?;

        Ok(Hash {
            algorithm: algorithm.into(),
            ctx: Some(ctx),
        })
    }

    fn update(&mut self, py: pyo3::Python<'_>, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.get_mut_ctx(py)?.update(data.as_bytes())?;
        Ok(())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        {
            let xof_class = py
                .import(pyo3::intern!(py, "cryptography.hazmat.primitives.hashes"))?
                .getattr(pyo3::intern!(py, "ExtendableOutputFunction"))?;
            let algorithm = self.algorithm.clone_ref(py);
            let algorithm = algorithm.as_ref(py);
            if algorithm.is_instance(xof_class)? {
                let ctx = self.get_mut_ctx(py)?;
                let digest_size = algorithm
                    .getattr(pyo3::intern!(py, "digest_size"))?
                    .extract::<usize>()?;
                let result = pyo3::types::PyBytes::new_with(py, digest_size, |b| {
                    ctx.finish_xof(b).unwrap();
                    Ok(())
                })?;
                self.ctx = None;
                return Ok(result);
            }
        }

        let data = self.get_mut_ctx(py)?.finish()?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new(py, &data))
    }

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<Hash> {
        Ok(Hash {
            algorithm: self.algorithm.clone_ref(py),
            ctx: Some(self.get_ctx(py)?.clone()),
        })
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "hashes")?;
    m.add_class::<Hash>()?;

    Ok(m)
}
