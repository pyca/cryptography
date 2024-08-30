// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::PyAnyMethods;
use pyo3::IntoPy;
use std::borrow::Cow;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.hashes")]
pub(crate) struct Hash {
    #[pyo3(get)]
    algorithm: pyo3::Py<pyo3::PyAny>,
    ctx: Option<openssl::hash::Hasher>,
}

impl Hash {
    fn get_ctx(&self) -> CryptographyResult<&openssl::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        };
        Err(exceptions::already_finalized_error())
    }

    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut openssl::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

pub(crate) fn message_digest_from_algorithm(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<openssl::hash::MessageDigest> {
    if !algorithm.is_instance(&types::HASH_ALGORITHM.get(py)?)? {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("Expected instance of hashes.HashAlgorithm."),
        ));
    }

    let name = algorithm
        .getattr(pyo3::intern!(py, "name"))?
        .extract::<pyo3::pybacked::PyBackedStr>()?;
    let openssl_name = if name == "blake2b" || name == "blake2s" {
        let digest_size = algorithm
            .getattr(pyo3::intern!(py, "digest_size"))?
            .extract::<usize>()?;
        Cow::Owned(format!("{}{}", name, digest_size * 8))
    } else {
        Cow::Borrowed(name.as_ref())
    };

    match openssl::hash::MessageDigest::from_name(&openssl_name) {
        Some(md) => Ok(md),
        None => Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!("{name} is not a supported hash on this backend"),
                exceptions::Reasons::UNSUPPORTED_HASH,
            )),
        )),
    }
}

#[pyo3::pyfunction]
fn hash_supported(py: pyo3::Python<'_>, algorithm: pyo3::Bound<'_, pyo3::PyAny>) -> bool {
    message_digest_from_algorithm(py, &algorithm).is_ok()
}

impl Hash {
    pub(crate) fn update_bytes(&mut self, data: &[u8]) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data)?;
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

        let md = message_digest_from_algorithm(py, algorithm)?;
        let ctx = openssl::hash::Hasher::new(md)?;

        Ok(Hash {
            algorithm: algorithm.clone().into_py(py),
            ctx: Some(ctx),
        })
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.update_bytes(data.as_bytes())
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
                let ctx = self.get_mut_ctx()?;
                let digest_size = algorithm
                    .getattr(pyo3::intern!(py, "digest_size"))?
                    .extract::<usize>()?;
                let result = pyo3::types::PyBytes::new_bound_with(py, digest_size, |b| {
                    ctx.finish_xof(b).unwrap();
                    Ok(())
                })?;
                self.ctx = None;
                return Ok(result);
            }
        }

        let data = self.get_mut_ctx()?.finish()?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new_bound(py, &data))
    }

    fn copy(&self, py: pyo3::Python<'_>) -> CryptographyResult<Hash> {
        Ok(Hash {
            algorithm: self.algorithm.clone_ref(py),
            ctx: Some(self.get_ctx()?.clone()),
        })
    }
}

#[pyo3::pymodule]
pub(crate) mod hashes {
    #[pymodule_export]
    use super::{hash_supported, Hash};
}
