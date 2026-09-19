// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_crypto::constant_time;
use pyo3::types::PyBytesMethods;

use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.poly1305")]
struct Poly1305 {
    inner: Option<openssl_bridge::poly1305::Poly1305>,
}

#[pyo3::pymethods]
impl Poly1305 {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305> {
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
        if openssl_bridge::runtime::is_fips_enabled() {
            return Err(exceptions::UnsupportedAlgorithm::new_err((
                "poly1305 is not supported by this version of OpenSSL.",
                exceptions::Reasons::UNSUPPORTED_MAC,
            ))
            .into());
        }
        let key = key.as_bytes().try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long")
        })?;
        Ok(Self {
            inner: Some(openssl_bridge::poly1305::Poly1305::new(key)?),
        })
    }

    #[staticmethod]
    fn generate_tag<'p>(
        py: pyo3::Python<'p>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.finalize(py)
    }

    #[staticmethod]
    fn verify_tag(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
        tag: &[u8],
    ) -> CryptographyResult<()> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.verify(py, tag)
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(exceptions::already_finalized_error)?
            .update(data.as_bytes())?;
        Ok(())
    }
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let tag = self
            .inner
            .take()
            .ok_or_else(exceptions::already_finalized_error)?
            .finish()?;
        Ok(pyo3::types::PyBytes::new(py, &tag))
    }

    fn verify(&mut self, py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual_bound = self.finalize(py)?;
        let actual = actual_bound.as_bytes();
        if !constant_time::bytes_eq(actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Value did not match computed tag."),
            ));
        }

        Ok(())
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod poly1305 {
    #[pymodule_export]
    use super::Poly1305;
}
