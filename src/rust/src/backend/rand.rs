// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};

pub(crate) fn get_rand_bytes(
    py: pyo3::Python<'_>,
    size: usize,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
    Ok(pyo3::types::PyBytes::new_with(py, size, |b| {
        fill_random(b)?;
        Ok(())
    })?)
}

/// Fills `buf` with random bytes from the backend's generator: OpenSSL's, or
/// the operating system's (`getrandom`) with verified-garbage.
pub(crate) fn fill_random(buf: &mut [u8]) -> CryptographyResult<()> {
    #[cfg(feature = "openssl")]
    cryptography_openssl::rand::rand_bytes(buf).map_err(CryptographyError::from)?;
    #[cfg(feature = "verified-garbage")]
    getrandom::fill(buf).map_err(|_| CryptographyError::VerifiedGarbage("getrandom failed"))?;
    Ok(())
}
