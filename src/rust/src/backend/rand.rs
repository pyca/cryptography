// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};

pub(crate) fn get_rand_bytes(
    py: pyo3::Python<'_>,
    size: usize,
) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
    Ok(pyo3::types::PyBytes::new_with(py, size, |b| {
        openssl_bridge::rand::fill_private(b).map_err(CryptographyError::from)?;
        Ok(())
    })?)
}
