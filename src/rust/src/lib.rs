// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[pyo3::prelude::pymodule]
// False positive: https://github.com/rust-lang/rust-clippy/issues/6721
#[allow(clippy::unnecessary_wraps)]
fn _rust(_py: pyo3::Python<'_>, _m: &pyo3::types::PyModule) -> pyo3::PyResult<()> {
    Ok(())
}
