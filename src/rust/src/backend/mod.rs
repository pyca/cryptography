// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
pub(crate) mod x25519;

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    #[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
    module.add_submodule(x25519::create_module(module.py())?)?;

    Ok(())
}
