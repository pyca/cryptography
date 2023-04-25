// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub(crate) mod dh;
#[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
pub(crate) mod ed25519;
#[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
pub(crate) mod ed448;
pub(crate) mod hashes;
pub(crate) mod hmac;
pub(crate) mod kdf;
pub(crate) mod utils;
#[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
pub(crate) mod x25519;
#[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
pub(crate) mod x448;

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_submodule(dh::create_module(module.py())?)?;

    #[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
    module.add_submodule(ed25519::create_module(module.py())?)?;
    #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
    module.add_submodule(ed448::create_module(module.py())?)?;

    #[cfg(any(not(CRYPTOGRAPHY_IS_LIBRESSL), CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER))]
    module.add_submodule(x25519::create_module(module.py())?)?;
    #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
    module.add_submodule(x448::create_module(module.py())?)?;

    module.add_submodule(hashes::create_module(module.py())?)?;
    module.add_submodule(hmac::create_module(module.py())?)?;
    module.add_submodule(kdf::create_module(module.py())?)?;

    Ok(())
}
