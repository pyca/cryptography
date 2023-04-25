// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(all(
    CRYPTOGRAPHY_OPENSSL_300_OR_GREATER,
    not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))
))]
use std::ptr;

pub fn is_enabled() -> bool {
    #[cfg(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))]
    {
        return false;
    }

    #[cfg(all(
        CRYPTOGRAPHY_OPENSSL_300_OR_GREATER,
        not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))
    ))]
    unsafe {
        ffi::EVP_default_properties_is_fips_enabled(ptr::null_mut()) == 1
    }

    #[cfg(all(
        not(CRYPTOGRAPHY_OPENSSL_300_OR_GREATER),
        not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL))
    ))]
    {
        return openssl::fips::enabled();
    }
}
