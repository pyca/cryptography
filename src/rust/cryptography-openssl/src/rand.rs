// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::OpenSSLResult;

/// Fill a buffer with random bytes.
pub fn rand_bytes(buf: &mut [u8]) -> OpenSSLResult<()> {
    #[cfg(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    openssl::rand::rand_bytes(buf)?;

    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    openssl::rand::rand_priv_bytes(buf)?;

    Ok(())
}
