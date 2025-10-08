// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub(crate) fn is_ed448(id: openssl::pkey::Id) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))] {
            id == openssl::pkey::Id::ED448
        } else {
            _ = id;
            false
        }
    }
}

pub(crate) fn is_x448(id: openssl::pkey::Id) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))] {
            id == openssl::pkey::Id::X448
        } else {
            _ = id;
            false
        }
    }
}
