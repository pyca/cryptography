// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    if let Ok(version) = env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
        if version >= 0x3_07_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_LIBRESSL_370_OR_GREATER");
        }
    }
    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
    }
}
