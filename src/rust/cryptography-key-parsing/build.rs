// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(CRYPTOGRAPHY_IS_LIBRESSL)");
    println!("cargo:rustc-check-cfg=cfg(CRYPTOGRAPHY_IS_BORINGSSL)");

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
    }
}
