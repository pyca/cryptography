// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

fn main() {
    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_AWSLC");
    }

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();
        if version >= 0x3050_0000 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_350_OR_GREATER");
        }
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OSSLCONF=\"{var}\"");
        }
    }
}
