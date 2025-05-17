// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    pyo3_build_config::use_pyo3_cfgs();

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x3_00_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_300_OR_GREATER");
        }
        if version >= 0x3_00_09_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_309_OR_GREATER");
        }
        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_320_OR_GREATER");
        }
        if version >= 0x3_03_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_330_OR_GREATER");
        }
        if version >= 0x3_05_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_350_OR_GREATER");
        }
    }

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    if env::var("DEP_OPENSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_BORINGSSL");
    }

    if env::var("DEP_OPENSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_AWSLC");
    }

    if env::var("CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY").is_ok_and(|v| !v.is_empty() && v != "0") {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_BUILD_OPENSSL_NO_LEGACY");
    }

    if let Ok(vars) = env::var("DEP_OPENSSL_CONF") {
        for var in vars.split(',') {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OSSLCONF=\"{var}\"");
        }
    }
}
