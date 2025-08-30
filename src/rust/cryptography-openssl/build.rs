// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=CRYPTOGRAPHY_OPENSSL_320_OR_GREATER");
        }
    }

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=CRYPTOGRAPHY_IS_LIBRESSL");
    }

    let is_boringssl = env::var("DEP_OPENSSL_BORINGSSL").is_ok();
    let is_awslc = env::var("DEP_OPENSSL_AWSLC").is_ok();

    if is_boringssl || is_awslc {
        let cfg_name = if is_boringssl {
            "CRYPTOGRAPHY_IS_BORINGSSL"
        } else {
            "CRYPTOGRAPHY_IS_AWSLC"
        };
        println!("cargo:rustc-cfg={cfg_name}");
        if env::var_os("CARGO_CFG_UNIX").is_some() {
            match env::var("CARGO_CFG_TARGET_OS").as_deref() {
                Ok("macos") => println!("cargo:rustc-link-lib=c++"),
                _ => println!("cargo:rustc-link-lib=stdc++"),
            }
        }
    }
}
