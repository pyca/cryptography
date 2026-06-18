// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::env;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    pyo3_build_config::use_pyo3_cfgs();

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

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

    // macOS 15 CI runners use Apple's new linker (ld_prime), which reserves
    // significantly less Mach-O header padding than the old ld. Tools like
    // Homebrew use install_name_tool to rewrite dylib paths post-install, and
    // that requires spare space in the header. Without this flag the relink
    // fails with "updated load commands do not fit in the header". This was
    // first observed with cryptography 46.0.4 when wheel builds moved from
    // macos-13 to macos-15 runners.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-headerpad_max_install_names");
    }
}
