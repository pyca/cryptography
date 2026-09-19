use std::env;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(backend, values(\"openssl\", \"libressl\", \"boringssl\", \"awslc\"))");
    println!("cargo:rustc-check-cfg=cfg(openssl_330)");
    println!("cargo:rustc-check-cfg=cfg(openssl_320)");
    println!("cargo:rustc-check-cfg=cfg(openssl_350)");
    if env::var("DEP_OPENSSL_VERSION_NUMBER_DECIMAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|v| v >= 0x30500000)
    {
        println!("cargo:rustc-cfg=openssl_350");
    }
    if env::var("DEP_OPENSSL_VERSION_NUMBER_DECIMAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|v| v >= 0x30200000)
    {
        println!("cargo:rustc-cfg=openssl_320");
    }
    let backend = env::var("DEP_OPENSSL_BACKEND").unwrap();
    println!("cargo:rustc-cfg=backend=\"{backend}\"");
    if env::var("DEP_OPENSSL_VERSION_NUMBER_DECIMAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|v| v >= 0x30300000)
    {
        println!("cargo:rustc-cfg=openssl_330");
    }
}
