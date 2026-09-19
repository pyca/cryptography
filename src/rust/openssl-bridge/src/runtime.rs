//! Process-lifetime initialization and read-only backend information.
//!
//! Configure FIPS through OpenSSL's configuration file before process startup.
//! This module deliberately has no default-property setter: OpenSSL does not
//! permit that mutation concurrently with operations in this or other libraries.
use crate::ffi;
#[cfg(backend = "openssl")]
use crate::{error::pointer, Error, Result};
use std::ffi::CStr;

pub fn version_number() -> u64 {
    // SAFETY: Pure backend version query with no pointer arguments.
    unsafe { ffi::OpenSSL_version_num() as u64 }
}

pub fn has_implicit_rsa_rejection() -> bool {
    // SAFETY: Pure query of the selected headers' implicit-rejection capability.
    unsafe { ffi::OB_has_implicit_rsa_rejection() != 0 }
}

pub fn version_text() -> String {
    // SAFETY: The version selector returns a static terminated string.
    unsafe { CStr::from_ptr(ffi::OpenSSL_version(ffi::OPENSSL_VERSION as i32)) }
        .to_string_lossy()
        .into_owned()
}

pub fn compiled_version_text() -> String {
    // bindgen copies the selected headers' terminated version literal.
    CStr::from_bytes_until_nul(ffi::OPENSSL_VERSION_TEXT)
        .expect("native version literal is terminated")
        .to_string_lossy()
        .into_owned()
}

pub fn is_fips_enabled() -> bool {
    #[cfg(backend = "openssl")]
    {
        // SAFETY: Read-only query of the default context. This abstraction never
        // mutates its default properties; external native code must likewise
        // obey OpenSSL's initialization-only property mutation contract.
        unsafe { ffi::EVP_default_properties_is_fips_enabled(std::ptr::null_mut()) == 1 }
    }
    #[cfg(backend = "awslc")]
    {
        // SAFETY: Read-only query of AWS-LC's build-time FIPS state.
        unsafe { ffi::FIPS_mode() == 1 }
    }
    #[cfg(any(backend = "boringssl", backend = "libressl"))]
    {
        false
    }
}

/// Check that the process was configured to fetch FIPS implementations. This
/// does not assert that a particular operation or deployment is FIPS validated.
#[cfg(backend = "openssl")]
pub fn require_fips_enabled() -> Result<()> {
    crate::initialize()?;
    if is_fips_enabled() {
        Ok(())
    } else {
        Err(Error::InvalidState(
            "FIPS must be configured through OPENSSL_CONF before starting the process",
        ))
    }
}

#[cfg(backend = "openssl")]
fn load_provider(name: &'static CStr) -> Result<()> {
    crate::initialize()?;
    // SAFETY: A fixed provider name and default context. OpenSSL serializes
    // provider loading. The successful reference is intentionally retained for
    // process lifetime; no unload can invalidate existing algorithm descriptors.
    pointer(unsafe { ffi::OSSL_PROVIDER_load(std::ptr::null_mut(), name.as_ptr()) })?;
    Ok(())
}

/// Retain the standard provider for process lifetime. Repeated calls share the
/// same result and native reference; no provider handle is exposed.
#[cfg(backend = "openssl")]
pub fn load_default_provider() -> Result<()> {
    static LOADED: std::sync::OnceLock<Result<()>> = std::sync::OnceLock::new();
    LOADED.get_or_init(|| load_provider(c"default")).clone()
}

/// Opt in to legacy algorithms for process lifetime. Availability still depends
/// on the backend build and process configuration, including FIPS properties.
#[cfg(backend = "openssl")]
pub fn load_legacy_provider() -> Result<()> {
    static LOADED: std::sync::OnceLock<Result<()>> = std::sync::OnceLock::new();
    LOADED.get_or_init(|| load_provider(c"legacy")).clone()
}
