//! Safe ownership and operation-specific APIs for OpenSSL and its forks.
//!
//! No foreign pointer or raw context is exposed by the safe API. Mutable
//! operations require exclusive access. Failed operations poison their context;
//! finalization consumes it. Fallible allocation and cloning return errors.
pub mod aead;
#[cfg(openssl_320)]
pub mod argon2;
pub mod cipher;
pub mod containers;
pub mod curve25519;
pub mod curve448;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod error;
pub mod gcm;
pub mod hash;
pub mod kdf;
pub mod legacy_key;
pub mod mac;
#[cfg(any(openssl_350, backend = "boringssl", backend = "awslc"))]
pub mod mldsa;
#[cfg(any(openssl_350, backend = "boringssl", backend = "awslc"))]
pub mod mlkem;
mod number;
#[cfg(any(backend = "openssl", backend = "libressl"))]
pub mod pkcs7;
pub mod poly1305;
#[cfg(any(openssl_350, backend = "boringssl", backend = "awslc"))]
mod pq;
pub mod rand;
pub mod rsa;
pub mod runtime;
pub mod secret;
pub mod tls;
pub mod x509;

/// Compare equal-length byte strings without data-dependent early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY: Both inputs are readable for a.len(), including the empty case.
    unsafe { ffi::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

pub use error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    OpenSsl,
    LibreSsl,
    BoringSsl,
    AwsLc,
}

pub const BACKEND: Backend = {
    #[cfg(backend = "openssl")]
    {
        Backend::OpenSsl
    }
    #[cfg(backend = "libressl")]
    {
        Backend::LibreSsl
    }
    #[cfg(backend = "boringssl")]
    {
        Backend::BoringSsl
    }
    #[cfg(backend = "awslc")]
    {
        Backend::AwsLc
    }
};
use openssl_bridge_sys as ffi;

/// Initialize native crypto and error strings exactly once. Disabling native
/// atexit cleanup keeps process-lifetime Rust descriptors valid during shutdown.
/// This does not load providers or change the process's FIPS configuration.
pub fn initialize() -> Result<()> {
    static INITIALIZED: std::sync::OnceLock<Result<()>> = std::sync::OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            // SAFETY: Native initialization is serialized here (and internally by
            // each backend). These flags have no pointer-valued settings.
            error::check(unsafe {
                ffi::OPENSSL_init_crypto(
                    u64::from(ffi::OPENSSL_INIT_LOAD_CRYPTO_STRINGS | ffi::OPENSSL_INIT_NO_ATEXIT),
                    std::ptr::null_mut(),
                )
            })
        })
        .clone()
}
