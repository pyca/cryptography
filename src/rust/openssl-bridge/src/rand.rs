use crate::{error::check, ffi, Result};

/// Mix additional input without trusting a caller's entropy estimate. The
/// backend remains responsible for obtaining entropy from the operating system.
pub fn mix_additional_input(input: &[u8]) -> Result<()> {
    crate::initialize()?;
    for chunk in input.chunks(i32::MAX as usize) {
        // SAFETY: Live bounded input; zero entropy credit cannot substitute
        // caller-controlled bytes for the backend's required entropy source.
        unsafe { ffi::RAND_add(chunk.as_ptr().cast(), chunk.len() as _, 0.0) };
    }
    Ok(())
}

pub fn is_ready() -> Result<bool> {
    crate::initialize()?;
    // SAFETY: Native RNG readiness query, without external pointer arguments.
    Ok(unsafe { ffi::RAND_status() == 1 })
}

pub fn fill(output: &mut [u8]) -> Result<()> {
    crate::initialize()?;
    // The common API uses int on OpenSSL and size_t on some forks. Chunking
    // avoids truncation and works for both, including unusually large slices.
    for chunk in output.chunks_mut(i32::MAX as usize) {
        // SAFETY: Each chunk is writable for a length representable by either ABI.
        check(unsafe { ffi::RAND_bytes(chunk.as_mut_ptr(), chunk.len() as _) })?;
    }
    Ok(())
}

/// Fill secret key material using OpenSSL's separate private DRBG where it is
/// available. Forks use their cryptographic RAND_bytes implementation.
pub fn fill_private(output: &mut [u8]) -> Result<()> {
    crate::initialize()?;
    #[cfg(backend = "openssl")]
    {
        for chunk in output.chunks_mut(i32::MAX as usize) {
            // SAFETY: Each exclusive slice covers the checked native length.
            check(unsafe { ffi::RAND_priv_bytes(chunk.as_mut_ptr(), chunk.len() as i32) })?;
        }
        Ok(())
    }
    #[cfg(not(backend = "openssl"))]
    fill(output)
}
