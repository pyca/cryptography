use crate::{error::check, ffi, hash::Algorithm, Error, Result};
use std::num::NonZeroU32;

// Lengths/counts use signed int on OpenSSL/LibreSSL, but size_t/u32 on forks.
#[allow(clippy::useless_conversion)]
pub fn pbkdf2_hmac(
    algorithm: Algorithm,
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    output: &mut [u8],
) -> Result<()> {
    if algorithm.is_xof() {
        return Err(Error::InvalidInput("PBKDF2 requires a fixed-output digest"));
    }
    let password_length = password
        .len()
        .try_into()
        .map_err(|_| Error::InvalidInput("password is too long"))?;
    let salt_length = salt
        .len()
        .try_into()
        .map_err(|_| Error::InvalidInput("salt is too long"))?;
    let iterations = iterations
        .get()
        .try_into()
        .map_err(|_| Error::InvalidInput("iteration count is too large"))?;
    let output_length = output
        .len()
        .try_into()
        .map_err(|_| Error::InvalidInput("derived key is too long"))?;
    // SAFETY: All lengths fit the target backend ABI, each slice covers its
    // declared length, and the output does not alias either input.
    check(unsafe {
        ffi::PKCS5_PBKDF2_HMAC(
            password.as_ptr().cast(),
            password_length,
            salt.as_ptr(),
            salt_length,
            iterations,
            algorithm.as_ptr(),
            output_length,
            output.as_mut_ptr(),
        )
    })
}

#[cfg(not(backend = "libressl"))]
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    max_memory: u64,
    output: &mut [u8],
) -> Result<()> {
    crate::initialize()?;
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
        return Err(Error::InvalidInput("invalid scrypt work parameters"));
    }
    if max_memory == 0 {
        return Err(Error::InvalidInput(
            "an explicit scrypt memory limit is required",
        ));
    }
    #[allow(clippy::useless_conversion)]
    let max_memory = max_memory
        .try_into()
        .map_err(|_| Error::InvalidInput("memory limit is too large for this backend"))?;
    // SAFETY: Slices cover their lengths and do not alias. The backend validates
    // memory/work arithmetic and enforces max_memory before allocation.
    check(unsafe {
        ffi::EVP_PBE_scrypt(
            password.as_ptr().cast(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            n,
            r,
            p,
            max_memory,
            output.as_mut_ptr(),
            output.len(),
        )
    })
}

#[cfg(backend = "libressl")]
pub fn scrypt(
    _password: &[u8],
    _salt: &[u8],
    _n: u64,
    _r: u64,
    _p: u64,
    _max_memory: u64,
    _output: &mut [u8],
) -> Result<()> {
    Err(Error::Unsupported("LibreSSL does not provide scrypt"))
}
