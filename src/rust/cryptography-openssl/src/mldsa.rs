// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::ForeignType;
use openssl_sys as ffi;
use std::os::raw::c_int;

use crate::{cvt_p, OpenSSLResult};

pub const NID_ML_DSA_65: c_int = ffi::NID_MLDSA65;
pub const NID_PQDSA: c_int = ffi::NID_PQDSA;
const MLDSA65_SIGNATURE_BYTES: usize = 3309;
pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const MLDSA65_SEED_BYTES: usize = 32;

extern "C" {
    // We call ml_dsa_65_sign/verify directly instead of going through
    // EVP_DigestSign/EVP_DigestVerify because the EVP PQDSA path hardcodes
    // context to (NULL, 0), so we'd lose context string support.
    fn ml_dsa_65_sign(
        private_key: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_65_verify(
        public_key: *const u8,
        sig: *const u8,
        sig_len: usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;
}

/// Generate a random 32-byte ML-DSA-65 seed.
pub fn generate_seed() -> OpenSSLResult<[u8; MLDSA65_SEED_BYTES]> {
    let mut seed = [0u8; MLDSA65_SEED_BYTES];
    openssl::rand::rand_bytes(&mut seed)?;
    Ok(seed)
}

pub fn new_raw_private_key(
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    // SAFETY: EVP_PKEY_pqdsa_new_raw_private_key creates a new EVP_PKEY from
    // raw key bytes. For ML-DSA-65, a 32-byte seed expands into the full
    // keypair.
    unsafe {
        let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_private_key(
            NID_ML_DSA_65,
            data.as_ptr(),
            data.len(),
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn new_raw_public_key(
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    // SAFETY: EVP_PKEY_pqdsa_new_raw_public_key creates a new EVP_PKEY from
    // raw public key bytes.
    unsafe {
        let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_public_key(
            NID_ML_DSA_65,
            data.as_ptr(),
            data.len(),
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn sign(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    let raw_key = pkey.raw_private_key()?;

    let mut sig = vec![0u8; MLDSA65_SIGNATURE_BYTES];
    let mut sig_len: usize = 0;

    let msg_ptr = if data.is_empty() {
        std::ptr::null()
    } else {
        data.as_ptr()
    };
    let ctx_ptr = if context.is_empty() {
        std::ptr::null()
    } else {
        context.as_ptr()
    };

    // SAFETY: ml_dsa_65_sign takes raw key bytes, message, and context.
    let r = unsafe {
        ml_dsa_65_sign(
            raw_key.as_ptr(),
            sig.as_mut_ptr(),
            &mut sig_len,
            msg_ptr,
            data.len(),
            ctx_ptr,
            context.len(),
        )
    };

    if r != 1 {
        return Err(openssl::error::ErrorStack::get());
    }

    sig.truncate(sig_len);
    Ok(sig)
}

pub fn verify(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    signature: &[u8],
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<bool> {
    let raw_key = pkey.raw_public_key()?;

    let msg_ptr = if data.is_empty() {
        std::ptr::null()
    } else {
        data.as_ptr()
    };
    let ctx_ptr = if context.is_empty() {
        std::ptr::null()
    } else {
        context.as_ptr()
    };

    // SAFETY: ml_dsa_65_verify takes raw key bytes, signature, message,
    // and context.
    let r = unsafe {
        ml_dsa_65_verify(
            raw_key.as_ptr(),
            signature.as_ptr(),
            signature.len(),
            msg_ptr,
            data.len(),
            ctx_ptr,
            context.len(),
        )
    };

    if r != 1 {
        // Clear any errors from the OpenSSL error stack to prevent
        // leaking errors into subsequent operations.
        let _ = openssl::error::ErrorStack::get();
    }

    Ok(r == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_with_context_too_long_returns_error() {
        // ML-DSA context strings are limited to 255 bytes.
        // Passing a 256-byte context to ml_dsa_65_sign triggers
        // an FFI error return.
        let seed = generate_seed().unwrap();
        let pkey = new_raw_private_key(&seed).unwrap();
        let long_ctx = [0x41u8; 256];
        let result = sign(&pkey, b"test", &long_ctx);
        assert!(result.is_err());
    }
}
