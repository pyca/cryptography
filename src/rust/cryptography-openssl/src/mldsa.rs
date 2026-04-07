// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl_sys as ffi;
use std::os::raw::c_int;

use crate::{cvt, cvt_p, OpenSSLResult};

pub const PKEY_ID: openssl::pkey::Id = openssl::pkey::Id::from_raw(ffi::NID_PQDSA);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
}

impl MlDsaVariant {
    pub fn nid(self) -> c_int {
        match self {
            MlDsaVariant::MlDsa44 => ffi::NID_MLDSA44,
            MlDsaVariant::MlDsa65 => ffi::NID_MLDSA65,
        }
    }

    pub fn from_pkey<T: openssl::pkey::HasPublic>(
        pkey: &openssl::pkey::PKeyRef<T>,
    ) -> MlDsaVariant {
        // SAFETY: EVP_PKEY_pqdsa_get_type returns the NID of the PQDSA
        // algorithm for a valid PQDSA pkey.
        let nid = unsafe { ffi::EVP_PKEY_pqdsa_get_type(pkey.as_ptr()) };
        match nid {
            ffi::NID_MLDSA44 => MlDsaVariant::MlDsa44,
            ffi::NID_MLDSA65 => MlDsaVariant::MlDsa65,
            _ => panic!("Unsupported ML-DSA variant"),
        }
    }
}

extern "C" {
    // We call ml_dsa_{44,65}_sign/verify directly instead of going through
    // EVP_DigestSign/EVP_DigestVerify because the EVP PQDSA path hardcodes
    // context to (NULL, 0), so we'd lose context string support.
    fn ml_dsa_44_sign(
        private_key: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_44_verify(
        public_key: *const u8,
        sig: *const u8,
        sig_len: usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

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

pub fn new_raw_private_key(
    variant: MlDsaVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    // SAFETY: EVP_PKEY_pqdsa_new_raw_private_key creates a new EVP_PKEY from
    // raw key bytes. For ML-DSA, a seed expands into the full keypair.
    unsafe {
        let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_private_key(
            variant.nid(),
            data.as_ptr(),
            data.len(),
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn new_raw_public_key(
    variant: MlDsaVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    // SAFETY: EVP_PKEY_pqdsa_new_raw_public_key creates a new EVP_PKEY from
    // raw public key bytes.
    unsafe {
        let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_public_key(
            variant.nid(),
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
    let variant = MlDsaVariant::from_pkey(pkey);

    type SignFn = unsafe extern "C" fn(
        *const u8,
        *mut u8,
        *mut usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int;
    let (signature_bytes, sign_func): (usize, SignFn) = match variant {
        MlDsaVariant::MlDsa44 => (2420, ml_dsa_44_sign),
        MlDsaVariant::MlDsa65 => (3309, ml_dsa_65_sign),
    };

    let mut sig = vec![0u8; signature_bytes];
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

    // SAFETY: The sign function takes raw key bytes, message, and context.
    unsafe {
        let r = sign_func(
            raw_key.as_ptr(),
            sig.as_mut_ptr(),
            &mut sig_len,
            msg_ptr,
            data.len(),
            ctx_ptr,
            context.len(),
        );
        cvt(r)?;
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
    let variant = MlDsaVariant::from_pkey(pkey);

    type VerifyFn = unsafe extern "C" fn(
        *const u8,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
    ) -> c_int;
    let verify_func: VerifyFn = match variant {
        MlDsaVariant::MlDsa44 => ml_dsa_44_verify,
        MlDsaVariant::MlDsa65 => ml_dsa_65_verify,
    };

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

    // SAFETY: The verify function takes raw key bytes, signature, message,
    // and context.
    let r = unsafe {
        verify_func(
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
    use super::MlDsaVariant;

    #[test]
    #[should_panic(expected = "Unsupported ML-DSA variant")]
    fn test_from_pkey_wrong_type() {
        let key = openssl::pkey::PKey::generate_ed25519().unwrap();
        MlDsaVariant::from_pkey(&key);
    }
}
