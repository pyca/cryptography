// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::ForeignType;
use openssl_sys as ffi;
use std::os::raw::c_int;

use crate::{cvt, cvt_p, OpenSSLResult};

pub const PKEY_ID: openssl::pkey::Id = openssl::pkey::Id::from_raw(ffi::NID_kem);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    pub fn nid(self) -> c_int {
        match self {
            MlKemVariant::MlKem768 => ffi::NID_MLKEM768,
            MlKemVariant::MlKem1024 => ffi::NID_MLKEM1024,
        }
    }

    pub fn from_pkey<T: openssl::pkey::HasPublic>(
        pkey: &openssl::pkey::PKeyRef<T>,
    ) -> MlKemVariant {
        // AWS-LC is missing the equivalent `EVP_PKEY_pqdsa_get_type`, so we
        // are using the key size as a discriminator to find the variant.
        let len = pkey
            .raw_public_key()
            .expect("valid ML-KEM public key")
            .len();
        match len {
            1184 => MlKemVariant::MlKem768,
            1568 => MlKemVariant::MlKem1024,
            _ => panic!("Unsupported ML-KEM variant"),
        }
    }
}

extern "C" {
    // Manually declared because this function is in an experimental header
    // in AWS-LC (April 2026).
    // https://github.com/aws/aws-lc/blob/23b13826748f942ed7d6c4bcb9971dc9244cbc6f/include/openssl/experimental/kem_deterministic_api.h#L31
    fn EVP_PKEY_keygen_deterministic(
        ctx: *mut ffi::EVP_PKEY_CTX,
        out_pkey: *mut *mut ffi::EVP_PKEY,
        seed: *const u8,
        seed_len: *mut usize,
    ) -> c_int;
}

pub fn new_raw_private_key(
    variant: MlKemVariant,
    seed: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new_id(PKEY_ID)?;
    // SAFETY: ctx is a valid EVP_PKEY_CTX for KEM.
    unsafe {
        cvt(ffi::EVP_PKEY_CTX_kem_set_params(
            ctx.as_ptr(),
            variant.nid(),
        ))?
    };
    // SAFETY: ctx is a valid EVP_PKEY_CTX with KEM params set.
    unsafe { cvt(ffi::EVP_PKEY_keygen_init(ctx.as_ptr()))? };

    let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();
    let mut seed_len = seed.len();
    // SAFETY: ctx is initialized for keygen, seed points to valid memory.
    unsafe {
        cvt(EVP_PKEY_keygen_deterministic(
            ctx.as_ptr(),
            &mut pkey,
            seed.as_ptr(),
            &mut seed_len,
        ))?;
    }
    let expected_seed_len = match variant {
        MlKemVariant::MlKem768 | MlKemVariant::MlKem1024 => 64,
    };
    assert_eq!(seed_len, expected_seed_len);
    // SAFETY: EVP_PKEY_keygen_deterministic succeeded, pkey is valid.
    let pkey = unsafe { openssl::pkey::PKey::from_ptr(pkey) };
    Ok(pkey)
}

pub fn new_raw_public_key(
    variant: MlKemVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    // SAFETY: data points to valid memory of the given length.
    unsafe {
        let pkey = cvt_p(ffi::EVP_PKEY_kem_new_raw_public_key(
            variant.nid(),
            data.as_ptr(),
            data.len(),
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn encapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> OpenSSLResult<(Vec<u8>, Vec<u8>)> {
    let (ct_bytes, ss_bytes) = match MlKemVariant::from_pkey(pkey) {
        MlKemVariant::MlKem768 => (1088, 32),
        MlKemVariant::MlKem1024 => (1568, 32),
    };
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;

    let mut ciphertext = vec![0u8; ct_bytes];
    let mut shared_secret = vec![0u8; ss_bytes];
    let mut ct_len = ciphertext.len();
    let mut ss_len = shared_secret.len();
    // SAFETY: ctx is a valid EVP_PKEY_CTX, buffers are correctly sized.
    unsafe {
        cvt(ffi::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ciphertext.as_mut_ptr(),
            &mut ct_len,
            shared_secret.as_mut_ptr(),
            &mut ss_len,
        ))?;
    }
    assert_eq!(ct_len, ct_bytes);
    assert_eq!(ss_len, ss_bytes);
    Ok((ciphertext, shared_secret))
}

pub fn decapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    ciphertext: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;

    let ss_bytes: usize = match MlKemVariant::from_pkey(pkey) {
        MlKemVariant::MlKem768 | MlKemVariant::MlKem1024 => 32,
    };
    let mut shared_secret = vec![0u8; ss_bytes];
    let mut ss_len = ss_bytes;
    // SAFETY: ctx is a valid EVP_PKEY_CTX, buffers are correctly sized.
    unsafe {
        cvt(ffi::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            shared_secret.as_mut_ptr(),
            &mut ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }
    assert_eq!(ss_len, ss_bytes);
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::MlKemVariant;

    #[test]
    #[should_panic(expected = "Unsupported ML-KEM variant")]
    fn test_from_pkey_wrong_type() {
        let key = openssl::pkey::PKey::generate_ed25519().unwrap();
        MlKemVariant::from_pkey(&key);
    }
}
