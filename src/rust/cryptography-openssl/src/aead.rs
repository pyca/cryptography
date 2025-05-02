// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::{ForeignType, ForeignTypeRef};

use crate::{cvt, cvt_p, OpenSSLResult};

pub enum AeadType {
    ChaCha20Poly1305,
}

foreign_types::foreign_type! {
    type CType = ffi::EVP_AEAD_CTX;
    fn drop = ffi::EVP_AEAD_CTX_free;

    pub struct AeadCtx;
    pub struct AeadCtxRef;
}

// SAFETY: Can safely be used from multiple threads concurrently.
unsafe impl Sync for AeadCtx {}
// SAFETY: Can safely be sent between threads.
unsafe impl Send for AeadCtx {}

impl AeadCtx {
    pub fn new(aead: AeadType, key: &[u8]) -> OpenSSLResult<AeadCtx> {
        let aead = match aead {
            // SAFETY: No preconditions.
            AeadType::ChaCha20Poly1305 => unsafe { ffi::EVP_aead_chacha20_poly1305() },
        };

        // SAFETY: We're passing a valid key and aead.
        unsafe {
            let ctx = cvt_p(ffi::EVP_AEAD_CTX_new(
                aead,
                key.as_ptr(),
                key.len(),
                ffi::EVP_AEAD_DEFAULT_TAG_LENGTH as usize,
            ))?;
            Ok(AeadCtx::from_ptr(ctx))
        }
    }
}

impl AeadCtxRef {
    pub fn encrypt(
        &self,
        data: &[u8],
        nonce: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> OpenSSLResult<()> {
        let mut out_len = out.len();
        // SAFETY: All the lengths and pointers are known valid.
        unsafe {
            cvt(ffi::EVP_AEAD_CTX_seal(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                data.len(),
                ad.as_ptr(),
                ad.len(),
            ))?;
        }
        Ok(())
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        nonce: &[u8],
        ad: &[u8],
        out: &mut [u8],
    ) -> OpenSSLResult<()> {
        let mut out_len = out.len();
        // SAFETY: All the lengths and pointers are known valid.
        unsafe {
            cvt(ffi::EVP_AEAD_CTX_open(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                out.len(),
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                data.len(),
                ad.as_ptr(),
                ad.len(),
            ))?;
        }
        Ok(())
    }
}
