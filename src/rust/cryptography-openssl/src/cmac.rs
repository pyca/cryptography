// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::ptr;

use foreign_types_shared::{ForeignType, ForeignTypeRef};

use crate::hmac::DigestBytes;
use crate::{cvt, cvt_p, OpenSSLResult};

foreign_types::foreign_type! {
    type CType = ffi::CMAC_CTX;
    fn drop = ffi::CMAC_CTX_free;

    pub struct Cmac;
    pub struct CmacRef;
}

// SAFETY: It's safe to have `&` references from multiple threads.
unsafe impl Sync for Cmac {}
// SAFETY: It's safe to move the `Cmac` from one thread to another.
unsafe impl Send for Cmac {}

impl Cmac {
    pub fn new(key: &[u8], cipher: &openssl::cipher::CipherRef) -> OpenSSLResult<Cmac> {
        // SAFETY: All FFI conditions are handled.
        unsafe {
            let ctx = Cmac::from_ptr(cvt_p(ffi::CMAC_CTX_new())?);
            cvt(ffi::CMAC_Init(
                ctx.as_ptr(),
                key.as_ptr().cast(),
                key.len(),
                cipher.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(ctx)
        }
    }
}

impl CmacRef {
    pub fn update(&mut self, data: &[u8]) -> OpenSSLResult<()> {
        // SAFETY: All FFI conditions are handled.
        unsafe {
            cvt(ffi::CMAC_Update(
                self.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
            ))?;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> OpenSSLResult<DigestBytes> {
        let mut buf = [0; ffi::EVP_MAX_MD_SIZE as usize];
        let mut len = ffi::EVP_MAX_MD_SIZE as usize;
        // SAFETY: All FFI conditions are handled.
        unsafe {
            cvt(ffi::CMAC_Final(self.as_ptr(), buf.as_mut_ptr(), &mut len))?;
        }
        Ok(DigestBytes { buf, len })
    }

    pub fn copy(&self) -> OpenSSLResult<Cmac> {
        // SAFETY: All FFI conditions are handled.
        unsafe {
            let h = Cmac::from_ptr(cvt_p(ffi::CMAC_CTX_new())?);
            cvt(ffi::CMAC_CTX_copy(h.as_ptr(), self.as_ptr()))?;
            Ok(h)
        }
    }
}
