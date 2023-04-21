// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{cvt, cvt_p, OpenSSLResult};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use std::ptr;

foreign_types::foreign_type! {
    type CType = ffi::HMAC_CTX;
    fn drop = ffi::HMAC_CTX_free;

    pub struct Hmac;
    pub struct HmacRef;
}

unsafe impl Sync for Hmac {}
unsafe impl Send for Hmac {}

impl Hmac {
    pub fn new(key: &[u8], md: openssl::hash::MessageDigest) -> OpenSSLResult<Hmac> {
        unsafe {
            let h = Hmac::from_ptr(cvt_p(ffi::HMAC_CTX_new())?);
            cvt(ffi::HMAC_Init_ex(
                h.as_ptr(),
                key.as_ptr().cast(),
                key.len()
                    .try_into()
                    .expect("Key too long for OpenSSL's length type"),
                md.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(h)
        }
    }
}

impl HmacRef {
    pub fn update(&mut self, data: &[u8]) -> OpenSSLResult<()> {
        unsafe {
            cvt(ffi::HMAC_Update(self.as_ptr(), data.as_ptr(), data.len()))?;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> OpenSSLResult<DigestBytes> {
        let mut buf = [0; ffi::EVP_MAX_MD_SIZE as usize];
        let mut len = ffi::EVP_MAX_MD_SIZE as std::os::raw::c_uint;
        unsafe {
            cvt(ffi::HMAC_Final(self.as_ptr(), buf.as_mut_ptr(), &mut len))?;
        }
        Ok(DigestBytes {
            buf,
            len: len.try_into().unwrap(),
        })
    }

    pub fn copy(&self) -> OpenSSLResult<Hmac> {
        unsafe {
            let h = Hmac::from_ptr(cvt_p(ffi::HMAC_CTX_new())?);
            cvt(ffi::HMAC_CTX_copy(h.as_ptr(), self.as_ptr()))?;
            Ok(h)
        }
    }
}

pub struct DigestBytes {
    buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    len: usize,
}

impl std::ops::Deref for DigestBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::DigestBytes;

    #[test]
    fn test_digest_bytes() {
        let d = DigestBytes {
            buf: [19; ffi::EVP_MAX_MD_SIZE as usize],
            len: 12,
        };
        assert_eq!(&*d, b"\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13");
    }
}
