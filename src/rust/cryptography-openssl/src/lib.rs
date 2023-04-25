// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub mod fips;
pub mod hmac;

pub type OpenSSLResult<T> = Result<T, openssl::error::ErrorStack>;

#[inline]
fn cvt(r: std::os::raw::c_int) -> Result<std::os::raw::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    #[test]
    fn test_cvt() {
        assert!(crate::cvt(-1).is_err());
        assert!(crate::cvt_p(ptr::null_mut::<()>()).is_err());
    }
}
