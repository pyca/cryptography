//! Internal, bounded, unsigned native integers. No raw pointer is public.
use crate::{
    error::{check, pointer},
    ffi,
    secret::SecretBytes,
    Error, Result,
};
use std::ptr::{self, NonNull};
pub(crate) struct Number(NonNull<ffi::BIGNUM>);
impl Number {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::BN_new() }).map(Self)
    }
    pub(crate) fn from_bytes(bytes: &[u8], maximum: usize) -> Result<Self> {
        let bytes = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..];
        if bytes.len() > maximum {
            return Err(Error::InvalidInput("integer exceeds algorithm limit"));
        }
        #[allow(clippy::useless_conversion)]
        let length = bytes
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("integer exceeds native limit"))?;
        // SAFETY: Input covers the checked native length. NULL requests a new number.
        pointer(unsafe { ffi::BN_bin2bn(bytes.as_ptr(), length, ptr::null_mut()) }).map(Self)
    }
    pub(crate) fn ptr(&self) -> *mut ffi::BIGNUM {
        self.0.as_ptr()
    }
    pub(crate) fn into_raw(self) -> *mut ffi::BIGNUM {
        let p = self.ptr();
        std::mem::forget(self);
        p
    }
    pub(crate) fn bits(&self) -> usize {
        // SAFETY: The number is initialized and immutable for this query.
        unsafe { ffi::BN_num_bits(self.ptr()) as usize }
    }
    pub(crate) fn positive(&self) -> bool {
        self.bits() != 0
    }
    pub(crate) fn is_one(&self) -> bool {
        // SAFETY: Initialized immutable integer query.
        unsafe { ffi::BN_is_one(self.ptr()) == 1 }
    }
    pub(crate) fn is_prime(&self) -> Result<bool> {
        let ctx = Context::new()?;
        // SAFETY: The bounded integer is initialized, the context is exclusive,
        // and NULL disables callbacks. Explicit rounds cover adversarial imports.
        crate::error::check_bool(unsafe {
            ffi::BN_is_prime_ex(self.ptr(), 64, ctx.0.as_ptr(), ptr::null_mut())
        })
    }
    pub(crate) fn modulo(&self, modulus: &Self) -> Result<Self> {
        if !modulus.positive() {
            return Err(Error::InvalidInput("modulus is zero"));
        }
        let output = Self::new()?;
        let ctx = Context::new()?;
        // SAFETY: Division has a positive divisor, distinct remainder storage,
        // and a unique context. A NULL quotient requests only the remainder.
        check(unsafe {
            ffi::BN_div(
                ptr::null_mut(),
                output.ptr(),
                self.ptr(),
                modulus.ptr(),
                ctx.0.as_ptr(),
            )
        })?;
        Ok(output)
    }
    pub(crate) fn less_than(&self, other: &Self) -> bool {
        // SAFETY: Both numbers are initialized and read-only.
        unsafe { ffi::BN_cmp(self.ptr(), other.ptr()) < 0 }
    }
    pub(crate) fn secret_bytes(&self) -> Result<SecretBytes> {
        let mut out: SecretBytes = vec![0; self.bits().div_ceil(8)].into();
        // SAFETY: Output length is exactly the unsigned number's encoding size.
        let written = unsafe { ffi::BN_bn2bin(self.ptr(), out.as_mut().as_mut_ptr()) };
        crate::error::check_len(written as usize, out.as_ref().len())?;
        Ok(out)
    }
    /// The caller must provide a live, initialized BIGNUM for the duration of the copy.
    pub(crate) unsafe fn copy_raw(number: *const ffi::BIGNUM) -> Result<Self> {
        if number.is_null() {
            return Err(Error::InvalidState("missing key component"));
        }
        // SAFETY: Caller guarantees an initialized number; BN_dup returns an owned copy.
        pointer(unsafe { ffi::BN_dup(number) }).map(Self)
    }
    pub(crate) fn power_mod(base: &Self, exponent: &Self, modulus: &Self) -> Result<Self> {
        // The constant-time Montgomery operation requires a positive odd modulus.
        // SAFETY: Initialized number query is read-only.
        if modulus.bits() < 2 || unsafe { ffi::BN_is_odd(modulus.ptr()) } != 1 {
            return Err(Error::InvalidInput(
                "modulus must be odd and greater than one",
            ));
        }
        let output = Self::new()?;
        let ctx = Context::new()?;
        // SAFETY: All numbers are initialized, the output is distinct, the
        // modulus is odd, and NULL requests an internal Montgomery context.
        check(unsafe {
            ffi::BN_mod_exp_mont_consttime(
                output.ptr(),
                base.ptr(),
                exponent.ptr(),
                modulus.ptr(),
                ctx.0.as_ptr(),
                ptr::null_mut(),
            )
        })?;
        Ok(output)
    }
}
impl Drop for Number {
    fn drop(&mut self) {
        // SAFETY: Exactly one native allocation is owned; erase private values.
        unsafe { ffi::BN_clear_free(self.ptr()) };
    }
}
struct Context(NonNull<ffi::BN_CTX>);
impl Context {
    fn new() -> Result<Self> {
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::BN_CTX_new() }).map(Self)
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: The context is uniquely owned and no numbers escape its lifetime.
        unsafe { ffi::BN_CTX_free(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_integer_validation_and_zero_modulus() {
        assert!(Number::from_bytes(&[1, 0], 1).is_err());
        let one = Number::from_bytes(&[1], 1).unwrap();
        let zero = Number::from_bytes(&[0], 1).unwrap();
        assert!(one.modulo(&zero).is_err());
        // SAFETY: Explicitly exercise the helper's checked NULL rejection.
        assert!(unsafe { Number::copy_raw(ptr::null()) }.is_err());
    }
}
