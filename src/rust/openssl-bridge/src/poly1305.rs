//! Poly1305 with a consuming finalization API. Each key must be used once.
#[cfg(backend = "openssl")]
use crate::{
    error::{check, pointer},
    Error,
};
use crate::{ffi, Result};

pub struct Poly1305 {
    #[cfg(backend = "openssl")]
    ctx: std::ptr::NonNull<ffi::EVP_MAC_CTX>,
    #[cfg(backend = "openssl")]
    poisoned: bool,
    // Keep the native state at one address. Some implementations align their
    // working state within this allocation, so moving its bytes is not valid.
    #[cfg(not(backend = "openssl"))]
    ctx: Box<std::mem::MaybeUninit<ffi::poly1305_state>>,
}
// SAFETY: State is uniquely owned; moving the wrapper leaves its allocation fixed.
unsafe impl Send for Poly1305 {}
// SAFETY: No shared-reference method accesses or changes the native state.
unsafe impl Sync for Poly1305 {}
impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        crate::initialize()?;
        #[cfg(backend = "openssl")]
        {
            // SAFETY: Name is static; NULL uses the process's provider context.
            let mac = pointer(unsafe {
                ffi::EVP_MAC_fetch(std::ptr::null_mut(), c"POLY1305".as_ptr(), std::ptr::null())
            })?;
            // SAFETY: mac is an owned algorithm reference; the new context retains
            // its own reference, including when this reference is freed below.
            let raw = unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr()) };
            // SAFETY: Free exactly the fetched reference, whether allocation worked or not.
            unsafe { ffi::EVP_MAC_free(mac.as_ptr()) };
            let result = Self {
                ctx: pointer(raw)?,
                poisoned: false,
            };
            // SAFETY: Key covers exactly 32 bytes. No algorithm-specific parameters
            // are needed for Poly1305; context owns copied key state.
            check(unsafe {
                ffi::EVP_MAC_init(
                    result.ctx.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    std::ptr::null(),
                )
            })?;
            Ok(result)
        }
        #[cfg(not(backend = "openssl"))]
        {
            let mut ctx = Box::new(std::mem::MaybeUninit::<ffi::poly1305_state>::zeroed());
            // SAFETY: The allocation has the exact native layout and remains at
            // this address until Drop. Keep it in MaybeUninit even after native
            // initialization: unused bytes are never assumed to be Rust values.
            unsafe { ffi::CRYPTO_poly1305_init(ctx.as_mut_ptr(), key.as_ptr()) };
            Ok(Self { ctx })
        }
    }
    pub fn update(&mut self, input: &[u8]) -> Result<()> {
        #[cfg(backend = "openssl")]
        {
            if self.poisoned {
                return Err(Error::InvalidState("Poly1305 context is poisoned"));
            }
            self.poisoned = true;
            // SAFETY: Initialized exclusive context; input covers the supplied length.
            check(unsafe { ffi::EVP_MAC_update(self.ctx.as_ptr(), input.as_ptr(), input.len()) })?;
            self.poisoned = false;
        }
        #[cfg(not(backend = "openssl"))]
        // SAFETY: Initialized exclusive native state at its original address;
        // the borrowed input remains live for the complete call.
        unsafe {
            ffi::CRYPTO_poly1305_update(self.ctx.as_mut_ptr(), input.as_ptr(), input.len())
        };
        Ok(())
    }
    pub fn finish(mut self) -> Result<[u8; 16]> {
        let mut output = [0; 16];
        #[cfg(backend = "openssl")]
        {
            if self.poisoned {
                return Err(Error::InvalidState("Poly1305 context is poisoned"));
            }
            let mut written = 0;
            // SAFETY: Output capacity is supplied explicitly; this consumes the context.
            check(unsafe {
                ffi::EVP_MAC_final(
                    self.ctx.as_ptr(),
                    output.as_mut_ptr(),
                    &mut written,
                    output.len(),
                )
            })?;
            crate::error::check_len(written, output.len())?;
            self.poisoned = true;
        }
        #[cfg(not(backend = "openssl"))]
        // SAFETY: Output is exactly a Poly1305 tag. Context is initialized and is
        // consumed here; Drop erases all remaining native key state afterwards.
        unsafe {
            ffi::CRYPTO_poly1305_finish(self.ctx.as_mut_ptr(), output.as_mut_ptr())
        };
        Ok(output)
    }
}
impl Drop for Poly1305 {
    fn drop(&mut self) {
        #[cfg(backend = "openssl")]
        // SAFETY: This owns the initialized or partially initialized native context.
        unsafe {
            ffi::EVP_MAC_CTX_free(self.ctx.as_ptr())
        };
        #[cfg(not(backend = "openssl"))]
        // SAFETY: The entire native allocation is writable; erasing MaybeUninit
        // bytes does not create invalid Rust values or move the native state.
        unsafe {
            ffi::OPENSSL_cleanse(
                self.ctx.as_mut_ptr().cast(),
                std::mem::size_of::<ffi::poly1305_state>(),
            )
        };
    }
}
