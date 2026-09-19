//! Argon2 version 1.3 with explicit, validated work parameters.
//!
//! Lanes affect the derived key. This API processes them with one worker and
//! does not change OpenSSL's process-wide thread pool configuration.
use crate::{
    error::{check, pointer},
    ffi,
    secret::SecretBytes,
    Error, Result,
};
use std::{ffi::CStr, num::NonZeroU32, ptr};

#[derive(Clone, Copy)]
pub enum Variant {
    D,
    I,
    Id,
}
impl Variant {
    fn name(self) -> &'static CStr {
        match self {
            Self::D => c"ARGON2D",
            Self::I => c"ARGON2I",
            Self::Id => c"ARGON2ID",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Parameters {
    iterations: NonZeroU32,
    lanes: NonZeroU32,
    memory_kib: u32,
}
impl Parameters {
    pub fn new(iterations: NonZeroU32, lanes: NonZeroU32, memory_kib: u32) -> Result<Self> {
        if lanes.get() >= (1 << 24) || u64::from(memory_kib) < 8 * u64::from(lanes.get()) {
            return Err(Error::InvalidInput(
                "invalid Argon2 lane count or memory cost",
            ));
        }
        Ok(Self {
            iterations,
            lanes,
            memory_kib,
        })
    }

    /// Derive into an exclusively borrowed output buffer. On native failure,
    /// erase the entire output. Optional associated data and secret pepper are
    /// copied into erased-on-drop storage before passing writable ABI pointers.
    pub fn derive_into(
        self,
        variant: Variant,
        password: &[u8],
        salt: &[u8],
        associated_data: Option<&[u8]>,
        secret: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<()> {
        if salt.len() < 8 || output.len() < 4 {
            return Err(Error::InvalidInput(
                "Argon2 requires at least 8 salt bytes and 4 output bytes",
            ));
        }
        for input in [
            password,
            salt,
            associated_data.unwrap_or(&[]),
            secret.unwrap_or(&[]),
        ] {
            u32::try_from(input.len())
                .map_err(|_| Error::InvalidInput("Argon2 input exceeds its length limit"))?;
        }
        let size = u32::try_from(output.len())
            .map_err(|_| Error::InvalidInput("Argon2 output exceeds its length limit"))?;
        crate::initialize()?;
        struct Kdf(*mut ffi::EVP_KDF);
        impl Drop for Kdf {
            fn drop(&mut self) {
                // SAFETY: Sole fetched reference; contexts retain their own.
                unsafe { ffi::EVP_KDF_free(self.0) };
            }
        }
        struct Context(*mut ffi::EVP_KDF_CTX);
        impl Drop for Context {
            fn drop(&mut self) {
                // SAFETY: Sole ownership; native Argon2 cleanup erases secrets.
                unsafe { ffi::EVP_KDF_CTX_free(self.0) };
            }
        }
        // SAFETY: Static terminated name; NULL selects the default library context.
        let kdf = Kdf(pointer(unsafe {
            ffi::EVP_KDF_fetch(ptr::null_mut(), variant.name().as_ptr(), ptr::null())
        })?
        .as_ptr());
        // SAFETY: Live fetched KDF; result is a fresh context.
        let ctx = Context(pointer(unsafe { ffi::EVP_KDF_CTX_new(kdf.0) })?.as_ptr());
        let mut password = SecretBytes::from(password.to_vec());
        let mut salt = SecretBytes::from(salt.to_vec());
        let mut ad = SecretBytes::from(associated_data.unwrap_or(&[]).to_vec());
        let mut secret = SecretBytes::from(secret.unwrap_or(&[]).to_vec());
        // SAFETY: The shim borrows these exclusively owned buffers for this
        // synchronous derive and constructs all OSSL_PARAM values on its stack.
        let result = check(unsafe {
            ffi::OB_argon2_derive(
                ctx.0,
                output.as_mut_ptr(),
                output.len(),
                password.as_mut().as_mut_ptr().cast(),
                password.as_ref().len(),
                salt.as_mut().as_mut_ptr().cast(),
                salt.as_ref().len(),
                ad.as_mut().as_mut_ptr().cast(),
                ad.as_ref().len(),
                secret.as_mut().as_mut_ptr().cast(),
                secret.as_ref().len(),
                self.iterations.get(),
                self.lanes.get(),
                self.memory_kib,
                size,
            )
        });
        if result.is_err() {
            crate::secret::erase(output);
        }
        result
    }
}
