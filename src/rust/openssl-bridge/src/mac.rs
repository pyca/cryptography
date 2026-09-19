use crate::{
    error::{check, pointer},
    ffi,
    hash::Algorithm,
    Error, Result,
};
use std::ptr::{self, NonNull};

pub struct Hmac {
    ctx: NonNull<ffi::HMAC_CTX>,
    size: usize,
    poisoned: bool,
}

// SAFETY: Each context is owned exclusively and mutated through &mut self only.
unsafe impl Send for Hmac {}
// SAFETY: Shared methods only copy the native state; they do not modify it.
unsafe impl Sync for Hmac {}

impl Hmac {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        if algorithm.is_xof() {
            return Err(Error::InvalidInput("HMAC requires a fixed-output digest"));
        }
        let size = algorithm.output_size()?;
        #[allow(clippy::useless_conversion)]
        let key_len = key
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("HMAC key is too long"))?;
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::HMAC_CTX_new() })?;
        let result = Self {
            ctx,
            size,
            poisoned: false,
        };
        // SAFETY: ctx is owned, key covers key_len, md is a live descriptor.
        // Even an empty key supplies a non-NULL pointer so it does not mean reuse.
        check(unsafe {
            ffi::HMAC_Init_ex(
                ctx.as_ptr(),
                key.as_ptr().cast(),
                key_len,
                algorithm.as_ptr(),
                ptr::null_mut(),
            )
        })?;
        Ok(result)
    }

    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState("HMAC context is poisoned"))
        } else {
            Ok(())
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.ready()?;
        self.poisoned = true;
        // SAFETY: The initialized context is exclusive; data covers its length.
        check(unsafe { ffi::HMAC_Update(self.ctx.as_ptr(), data.as_ptr(), data.len()) })?;
        self.poisoned = false;
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        self.ready()?;
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::HMAC_CTX_new() })?;
        let result = Self {
            ctx,
            size: self.size,
            poisoned: false,
        };
        // SAFETY: The source is initialized and the destination is uniquely owned.
        check(unsafe { ffi::HMAC_CTX_copy(ctx.as_ptr(), self.ctx.as_ptr()) })?;
        Ok(result)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.ready()?;
        let mut output = vec![0; self.size];
        let mut written = 0;
        // SAFETY: The output fits the selected digest; this consumes the context.
        check(unsafe { ffi::HMAC_Final(self.ctx.as_ptr(), output.as_mut_ptr(), &mut written) })?;
        if written as usize != output.len() {
            return Err(Error::InvalidState(
                "backend returned an unexpected MAC length",
            ));
        }
        Ok(output)
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        // SAFETY: This is the unique owner; free accepts partially initialized state.
        unsafe { ffi::HMAC_CTX_free(self.ctx.as_ptr()) };
    }
}

#[derive(Clone, Copy)]
pub enum CmacCipher {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Des,
    Camellia128,
    Camellia192,
    Camellia256,
    Sm4,
    Seed,
    Blowfish,
    Cast5,
    Idea,
    Rc2,
}

impl CmacCipher {
    /// Resolve a conventional CBC cipher name. AEAD, composite TLS ciphers,
    /// and arbitrary user-defined descriptors are deliberately excluded.
    pub fn from_cbc_name(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-CBC" => Ok(Self::Aes128),
            "AES-192-CBC" => Ok(Self::Aes192),
            "AES-256-CBC" => Ok(Self::Aes256),
            "DES-EDE3-CBC" => Ok(Self::TripleDes),
            "DES-CBC" => Ok(Self::Des),
            "CAMELLIA-128-CBC" => Ok(Self::Camellia128),
            "CAMELLIA-192-CBC" => Ok(Self::Camellia192),
            "CAMELLIA-256-CBC" => Ok(Self::Camellia256),
            "SM4-CBC" => Ok(Self::Sm4),
            "SEED-CBC" => Ok(Self::Seed),
            "BF-CBC" => Ok(Self::Blowfish),
            "CAST5-CBC" => Ok(Self::Cast5),
            "IDEA-CBC" => Ok(Self::Idea),
            "RC2-CBC" => Ok(Self::Rc2),
            _ => Err(Error::Unsupported("unsupported CMAC cipher")),
        }
    }

    fn descriptor(self) -> *const ffi::EVP_CIPHER {
        let name = match self {
            Self::Aes128 => c"AES-128-CBC",
            Self::Aes192 => c"AES-192-CBC",
            Self::Aes256 => c"AES-256-CBC",
            Self::TripleDes => c"DES-EDE3-CBC",
            Self::Des => c"DES-CBC",
            Self::Camellia128 => c"CAMELLIA-128-CBC",
            Self::Camellia192 => c"CAMELLIA-192-CBC",
            Self::Camellia256 => c"CAMELLIA-256-CBC",
            Self::Sm4 => c"SM4-CBC",
            Self::Seed => c"SEED-CBC",
            Self::Blowfish => c"BF-CBC",
            Self::Cast5 => c"CAST5-CBC",
            Self::Idea => c"IDEA-CBC",
            Self::Rc2 => c"RC2-CBC",
        };
        // SAFETY: Static NUL-terminated name; lookup returns an immutable
        // process-lifetime descriptor or NULL for an unavailable algorithm.
        unsafe { ffi::EVP_get_cipherbyname(name.as_ptr()) }
    }

    fn variable_key_length(self) -> bool {
        matches!(self, Self::Blowfish | Self::Cast5 | Self::Rc2)
    }
}

pub struct Cmac {
    ctx: NonNull<ffi::CMAC_CTX>,
    size: usize,
    poisoned: bool,
}
// SAFETY: The context is uniquely owned; mutation requires exclusive access.
unsafe impl Send for Cmac {}
// SAFETY: Shared operations only copy state and never mutate the source.
unsafe impl Sync for Cmac {}

impl Cmac {
    pub fn new(cipher: CmacCipher, key: &[u8]) -> Result<Self> {
        crate::initialize()?;
        let descriptor = cipher.descriptor();
        if descriptor.is_null() {
            return Err(Error::Unsupported("CMAC cipher is unavailable"));
        }
        // SAFETY: The descriptor is valid and non-NULL.
        let (key_size, block_size) = unsafe {
            (
                ffi::OB_cipher_key_size(descriptor),
                ffi::OB_cipher_block_size(descriptor),
            )
        };
        if key.is_empty() || key.len() > i32::MAX as usize {
            return Err(Error::InvalidInput("invalid CMAC key length"));
        }
        if !cipher.variable_key_length() && key.len() != key_size as usize {
            return Err(Error::InvalidInput("incorrect CMAC key length"));
        }
        let size = usize::try_from(block_size)
            .ok()
            .filter(|v| matches!(*v, 8 | 16))
            .ok_or(Error::Unsupported("CMAC cipher has no block size"))?;
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::CMAC_CTX_new() })?;
        let result = Self {
            ctx,
            size,
            poisoned: false,
        };
        // SAFETY: ctx is owned. CMAC_Init configures the cipher's key length
        // before reading the key; the supplied length is bounded by INT_MAX for
        // forks that narrow it internally. Fixed key sizes are checked above.
        check(unsafe {
            ffi::CMAC_Init(
                ctx.as_ptr(),
                key.as_ptr().cast(),
                key.len(),
                descriptor,
                ptr::null_mut(),
            )
        })?;
        Ok(result)
    }

    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState("CMAC context is poisoned"))
        } else {
            Ok(())
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.ready()?;
        self.poisoned = true;
        // SAFETY: The initialized context is exclusive; data covers its length.
        check(unsafe { ffi::CMAC_Update(self.ctx.as_ptr(), data.as_ptr().cast(), data.len()) })?;
        self.poisoned = false;
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        self.ready()?;
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::CMAC_CTX_new() })?;
        let result = Self {
            ctx,
            size: self.size,
            poisoned: false,
        };
        // SAFETY: The initialized source is live and destination is uniquely owned.
        check(unsafe { ffi::CMAC_CTX_copy(ctx.as_ptr(), self.ctx.as_ptr()) })?;
        Ok(result)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.ready()?;
        let mut output = vec![0; self.size];
        let mut written = 0;
        // SAFETY: The output fits the selected cipher's block size. Context is
        // initialized, has not been finalized, and is consumed by this method.
        check(unsafe { ffi::CMAC_Final(self.ctx.as_ptr(), output.as_mut_ptr(), &mut written) })?;
        if written != output.len() {
            return Err(Error::InvalidState("unexpected CMAC output length"));
        }
        Ok(output)
    }
}
impl Drop for Cmac {
    fn drop(&mut self) {
        // SAFETY: This is the sole owner; free accepts partially initialized state.
        unsafe { ffi::CMAC_CTX_free(self.ctx.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poisoned_macs_reject_updates_cloning_and_finalization() {
        let mut h = Hmac::new(Algorithm::from_name("SHA256").unwrap(), b"key").unwrap();
        h.poisoned = true;
        assert!(h.update(b"message").is_err());
        assert!(h.try_clone().is_err());
        assert!(h.finish().is_err());
        let mut c = Cmac::new(CmacCipher::Aes128, &[0; 16]).unwrap();
        c.poisoned = true;
        assert!(c.update(b"message").is_err());
        assert!(c.try_clone().is_err());
        assert!(c.finish().is_err());
    }
}
