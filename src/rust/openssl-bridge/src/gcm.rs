use crate::cipher::{cleanse, Context, Direction};
use crate::{error::check, ffi, Error, Result};
use std::ptr;

/// Algorithms with the same GCM protocol. Other authenticated modes are not
/// accepted here: their ordering rules and output bounds differ.
#[derive(Clone, Copy, Debug)]
pub enum GcmCipher {
    Aes128,
    Aes192,
    Aes256,
    Sm4,
}
impl GcmCipher {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Ok(Self::Aes128),
            "AES-192-GCM" => Ok(Self::Aes192),
            "AES-256-GCM" => Ok(Self::Aes256),
            "SM4-GCM" => Ok(Self::Sm4),
            _ => Err(Error::Unsupported("unsupported GCM cipher")),
        }
    }
    fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Aes128 => c"AES-128-GCM",
            Self::Aes192 => c"AES-192-GCM",
            Self::Aes256 => c"AES-256-GCM",
            Self::Sm4 => c"SM4-GCM",
        }
    }
    pub fn is_available(self) -> bool {
        crate::cipher::Descriptor::lookup(self.name()).is_ok()
    }
}

struct GcmState {
    ctx: Context,
    _descriptor: crate::cipher::Descriptor,
    payload_started: bool,
    poisoned: bool,
    data_remaining: u64,
    aad_remaining: u64,
}
impl GcmState {
    fn new(cipher: GcmCipher, direction: Direction, key: &[u8], nonce: &[u8]) -> Result<Self> {
        let descriptor = crate::cipher::Descriptor::lookup(cipher.name())?;
        if key.len() != descriptor.sizes()?.0 {
            return Err(Error::InvalidInput("incorrect GCM key length"));
        }
        if nonce.is_empty() || nonce.len() > i32::MAX as usize {
            return Err(Error::InvalidInput("incorrect GCM nonce length"));
        }
        let mut ctx = Context::new()?;
        let encrypt = matches!(direction, Direction::Encrypt) as i32;
        // SAFETY: Select GCM on an owned context before configuring the IV length.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                descriptor.ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                encrypt,
            )
        })?;
        // SAFETY: This GCM control accepts an integer length and ignores its pointer.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                ctx.ptr(),
                ffi::EVP_CTRL_GCM_SET_IVLEN as i32,
                nonce.len() as i32,
                ptr::null_mut(),
            )
        })?;
        // SAFETY: Key and nonce cover the exact lengths configured above.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                ptr::null(),
                ptr::null_mut(),
                key.as_ptr(),
                nonce.as_ptr(),
                encrypt,
            )
        })?;
        Ok(Self {
            ctx,
            _descriptor: descriptor,
            payload_started: false,
            poisoned: false,
            data_remaining: (1u64 << 36) - 32,
            aad_remaining: (1u64 << 61) - 1,
        })
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState("GCM context is poisoned"))
        } else {
            Ok(())
        }
    }
    fn aad(&mut self, aad: &[u8]) -> Result<()> {
        self.ready()?;
        if self.payload_started {
            return Err(Error::InvalidState("AAD must precede payload"));
        }
        crate::error::input_length::<i32>(aad.len(), "AAD chunk exceeds INT_MAX")?;
        let remaining = self
            .aad_remaining
            .checked_sub(aad.len() as u64)
            .ok_or(Error::InvalidInput("GCM AAD limit exceeded"))?;
        self.poisoned = true;
        let mut written = 0;
        // SAFETY: NULL output selects AAD for this initialized GCM context, before
        // any payload. The input covers a length representable by signed int.
        check(unsafe {
            ffi::EVP_CipherUpdate(
                self.ctx.ptr(),
                ptr::null_mut(),
                &mut written,
                aad.as_ptr(),
                aad.len() as i32,
            )
        })?;
        self.aad_remaining = remaining;
        self.poisoned = false;
        Ok(())
    }
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.ready()?;
        crate::error::input_length::<i32>(input.len(), "GCM chunk exceeds INT_MAX")?;
        if output.len() < input.len() {
            return Err(Error::InvalidInput("GCM output buffer is too small"));
        }
        let remaining = self
            .data_remaining
            .checked_sub(input.len() as u64)
            .ok_or(Error::InvalidInput("GCM payload limit exceeded"))?;
        self.poisoned = true;
        let mut written = 0;
        // SAFETY: GCM has no block buffering, so output fits every write. Borrows
        // are disjoint, context is exclusive, and input length fits signed int.
        let result = check(unsafe {
            ffi::EVP_CipherUpdate(
                self.ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input.len() as i32,
            )
        });
        crate::secret::clear_on_error(result, &mut output[..input.len()])?;
        crate::secret::clear_on_error(
            crate::error::check_len(written as usize, input.len()),
            &mut output[..input.len()],
        )?;
        self.data_remaining = remaining;
        self.payload_started = true;
        self.poisoned = false;
        Ok(input.len())
    }
    fn finish(&mut self) -> Result<()> {
        self.ready()?;
        self.poisoned = true;
        let mut output = [0; 32];
        let mut written = 0;
        // SAFETY: Context has not been finalized; output fits a full block. GCM
        // emits no bytes here, but we supply storage defensively and cleanse it.
        let result = check(unsafe {
            ffi::EVP_CipherFinal_ex(self.ctx.ptr(), output.as_mut_ptr(), &mut written)
        });
        cleanse(&mut output);
        result?;
        crate::error::check_len(written as usize, 0)?;
        Ok(())
    }
}

/// Streaming GCM encryption. Never reuse a nonce with the same key.
pub struct GcmEncrypt(GcmState);
impl GcmEncrypt {
    pub fn new(cipher: GcmCipher, key: &[u8], nonce: &[u8]) -> Result<Self> {
        GcmState::new(cipher, Direction::Encrypt, key, nonce).map(Self)
    }
    pub fn authenticate(&mut self, aad: &[u8]) -> Result<()> {
        self.0.aad(aad)
    }
    pub fn update_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0.update(input, output)
    }
    pub fn finish(mut self) -> Result<[u8; 16]> {
        self.0.finish()?;
        let mut tag = [0; 16];
        // SAFETY: GCM encryption was successfully finalized; tag holds 16 bytes.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.0.ctx.ptr(),
                ffi::EVP_CTRL_GCM_GET_TAG as i32,
                16,
                tag.as_mut_ptr().cast(),
            )
        })?;
        Ok(tag)
    }
}

/// An explicit compatibility interface for protocols that expose streamed GCM
/// plaintext. **All output remains untrusted until `finish` succeeds.** Prefer
/// `crate::aead::Key::open_into`, which withholds plaintext until authentication succeeds.
///
/// AAD cannot follow payload, and finalization always requires an expected tag.
/// Failed authentication cannot erase plaintext already copied by the caller.
pub struct UnverifiedGcmDecrypt(GcmState);
impl UnverifiedGcmDecrypt {
    pub fn new(cipher: GcmCipher, key: &[u8], nonce: &[u8]) -> Result<Self> {
        GcmState::new(cipher, Direction::Decrypt, key, nonce).map(Self)
    }
    pub fn authenticate(&mut self, aad: &[u8]) -> Result<()> {
        self.0.aad(aad)
    }
    pub fn update_unverified_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.0.update(input, output)
    }
    /// Truncated tags are for existing protocols only; use 16 bytes for new ones.
    /// Tags shorter than four bytes are rejected before native verification.
    pub fn finish(mut self, tag: &[u8]) -> Result<()> {
        self.0.ready()?;
        if !(4..=16).contains(&tag.len()) {
            return Err(Error::InvalidInput(
                "GCM tag must contain 4 through 16 bytes",
            ));
        }
        let mut copy = [0; 16];
        copy[..tag.len()].copy_from_slice(tag);
        // SAFETY: The tag control copies exactly the provided length, which is
        // within GCM's tag range and the local buffer's capacity.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.0.ctx.ptr(),
                ffi::EVP_CTRL_GCM_SET_TAG as i32,
                tag.len() as i32,
                copy.as_mut_ptr().cast(),
            )
        })?;
        self.0.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poisoned_gcm_never_releases_more_output() {
        let mut c = GcmEncrypt::new(GcmCipher::Aes128, &[0; 16], &[0; 12]).unwrap();
        c.0.poisoned = true;
        let mut out = [0xa5; 16];
        assert!(c.authenticate(b"aad").is_err());
        assert!(c.update_into(&[0; 16], &mut out).is_err());
        assert!(c.finish().is_err());
        assert_eq!(out, [0xa5; 16]);
    }
}
