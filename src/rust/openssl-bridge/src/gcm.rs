use crate::cipher::{cleanse, Context, Direction};
use crate::{error::check, ffi, Error, Result};
use std::ptr;

/// AES-GCM with a 128-bit authentication tag. `open` never returns unauthenticated
/// plaintext, even if the native API writes it before detecting a bad tag.
pub struct AesGcm;
impl AesGcm {
    fn context(key: &[u8], nonce: &[u8], direction: Direction) -> Result<Context> {
        // SAFETY: These getters return process-lifetime immutable descriptors.
        let descriptor = unsafe {
            match key.len() {
                16 => ffi::EVP_aes_128_gcm(),
                24 => ffi::EVP_aes_192_gcm(),
                32 => ffi::EVP_aes_256_gcm(),
                _ => {
                    return Err(Error::InvalidInput(
                        "AES-GCM key must be 16, 24, or 32 bytes",
                    ))
                }
            }
        };
        if descriptor.is_null() {
            return Err(Error::Unsupported("AES-GCM unavailable"));
        }
        let nonce_len: i32 = nonce
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("nonce is too long"))?;
        if nonce_len == 0 {
            return Err(Error::InvalidInput("nonce cannot be empty"));
        }
        let mut ctx = Context::new()?;
        let encrypt = matches!(direction, Direction::Encrypt) as i32;
        // SAFETY: This owned context selects a cipher before setting its IV length.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                descriptor,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                encrypt,
            )
        })?;
        // SAFETY: This GCM control takes an integer length and no data pointer.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                ctx.ptr(),
                ffi::EVP_CTRL_GCM_SET_IVLEN as i32,
                nonce_len,
                ptr::null_mut(),
            )
        })?;
        // SAFETY: key matches the selected cipher and nonce matches the configured
        // IV length; both slices remain live for the duration of initialization.
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
        Ok(ctx)
    }

    fn update(ctx: &mut Context, input: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let input_len: i32 = input
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("input exceeds INT_MAX"))?;
        let aad_len: i32 = aad
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("AAD exceeds INT_MAX"))?;
        let mut written = 0;
        // SAFETY: A null output means AAD for an initialized GCM context;
        // aad is readable for aad_len. The context has not processed payload yet.
        check(unsafe {
            ffi::EVP_CipherUpdate(
                ctx.ptr(),
                ptr::null_mut(),
                &mut written,
                aad.as_ptr(),
                aad_len,
            )
        })?;
        let mut output = vec![0; input.len()];
        // SAFETY: GCM writes exactly input_len bytes and has no block buffering.
        let result = check(unsafe {
            ffi::EVP_CipherUpdate(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input_len,
            )
        });
        if let Err(error) = result {
            cleanse(&mut output);
            return Err(error);
        }
        if written != input_len {
            cleanse(&mut output);
            return Err(Error::InvalidState("unexpected GCM output length"));
        }
        Ok(output)
    }

    pub fn seal(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let mut ctx = Self::context(key, nonce, Direction::Encrypt)?;
        let output = Self::update(&mut ctx, plaintext, aad)?;
        let mut final_buffer = [0; 16];
        let mut written = 0;
        // SAFETY: A full block is available for finalization, which writes zero
        // bytes in GCM. The initialized context has not been finalized before.
        check(unsafe {
            ffi::EVP_CipherFinal_ex(ctx.ptr(), final_buffer.as_mut_ptr(), &mut written)
        })?;
        if written != 0 {
            return Err(Error::InvalidState("unexpected GCM final output"));
        }
        let mut tag = [0; 16];
        // SAFETY: GET_TAG runs after encryption finalization; tag fits 16 bytes.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                ctx.ptr(),
                ffi::EVP_CTRL_GCM_GET_TAG as i32,
                16,
                tag.as_mut_ptr().cast(),
            )
        })?;
        Ok((output, tag))
    }

    pub fn open(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let mut ctx = Self::context(key, nonce, Direction::Decrypt)?;
        let mut tag = *tag;
        // SAFETY: SET_TAG copies exactly 16 bytes from a live, writable local copy.
        check(unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                ctx.ptr(),
                ffi::EVP_CTRL_GCM_SET_TAG as i32,
                16,
                tag.as_mut_ptr().cast(),
            )
        })?;
        let mut plaintext = Self::update(&mut ctx, ciphertext, aad)?;
        let mut final_buffer = [0; 16];
        let mut written = 0;
        // SAFETY: Context has payload and expected tag; output fits one block.
        let result = check(unsafe {
            ffi::EVP_CipherFinal_ex(ctx.ptr(), final_buffer.as_mut_ptr(), &mut written)
        });
        cleanse(&mut final_buffer);
        if let Err(error) = result {
            cleanse(&mut plaintext);
            return Err(error);
        }
        if written != 0 {
            cleanse(&mut plaintext);
            return Err(Error::InvalidState("unexpected GCM final output"));
        }
        Ok(plaintext)
    }
}

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
        if aad.len() > i32::MAX as usize {
            return Err(Error::InvalidInput("AAD chunk exceeds INT_MAX"));
        }
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
        if input.len() > i32::MAX as usize {
            return Err(Error::InvalidInput("GCM chunk exceeds INT_MAX"));
        }
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
        if let Err(error) = result {
            cleanse(&mut output[..input.len()]);
            return Err(error);
        }
        if written != input.len() as i32 {
            cleanse(&mut output[..input.len()]);
            return Err(Error::InvalidState("unexpected GCM output length"));
        }
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
        if written != 0 {
            return Err(Error::InvalidState("unexpected GCM final output"));
        }
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
/// `AesGcm::open`, which withholds plaintext until authentication succeeds.
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
