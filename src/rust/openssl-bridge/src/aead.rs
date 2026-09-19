//! One-shot authenticated encryption with immutable keys and checked protocols.
//! Decryption copies to the caller's output only after authentication succeeds.
use crate::{
    cipher::{Context, Descriptor},
    error::check,
    ffi,
    secret::SecretBytes,
    Error, Result,
};
use std::{ffi::CStr, ptr};

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    Aes128Ocb,
    Aes192Ocb,
    Aes256Ocb,
    Aes128Siv,
    Aes192Siv,
    Aes256Siv,
    Aes128GcmSiv,
    Aes192GcmSiv,
    Aes256GcmSiv,
    ChaCha20Poly1305,
}
#[derive(Clone, Copy, PartialEq)]
enum Protocol {
    Gcm,
    Ccm,
    Ocb,
    Siv,
    GcmSiv,
    ChaCha,
}
impl Algorithm {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Ok(Self::Aes128Gcm),
            "AES-192-GCM" => Ok(Self::Aes192Gcm),
            "AES-256-GCM" => Ok(Self::Aes256Gcm),
            "AES-128-CCM" => Ok(Self::Aes128Ccm),
            "AES-192-CCM" => Ok(Self::Aes192Ccm),
            "AES-256-CCM" => Ok(Self::Aes256Ccm),
            "AES-128-OCB" => Ok(Self::Aes128Ocb),
            "AES-192-OCB" => Ok(Self::Aes192Ocb),
            "AES-256-OCB" => Ok(Self::Aes256Ocb),
            "AES-128-SIV" => Ok(Self::Aes128Siv),
            "AES-192-SIV" => Ok(Self::Aes192Siv),
            "AES-256-SIV" => Ok(Self::Aes256Siv),
            "AES-128-GCM-SIV" => Ok(Self::Aes128GcmSiv),
            "AES-192-GCM-SIV" => Ok(Self::Aes192GcmSiv),
            "AES-256-GCM-SIV" => Ok(Self::Aes256GcmSiv),
            "CHACHA20-POLY1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::Unsupported("unsupported AEAD algorithm")),
        }
    }
    fn name(self) -> &'static CStr {
        match self {
            Self::Aes128Gcm => c"AES-128-GCM",
            Self::Aes192Gcm => c"AES-192-GCM",
            Self::Aes256Gcm => c"AES-256-GCM",
            Self::Aes128Ccm => c"AES-128-CCM",
            Self::Aes192Ccm => c"AES-192-CCM",
            Self::Aes256Ccm => c"AES-256-CCM",
            Self::Aes128Ocb => c"AES-128-OCB",
            Self::Aes192Ocb => c"AES-192-OCB",
            Self::Aes256Ocb => c"AES-256-OCB",
            Self::Aes128Siv => c"AES-128-SIV",
            Self::Aes192Siv => c"AES-192-SIV",
            Self::Aes256Siv => c"AES-256-SIV",
            Self::Aes128GcmSiv => c"AES-128-GCM-SIV",
            Self::Aes192GcmSiv => c"AES-192-GCM-SIV",
            Self::Aes256GcmSiv => c"AES-256-GCM-SIV",
            Self::ChaCha20Poly1305 => c"ChaCha20-Poly1305",
        }
    }
    fn protocol(self) -> Protocol {
        match self {
            Self::Aes128Gcm | Self::Aes192Gcm | Self::Aes256Gcm => Protocol::Gcm,
            Self::Aes128Ccm | Self::Aes192Ccm | Self::Aes256Ccm => Protocol::Ccm,
            Self::Aes128Ocb | Self::Aes192Ocb | Self::Aes256Ocb => Protocol::Ocb,
            Self::Aes128Siv | Self::Aes192Siv | Self::Aes256Siv => Protocol::Siv,
            Self::Aes128GcmSiv | Self::Aes192GcmSiv | Self::Aes256GcmSiv => Protocol::GcmSiv,
            Self::ChaCha20Poly1305 => Protocol::ChaCha,
        }
    }
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Ccm | Self::Aes128Ocb | Self::Aes128GcmSiv => 16,
            Self::Aes192Gcm | Self::Aes192Ccm | Self::Aes192Ocb | Self::Aes192GcmSiv => 24,
            Self::Aes256Gcm
            | Self::Aes256Ccm
            | Self::Aes256Ocb
            | Self::Aes256GcmSiv
            | Self::ChaCha20Poly1305
            | Self::Aes128Siv => 32,
            Self::Aes192Siv => 48,
            Self::Aes256Siv => 64,
        }
    }
    pub fn is_available(self) -> bool {
        Implementation::new(self).is_ok()
    }
}

enum Implementation {
    Cipher(Descriptor),
    #[cfg(any(backend = "boringssl", backend = "awslc"))]
    Aead,
}
impl Implementation {
    fn new(algorithm: Algorithm) -> Result<Self> {
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        if matches!(
            algorithm,
            Algorithm::ChaCha20Poly1305 | Algorithm::Aes128GcmSiv | Algorithm::Aes256GcmSiv
        ) {
            return Ok(Self::Aead);
        }
        let descriptor = Descriptor::lookup(algorithm.name())?;
        if descriptor.sizes()?.0 != algorithm.key_size() {
            return Err(Error::Unsupported("unexpected AEAD descriptor parameters"));
        }
        Ok(Self::Cipher(descriptor))
    }
}

/// An owned, immutable key. No context or output pointer is exposed, and each
/// operation has independent native state. Nonces must satisfy the protocol's
/// uniqueness requirements; the wrapper cannot track them across processes.
pub struct Key {
    algorithm: Algorithm,
    key: SecretBytes,
    implementation: Implementation,
    tag_size: usize,
}
impl Key {
    /// Use a 128-bit tag. For CCM protocols with shorter tags use `ccm`.
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        Self::with_tag(algorithm, key, 16)
    }
    pub fn ccm(key: &[u8], tag_size: usize) -> Result<Self> {
        let algorithm = match key.len() {
            16 => Algorithm::Aes128Ccm,
            24 => Algorithm::Aes192Ccm,
            32 => Algorithm::Aes256Ccm,
            _ => return Err(Error::InvalidInput("incorrect CCM key length")),
        };
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_size) {
            return Err(Error::InvalidInput("invalid CCM tag size"));
        }
        Self::with_tag(algorithm, key, tag_size)
    }
    fn with_tag(algorithm: Algorithm, key: &[u8], tag_size: usize) -> Result<Self> {
        if key.len() != algorithm.key_size() {
            return Err(Error::InvalidInput("incorrect AEAD key length"));
        }
        let implementation = Implementation::new(algorithm)?;
        Ok(Self {
            algorithm,
            key: key.to_vec().into(),
            implementation,
            tag_size,
        })
    }
    pub fn tag_size(&self) -> usize {
        self.tag_size
    }
    fn validate(
        &self,
        nonce: &[u8],
        aad: &[&[u8]],
        length: usize,
        output: usize,
        tag: usize,
    ) -> Result<()> {
        let protocol = self.algorithm.protocol();
        if length > (i32::MAX as usize).saturating_sub(32) {
            return Err(Error::InvalidInput("AEAD payload exceeds native limit"));
        }
        if output != length || tag != self.tag_size {
            return Err(Error::InvalidInput("incorrect AEAD output or tag size"));
        }
        if aad.iter().any(|data| data.len() > i32::MAX as usize) {
            return Err(Error::InvalidInput(
                "AEAD associated data exceeds native limit",
            ));
        }
        if (protocol != Protocol::Siv && aad.len() > 1) || aad.len() > 126 {
            return Err(Error::InvalidInput(
                "incorrect number of associated data components",
            ));
        }
        let valid_nonce = match protocol {
            Protocol::Gcm => !nonce.is_empty() && nonce.len() <= i32::MAX as usize,
            Protocol::Ccm => (7..=13).contains(&nonce.len()),
            Protocol::Ocb => (1..=15).contains(&nonce.len()),
            Protocol::Siv => nonce.is_empty(),
            Protocol::ChaCha | Protocol::GcmSiv => nonce.len() == 12,
        };
        if !valid_nonce {
            return Err(Error::InvalidInput("incorrect AEAD nonce length"));
        }
        if protocol == Protocol::Ccm {
            let bits = 8 * (15 - nonce.len());
            if bits < usize::BITS as usize && length >= (1usize << bits) {
                return Err(Error::InvalidInput("CCM payload is too large for nonce"));
            }
        }
        Ok(())
    }
    /// Each SIV AAD slice is a separate authenticated component. Other algorithms
    /// accept zero or one component. `ciphertext` must exactly fit the payload.
    pub fn seal_into(
        &self,
        nonce: &[u8],
        aad: &[&[u8]],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        self.validate(nonce, aad, plaintext.len(), ciphertext.len(), tag.len())?;
        match &self.implementation {
            Implementation::Cipher(descriptor) => {
                let (output, generated) =
                    self.cipher_operation(descriptor, nonce, aad, plaintext, None)?;
                ciphertext.copy_from_slice(&output.as_ref()[..plaintext.len()]);
                tag.copy_from_slice(&generated[..self.tag_size]);
                Ok(())
            }
            #[cfg(any(backend = "boringssl", backend = "awslc"))]
            Implementation::Aead => self.native_seal(
                nonce,
                aad.first().copied().unwrap_or(&[]),
                plaintext,
                ciphertext,
                tag,
            ),
        }
    }
    /// On failure, `plaintext` is unchanged. Unauthenticated bytes only exist in
    /// a private temporary allocation which is cleansed before it is released.
    pub fn open_into(
        &self,
        nonce: &[u8],
        aad: &[&[u8]],
        ciphertext: &[u8],
        tag: &[u8],
        plaintext: &mut [u8],
    ) -> Result<()> {
        self.validate(nonce, aad, ciphertext.len(), plaintext.len(), tag.len())?;
        match &self.implementation {
            Implementation::Cipher(descriptor) => {
                let (output, _) =
                    self.cipher_operation(descriptor, nonce, aad, ciphertext, Some(tag))?;
                plaintext.copy_from_slice(&output.as_ref()[..ciphertext.len()]);
                Ok(())
            }
            #[cfg(any(backend = "boringssl", backend = "awslc"))]
            Implementation::Aead => self.native_open(
                nonce,
                aad.first().copied().unwrap_or(&[]),
                ciphertext,
                tag,
                plaintext,
            ),
        }
    }
    fn cipher_operation(
        &self,
        descriptor: &Descriptor,
        nonce: &[u8],
        aad: &[&[u8]],
        input: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<(SecretBytes, [u8; 16])> {
        let protocol = self.algorithm.protocol();
        let encrypt = expected.is_none() as i32;
        let mut ctx = Context::new()?;
        // SAFETY: Select a whitelisted AEAD on a newly owned context before controls.
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
        if protocol != Protocol::Siv {
            // SAFETY: AEAD IV-length control accepts a checked int, no data pointer.
            check(unsafe {
                ffi::EVP_CIPHER_CTX_ctrl(
                    ctx.ptr(),
                    ffi::EVP_CTRL_AEAD_SET_IVLEN as i32,
                    nonce.len() as i32,
                    ptr::null_mut(),
                )
            })?;
        }
        let mut tag = [0; 16];
        if let Some(expected) = expected {
            tag[..expected.len()].copy_from_slice(expected);
        }
        if expected.is_some() || protocol == Protocol::Ccm {
            // SAFETY: CCM configures tag length before setting key/nonce. Other
            // AEADs accept the expected tag before processing any input. Controls
            // copy the tag, which fits the live local array.
            check(unsafe {
                ffi::EVP_CIPHER_CTX_ctrl(
                    ctx.ptr(),
                    ffi::EVP_CTRL_AEAD_SET_TAG as i32,
                    self.tag_size as i32,
                    if expected.is_some() {
                        tag.as_mut_ptr().cast()
                    } else {
                        ptr::null_mut()
                    },
                )
            })?;
        }
        // SAFETY: The stored key has the algorithm's exact length; nonce length
        // has been configured. SIV deliberately receives no nonce.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                ptr::null(),
                ptr::null_mut(),
                self.key.as_ref().as_ptr(),
                if protocol == Protocol::Siv {
                    ptr::null()
                } else {
                    nonce.as_ptr()
                },
                encrypt,
            )
        })?;
        let mut written = 0;
        if protocol == Protocol::Ccm {
            // SAFETY: CCM's NULL-input, NULL-output call announces total payload
            // size before AAD; this does not read input or write payload bytes.
            check(unsafe {
                ffi::EVP_CipherUpdate(
                    ctx.ptr(),
                    ptr::null_mut(),
                    &mut written,
                    ptr::null(),
                    input.len() as i32,
                )
            })?;
        }
        for component in aad {
            // SAFETY: NULL output selects AAD. Each checked component remains
            // live, and the payload has not started. SIV preserves boundaries.
            check(unsafe {
                ffi::EVP_CipherUpdate(
                    ctx.ptr(),
                    ptr::null_mut(),
                    &mut written,
                    component.as_ptr(),
                    component.len() as i32,
                )
            })?;
        }
        let mut output: SecretBytes = vec![0; input.len() + 32].into();
        // SAFETY: Extra storage covers a complete native block and output int
        // arithmetic. Even empty payloads are passed with a non-NULL input so
        // CCM performs authentication. Input and output do not alias.
        check(unsafe {
            ffi::EVP_CipherUpdate(
                ctx.ptr(),
                output.as_mut().as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input.len() as i32,
            )
        })?;
        let mut total = usize::try_from(written)
            .map_err(|_| Error::InvalidState("negative AEAD output length"))?;
        crate::error::check_len_at_most(total, input.len())?;
        if protocol != Protocol::Ccm {
            // SAFETY: At least one full block remains; this is the first and only
            // finalization. On failure the private output is cleansed by Drop.
            check(unsafe {
                ffi::EVP_CipherFinal_ex(
                    ctx.ptr(),
                    output.as_mut()[total..].as_mut_ptr(),
                    &mut written,
                )
            })?;
            total = total
                .checked_add(
                    usize::try_from(written)
                        .map_err(|_| Error::InvalidState("negative AEAD final length"))?,
                )
                .ok_or(Error::InvalidState("AEAD output overflow"))?;
        }
        crate::error::check_len(total, input.len())?;
        if expected.is_none() {
            // SAFETY: Authentication succeeded; tag array covers the requested
            // length, and encryption is complete (CCM finalizes in update).
            check(unsafe {
                ffi::EVP_CIPHER_CTX_ctrl(
                    ctx.ptr(),
                    ffi::EVP_CTRL_AEAD_GET_TAG as i32,
                    self.tag_size as i32,
                    tag.as_mut_ptr().cast(),
                )
            })?;
        }
        Ok((output, tag))
    }
}

#[cfg(any(backend = "boringssl", backend = "awslc"))]
struct NativeContext(std::ptr::NonNull<ffi::EVP_AEAD_CTX>);
#[cfg(any(backend = "boringssl", backend = "awslc"))]
impl Drop for NativeContext {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the allocation returned by EVP_AEAD_CTX_new.
        unsafe { ffi::EVP_AEAD_CTX_free(self.0.as_ptr()) };
    }
}
#[cfg(any(backend = "boringssl", backend = "awslc"))]
impl Key {
    fn native_context(&self) -> Result<NativeContext> {
        // SAFETY: These getters have no preconditions and return static descriptors.
        let descriptor = unsafe {
            match self.algorithm {
                Algorithm::ChaCha20Poly1305 => ffi::EVP_aead_chacha20_poly1305(),
                Algorithm::Aes128GcmSiv => ffi::EVP_aead_aes_128_gcm_siv(),
                Algorithm::Aes256GcmSiv => ffi::EVP_aead_aes_256_gcm_siv(),
                _ => return Err(Error::Unsupported("unsupported native AEAD")),
            }
        };
        if descriptor.is_null() {
            return Err(Error::Unsupported("native AEAD is unavailable"));
        }
        // SAFETY: Descriptor matches a validated key length and 16-byte tag size.
        crate::error::pointer(unsafe {
            ffi::EVP_AEAD_CTX_new(
                descriptor,
                self.key.as_ref().as_ptr(),
                self.key.as_ref().len(),
                self.tag_size,
            )
        })
        .map(NativeContext)
    }
    fn native_seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        let ctx = self.native_context()?;
        let mut combined = vec![0; input.len() + self.tag_size];
        let mut written = 0;
        // SAFETY: All slices and lengths are live, disjoint, and checked; combined
        // fits payload plus tag. Native AEAD also receives the exact capacity.
        check(unsafe {
            ffi::EVP_AEAD_CTX_seal(
                ctx.0.as_ptr(),
                combined.as_mut_ptr(),
                &mut written,
                combined.len(),
                nonce.as_ptr(),
                nonce.len(),
                input.as_ptr(),
                input.len(),
                aad.as_ptr(),
                aad.len(),
            )
        })?;
        crate::error::check_len(written, combined.len())?;
        output.copy_from_slice(&combined[..input.len()]);
        tag.copy_from_slice(&combined[input.len()..]);
        Ok(())
    }
    fn native_open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
        tag: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        let ctx = self.native_context()?;
        let mut combined = Vec::with_capacity(input.len() + tag.len());
        combined.extend_from_slice(input);
        combined.extend_from_slice(tag);
        let mut private: SecretBytes = vec![0; input.len()].into();
        let mut written = 0;
        // SAFETY: The native API receives all capacities and cannot expose its
        // private output before authentication. Drop cleanses on every error.
        check(unsafe {
            ffi::EVP_AEAD_CTX_open(
                ctx.0.as_ptr(),
                private.as_mut().as_mut_ptr(),
                &mut written,
                input.len(),
                nonce.as_ptr(),
                nonce.len(),
                combined.as_ptr(),
                combined.len(),
                aad.as_ptr(),
                aad.len(),
            )
        })?;
        crate::error::check_len(written, output.len())?;
        output.copy_from_slice(private.as_ref());
        Ok(())
    }
}
