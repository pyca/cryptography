//! Conventional cipher contexts. Authenticated modes use separate APIs.
use crate::{
    error::{check, pointer},
    ffi, Error, Result,
};
use std::{
    ffi::CStr,
    ptr::{self, NonNull},
};

pub use crate::gcm::AesGcm;

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// A closed set of conventional algorithms, excluding AEAD and composite TLS
/// ciphers. Availability depends on the selected backend and loaded providers.
#[derive(Clone, Copy, Debug)]
pub enum Cipher {
    Aes128Cbc,
    Aes128Ctr,
    Aes128Ecb,
    Aes128Ofb,
    Aes128Cfb,
    Aes128Cfb8,
    Aes192Cbc,
    Aes192Ctr,
    Aes192Ecb,
    Aes192Ofb,
    Aes192Cfb,
    Aes192Cfb8,
    Aes256Cbc,
    Aes256Ctr,
    Aes256Ecb,
    Aes256Ofb,
    Aes256Cfb,
    Aes256Cfb8,
    Camellia128Cbc,
    Camellia128Ecb,
    Camellia128Ofb,
    Camellia128Cfb,
    Camellia192Cbc,
    Camellia192Ecb,
    Camellia192Ofb,
    Camellia192Cfb,
    Camellia256Cbc,
    Camellia256Ecb,
    Camellia256Ofb,
    Camellia256Cfb,
    TripleDesCbc,
    TripleDesEcb,
    TripleDesOfb,
    TripleDesCfb,
    TripleDesCfb8,
    DesCbc,
    Sm4Cbc,
    Sm4Ctr,
    Sm4Ecb,
    Sm4Ofb,
    Sm4Cfb,
    SeedCbc,
    SeedEcb,
    SeedOfb,
    SeedCfb,
    BlowfishCbc,
    BlowfishEcb,
    BlowfishOfb,
    BlowfishCfb,
    Cast5Cbc,
    Cast5Ecb,
    Cast5Ofb,
    Cast5Cfb,
    IdeaCbc,
    IdeaEcb,
    IdeaOfb,
    IdeaCfb,
    Rc2Cbc,
    Rc2_40Cbc,
    Rc4,
    ChaCha20,
}

impl Cipher {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-128-CBC" => Ok(Self::Aes128Cbc),
            "AES-128-CTR" => Ok(Self::Aes128Ctr),
            "AES-128-ECB" => Ok(Self::Aes128Ecb),
            "AES-128-OFB" => Ok(Self::Aes128Ofb),
            "AES-128-CFB" => Ok(Self::Aes128Cfb),
            "AES-128-CFB8" => Ok(Self::Aes128Cfb8),
            "AES-192-CBC" => Ok(Self::Aes192Cbc),
            "AES-192-CTR" => Ok(Self::Aes192Ctr),
            "AES-192-ECB" => Ok(Self::Aes192Ecb),
            "AES-192-OFB" => Ok(Self::Aes192Ofb),
            "AES-192-CFB" => Ok(Self::Aes192Cfb),
            "AES-192-CFB8" => Ok(Self::Aes192Cfb8),
            "AES-256-CBC" => Ok(Self::Aes256Cbc),
            "AES-256-CTR" => Ok(Self::Aes256Ctr),
            "AES-256-ECB" => Ok(Self::Aes256Ecb),
            "AES-256-OFB" => Ok(Self::Aes256Ofb),
            "AES-256-CFB" => Ok(Self::Aes256Cfb),
            "AES-256-CFB8" => Ok(Self::Aes256Cfb8),
            "CAMELLIA-128-CBC" => Ok(Self::Camellia128Cbc),
            "CAMELLIA-128-ECB" => Ok(Self::Camellia128Ecb),
            "CAMELLIA-128-OFB" => Ok(Self::Camellia128Ofb),
            "CAMELLIA-128-CFB" => Ok(Self::Camellia128Cfb),
            "CAMELLIA-192-CBC" => Ok(Self::Camellia192Cbc),
            "CAMELLIA-192-ECB" => Ok(Self::Camellia192Ecb),
            "CAMELLIA-192-OFB" => Ok(Self::Camellia192Ofb),
            "CAMELLIA-192-CFB" => Ok(Self::Camellia192Cfb),
            "CAMELLIA-256-CBC" => Ok(Self::Camellia256Cbc),
            "CAMELLIA-256-ECB" => Ok(Self::Camellia256Ecb),
            "CAMELLIA-256-OFB" => Ok(Self::Camellia256Ofb),
            "CAMELLIA-256-CFB" => Ok(Self::Camellia256Cfb),
            "DES-EDE3-CBC" => Ok(Self::TripleDesCbc),
            "DES-EDE3-ECB" => Ok(Self::TripleDesEcb),
            "DES-EDE3-OFB" => Ok(Self::TripleDesOfb),
            "DES-EDE3-CFB" => Ok(Self::TripleDesCfb),
            "DES-EDE3-CFB8" => Ok(Self::TripleDesCfb8),
            "DES-CBC" => Ok(Self::DesCbc),
            "SM4-CBC" => Ok(Self::Sm4Cbc),
            "SM4-CTR" => Ok(Self::Sm4Ctr),
            "SM4-ECB" => Ok(Self::Sm4Ecb),
            "SM4-OFB" => Ok(Self::Sm4Ofb),
            "SM4-CFB" => Ok(Self::Sm4Cfb),
            "SEED-CBC" => Ok(Self::SeedCbc),
            "SEED-ECB" => Ok(Self::SeedEcb),
            "SEED-OFB" => Ok(Self::SeedOfb),
            "SEED-CFB" => Ok(Self::SeedCfb),
            "BF-CBC" => Ok(Self::BlowfishCbc),
            "BF-ECB" => Ok(Self::BlowfishEcb),
            "BF-OFB" => Ok(Self::BlowfishOfb),
            "BF-CFB" => Ok(Self::BlowfishCfb),
            "CAST5-CBC" => Ok(Self::Cast5Cbc),
            "CAST5-ECB" => Ok(Self::Cast5Ecb),
            "CAST5-OFB" => Ok(Self::Cast5Ofb),
            "CAST5-CFB" => Ok(Self::Cast5Cfb),
            "IDEA-CBC" => Ok(Self::IdeaCbc),
            "IDEA-ECB" => Ok(Self::IdeaEcb),
            "IDEA-OFB" => Ok(Self::IdeaOfb),
            "IDEA-CFB" => Ok(Self::IdeaCfb),
            "RC2-CBC" => Ok(Self::Rc2Cbc),
            "RC2-40-CBC" => Ok(Self::Rc2_40Cbc),
            "RC4" => Ok(Self::Rc4),
            "CHACHA20" => Ok(Self::ChaCha20),
            _ => Err(Error::Unsupported("unsupported conventional cipher")),
        }
    }
    fn name(self) -> &'static CStr {
        match self {
            Self::Aes128Cbc => c"AES-128-CBC",
            Self::Aes128Ctr => c"AES-128-CTR",
            Self::Aes128Ecb => c"AES-128-ECB",
            Self::Aes128Ofb => c"AES-128-OFB",
            Self::Aes128Cfb => c"AES-128-CFB",
            Self::Aes128Cfb8 => c"AES-128-CFB8",
            Self::Aes192Cbc => c"AES-192-CBC",
            Self::Aes192Ctr => c"AES-192-CTR",
            Self::Aes192Ecb => c"AES-192-ECB",
            Self::Aes192Ofb => c"AES-192-OFB",
            Self::Aes192Cfb => c"AES-192-CFB",
            Self::Aes192Cfb8 => c"AES-192-CFB8",
            Self::Aes256Cbc => c"AES-256-CBC",
            Self::Aes256Ctr => c"AES-256-CTR",
            Self::Aes256Ecb => c"AES-256-ECB",
            Self::Aes256Ofb => c"AES-256-OFB",
            Self::Aes256Cfb => c"AES-256-CFB",
            Self::Aes256Cfb8 => c"AES-256-CFB8",
            Self::Camellia128Cbc => c"CAMELLIA-128-CBC",
            Self::Camellia128Ecb => c"CAMELLIA-128-ECB",
            Self::Camellia128Ofb => c"CAMELLIA-128-OFB",
            Self::Camellia128Cfb => c"CAMELLIA-128-CFB",
            Self::Camellia192Cbc => c"CAMELLIA-192-CBC",
            Self::Camellia192Ecb => c"CAMELLIA-192-ECB",
            Self::Camellia192Ofb => c"CAMELLIA-192-OFB",
            Self::Camellia192Cfb => c"CAMELLIA-192-CFB",
            Self::Camellia256Cbc => c"CAMELLIA-256-CBC",
            Self::Camellia256Ecb => c"CAMELLIA-256-ECB",
            Self::Camellia256Ofb => c"CAMELLIA-256-OFB",
            Self::Camellia256Cfb => c"CAMELLIA-256-CFB",
            Self::TripleDesCbc => c"DES-EDE3-CBC",
            Self::TripleDesEcb => c"DES-EDE3-ECB",
            Self::TripleDesOfb => c"DES-EDE3-OFB",
            Self::TripleDesCfb => c"DES-EDE3-CFB",
            Self::TripleDesCfb8 => c"DES-EDE3-CFB8",
            Self::DesCbc => c"DES-CBC",
            Self::Sm4Cbc => c"SM4-CBC",
            Self::Sm4Ctr => c"SM4-CTR",
            Self::Sm4Ecb => c"SM4-ECB",
            Self::Sm4Ofb => c"SM4-OFB",
            Self::Sm4Cfb => c"SM4-CFB",
            Self::SeedCbc => c"SEED-CBC",
            Self::SeedEcb => c"SEED-ECB",
            Self::SeedOfb => c"SEED-OFB",
            Self::SeedCfb => c"SEED-CFB",
            Self::BlowfishCbc => c"BF-CBC",
            Self::BlowfishEcb => c"BF-ECB",
            Self::BlowfishOfb => c"BF-OFB",
            Self::BlowfishCfb => c"BF-CFB",
            Self::Cast5Cbc => c"CAST5-CBC",
            Self::Cast5Ecb => c"CAST5-ECB",
            Self::Cast5Ofb => c"CAST5-OFB",
            Self::Cast5Cfb => c"CAST5-CFB",
            Self::IdeaCbc => c"IDEA-CBC",
            Self::IdeaEcb => c"IDEA-ECB",
            Self::IdeaOfb => c"IDEA-OFB",
            Self::IdeaCfb => c"IDEA-CFB",
            Self::Rc2Cbc => c"RC2-CBC",
            Self::Rc2_40Cbc => c"RC2-40-CBC",
            Self::Rc4 => c"RC4",
            Self::ChaCha20 => c"ChaCha20",
        }
    }
    pub fn is_available(self) -> bool {
        Descriptor::lookup(self.name()).is_ok()
    }

    pub fn default_key_size(self) -> Result<usize> {
        Ok(Descriptor::lookup(self.name())?.sizes()?.0)
    }
    pub fn iv_size(self) -> Result<usize> {
        Ok(Descriptor::lookup(self.name())?.sizes()?.1)
    }
    pub fn block_size(self) -> Result<usize> {
        Ok(Descriptor::lookup(self.name())?.sizes()?.2)
    }

    fn valid_key(self, actual: usize, required: usize) -> bool {
        match self {
            Self::BlowfishCbc | Self::BlowfishEcb | Self::BlowfishOfb | Self::BlowfishCfb => {
                (4..=56).contains(&actual)
            }
            Self::Cast5Cbc | Self::Cast5Ecb | Self::Cast5Ofb | Self::Cast5Cfb => {
                (5..=16).contains(&actual)
            }
            Self::Rc4 => (1..=256).contains(&actual),
            Self::Rc2Cbc => (1..=128).contains(&actual),
            _ => actual == required,
        }
    }
    fn can_reset_nonce(self) -> bool {
        matches!(
            self,
            Self::Aes128Ctr | Self::Aes192Ctr | Self::Aes256Ctr | Self::Sm4Ctr | Self::ChaCha20
        )
    }
}

pub(crate) struct Descriptor(NonNull<ffi::EVP_CIPHER>);
// SAFETY: Descriptors are immutable. OpenSSL owns a reference; fork descriptors
// are static. No API in this crate mutates the descriptor.
unsafe impl Send for Descriptor {}
// SAFETY: Sharing an immutable algorithm descriptor is supported by all backends.
unsafe impl Sync for Descriptor {}
impl Descriptor {
    pub(crate) fn lookup(name: &CStr) -> Result<Self> {
        crate::initialize()?;
        #[cfg(backend = "openssl")]
        // SAFETY: name is NUL-terminated; NULL selects the default library context.
        let result = unsafe { ffi::EVP_CIPHER_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        #[cfg(not(backend = "openssl"))]
        // SAFETY: name is NUL-terminated. Lookup returns a static descriptor or NULL.
        let result = unsafe {
            // Fork lookup tables omit some supported descriptors or expose only
            // their object-identifier names. Resolve those explicitly.
            match name.to_bytes() {
                b"AES-128-GCM" => ffi::EVP_aes_128_gcm(),
                b"AES-192-GCM" => ffi::EVP_aes_192_gcm(),
                b"AES-256-GCM" => ffi::EVP_aes_256_gcm(),
                b"DES-EDE3-ECB" => ffi::EVP_des_ede3_ecb(),
                b"RC2-40-CBC" => ffi::EVP_rc2_40_cbc(),
                #[cfg(not(backend = "boringssl"))]
                b"AES-128-CCM" => ffi::EVP_aes_128_ccm(),
                #[cfg(not(backend = "boringssl"))]
                b"AES-192-CCM" => ffi::EVP_aes_192_ccm(),
                #[cfg(not(backend = "boringssl"))]
                b"AES-256-CCM" => ffi::EVP_aes_256_ccm(),
                #[cfg(backend = "awslc")]
                b"AES-128-CFB8" => ffi::EVP_aes_128_cfb8(),
                #[cfg(backend = "awslc")]
                b"AES-192-CFB8" => ffi::EVP_aes_192_cfb8(),
                #[cfg(backend = "awslc")]
                b"AES-256-CFB8" => ffi::EVP_aes_256_cfb8(),
                #[cfg(backend = "awslc")]
                b"BF-OFB" => ffi::EVP_bf_ofb(),
                _ => ffi::EVP_get_cipherbyname(name.as_ptr()),
            }
        }
        .cast_mut();
        match NonNull::new(result) {
            Some(p) => Ok(Self(p)),
            None => {
                let _ = Error::capture();
                Err(Error::Unsupported("cipher is unavailable"))
            }
        }
    }
    pub(crate) fn ptr(&self) -> *const ffi::EVP_CIPHER {
        self.0.as_ptr()
    }
    pub(crate) fn sizes(&self) -> Result<(usize, usize, usize)> {
        // SAFETY: self retains a valid, immutable descriptor.
        let (key, iv, block) = unsafe {
            (
                ffi::OB_cipher_key_size(self.ptr()),
                ffi::OB_cipher_iv_size(self.ptr()),
                ffi::OB_cipher_block_size(self.ptr()),
            )
        };
        if key <= 0 || iv < 0 || block <= 0 || block > 32 {
            return Err(Error::Unsupported("unexpected cipher parameters"));
        }
        Ok((key as usize, iv as usize, block as usize))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        #[cfg(backend = "openssl")]
        // SAFETY: This owns the reference returned by EVP_CIPHER_fetch.
        unsafe {
            ffi::EVP_CIPHER_free(self.0.as_ptr())
        };
    }
}

pub(crate) struct Context(NonNull<ffi::EVP_CIPHER_CTX>);
// SAFETY: A context is uniquely owned; all operations require exclusive access.
unsafe impl Send for Context {}
// SAFETY: Shared access only copies pristine key schedules through a const
// native source; all other native operations require exclusive access.
unsafe impl Sync for Context {}
impl Context {
    pub(crate) fn new() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: The allocator has no preconditions.
        pointer(unsafe { ffi::EVP_CIPHER_CTX_new() }).map(Self)
    }
    pub(crate) fn ptr(&mut self) -> *mut ffi::EVP_CIPHER_CTX {
        self.0.as_ptr()
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: This is the sole owner; free accepts partially initialized state.
        unsafe { ffi::EVP_CIPHER_CTX_free(self.0.as_ptr()) };
    }
}

pub struct Stream {
    ctx: Context,
    _descriptor: std::sync::Arc<Descriptor>,
    cipher: Cipher,
    block_size: usize,
    iv_size: usize,
    padding: bool,
    poisoned: bool,
    // ChaCha20 uses a 32-bit counter and 96-bit nonce. Reject counter carry.
    remaining: Option<u64>,
}
impl Stream {
    pub fn new(
        cipher: Cipher,
        direction: Direction,
        key: &[u8],
        iv: &[u8],
        padding: bool,
    ) -> Result<Self> {
        let descriptor = Descriptor::lookup(cipher.name())?;
        let (key_size, iv_size, block_size) = descriptor.sizes()?;
        if !cipher.valid_key(key.len(), key_size) {
            return Err(Error::InvalidInput("incorrect key length"));
        }
        if iv.len() != iv_size {
            return Err(Error::InvalidInput("incorrect IV length"));
        }
        let mut ctx = Context::new()?;
        let encrypt = matches!(direction, Direction::Encrypt) as i32;
        // SAFETY: Select the cipher on an owned context before configuring key length.
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
        // SAFETY: Validated key lengths fit int; no key bytes have been supplied yet.
        let key_length = key
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("key length exceeds native limit"))?;
        // SAFETY: The native integer conversion was checked, and the cipher has
        // been selected without supplying key material.
        check(unsafe { ffi::EVP_CIPHER_CTX_set_key_length(ctx.ptr(), key_length) })?;
        // SAFETY: Key and IV cover the configured lengths; ECB ignores the IV.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                ptr::null(),
                ptr::null_mut(),
                key.as_ptr(),
                if iv.is_empty() {
                    ptr::null()
                } else {
                    iv.as_ptr()
                },
                encrypt,
            )
        })?;
        // SAFETY: Padding is configured exactly once, before any payload.
        check(unsafe { ffi::EVP_CIPHER_CTX_set_padding(ctx.ptr(), padding as i32) })?;
        Ok(Self {
            ctx,
            _descriptor: std::sync::Arc::new(descriptor),
            cipher,
            block_size,
            iv_size,
            padding,
            poisoned: false,
            remaining: Self::counter_limit(cipher, iv),
        })
    }
    fn counter_limit(cipher: Cipher, iv: &[u8]) -> Option<u64> {
        if matches!(cipher, Cipher::ChaCha20) {
            // IV length was checked before this helper is called.
            let counter = u32::from_le_bytes(iv[..4].try_into().unwrap());
            Some(((1u64 << 32) - u64::from(counter)) * 64)
        } else {
            None
        }
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState("cipher context is poisoned"))
        } else {
            Ok(())
        }
    }
    pub fn block_size(&self) -> usize {
        self.block_size
    }
    pub fn iv_size(&self) -> usize {
        self.iv_size
    }
    /// Reset only CTR or ChaCha20. The caller must choose a nonce/counter range
    /// that does not reuse keystream with the same key.
    pub fn reset_nonce(&mut self, nonce: &[u8]) -> Result<()> {
        self.ready()?;
        if !self.cipher.can_reset_nonce() {
            return Err(Error::Unsupported("cipher does not support nonce reset"));
        }
        if nonce.len() != self.iv_size {
            return Err(Error::InvalidInput("incorrect nonce length"));
        }
        self.poisoned = true;
        // SAFETY: Same cipher/key/direction, and nonce has the original IV length.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                self.ctx.ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                nonce.as_ptr(),
                -1,
            )
        })?;
        self.remaining = Self::counter_limit(self.cipher, nonce);
        self.poisoned = false;
        Ok(())
    }
    pub fn update_capacity(&self, input_length: usize) -> Result<usize> {
        // Padded decryption can write a complete withheld block before deciding
        // its returned length (even on empty input, notably in LibreSSL).
        let slack = if self.block_size == 1 {
            0
        } else if self.padding {
            self.block_size
        } else {
            self.block_size - 1
        };
        input_length
            .checked_add(slack)
            .ok_or(Error::InvalidInput("output size overflow"))
    }
    pub fn update_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.ready()?;
        let capacity = self.update_capacity(input.len())?;
        if output.len() < capacity {
            return Err(Error::InvalidInput("output buffer is too small"));
        }
        if capacity > i32::MAX as usize {
            return Err(Error::InvalidInput("cipher output exceeds INT_MAX"));
        }
        let remaining = self
            .remaining
            .map(|n| {
                n.checked_sub(input.len() as u64)
                    .ok_or(Error::InvalidInput("ChaCha20 counter would overflow"))
            })
            .transpose()?;
        self.poisoned = true;
        let mut written = 0;
        // SAFETY: Initialized exclusive context; disjoint buffers; capacity covers
        // every native write, and both input/output lengths fit signed int.
        check(unsafe {
            ffi::EVP_CipherUpdate(
                self.ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input.len() as i32,
            )
        })?;
        let written = usize::try_from(written)
            .map_err(|_| Error::InvalidState("negative cipher output length"))?;
        if written > output.len() {
            return Err(Error::InvalidState("unexpected cipher output length"));
        }
        self.remaining = remaining;
        self.poisoned = false;
        Ok(written)
    }
    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.ready()?;
        let mut output = vec![0; self.block_size];
        let mut written = 0;
        // SAFETY: Output fits a complete final block; context is consumed here.
        let result = check(unsafe {
            ffi::EVP_CipherFinal_ex(self.ctx.ptr(), output.as_mut_ptr(), &mut written)
        });
        if let Err(error) = result {
            cleanse(&mut output);
            return Err(error);
        }
        let written = usize::try_from(written)
            .map_err(|_| Error::InvalidState("negative final output length"))?;
        if written > output.len() {
            cleanse(&mut output);
            return Err(Error::InvalidState("unexpected final output length"));
        }
        cleanse(&mut output[written..]);
        output.truncate(written);
        Ok(output)
    }
}

/// XTS processes one complete data unit. Its tweak must identify that unit, and
/// the two halves of the key must differ. XTS does not provide authentication.
pub struct XtsDataUnit {
    ctx: Context,
    _descriptor: Descriptor,
}
impl XtsDataUnit {
    pub fn is_available(key_length: usize) -> bool {
        Self::descriptor(key_length).is_ok()
    }
    fn descriptor(key_length: usize) -> Result<Descriptor> {
        Descriptor::lookup(match key_length {
            32 => c"AES-128-XTS",
            64 => c"AES-256-XTS",
            _ => return Err(Error::InvalidInput("XTS key must be 32 or 64 bytes")),
        })
    }
    pub fn new(direction: Direction, key: &[u8], tweak: &[u8; 16]) -> Result<Self> {
        let descriptor = Self::descriptor(key.len())?;
        if crate::constant_time_eq(&key[..key.len() / 2], &key[key.len() / 2..]) {
            return Err(Error::InvalidInput("XTS key halves must differ"));
        }
        let mut ctx = Context::new()?;
        // SAFETY: Key length selects the descriptor; tweak always has 16 bytes.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                descriptor.ptr(),
                ptr::null_mut(),
                key.as_ptr(),
                tweak.as_ptr(),
                matches!(direction, Direction::Encrypt) as i32,
            )
        })?;
        Ok(Self {
            ctx,
            _descriptor: descriptor,
        })
    }
    pub fn crypt_into(mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if !(16..=(1 << 24)).contains(&input.len()) {
            return Err(Error::InvalidInput(
                "XTS data unit must contain 16 through 2^24 bytes",
            ));
        }
        if output.len() < input.len() {
            return Err(Error::InvalidInput("XTS output buffer is too small"));
        }
        let mut written = 0;
        // SAFETY: A complete XTS data unit is length preserving, all lengths fit
        // int, and input and output borrows are disjoint. Context is consumed.
        check(unsafe {
            ffi::EVP_CipherUpdate(
                self.ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input.len() as i32,
            )
        })?;
        if written != input.len() as i32 {
            return Err(Error::InvalidState("unexpected XTS output length"));
        }
        let mut final_block = [0; 32];
        let mut final_written = 0;
        // SAFETY: A complete block is available; XTS must produce no final bytes.
        check(unsafe {
            ffi::EVP_CipherFinal_ex(self.ctx.ptr(), final_block.as_mut_ptr(), &mut final_written)
        })?;
        cleanse(&mut final_block);
        if final_written != 0 {
            return Err(Error::InvalidState("unexpected XTS final output"));
        }
        Ok(written as usize)
    }
}

pub(crate) fn cleanse(bytes: &mut [u8]) {
    // SAFETY: bytes is exclusively writable for the declared length.
    unsafe { ffi::OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
}

/// An immutable key schedule for repeated conventional-cipher operations. Each
/// `start` returns independent state and requires a complete IV; callers cannot
/// obtain or operate on a context with only partial initialization.
pub struct CipherKey {
    encrypt: Stream,
    decrypt: Stream,
}
impl CipherKey {
    pub fn new(cipher: Cipher, key: &[u8], padding: bool) -> Result<Self> {
        let initial_iv = vec![0; cipher.iv_size()?];
        Ok(Self {
            encrypt: Stream::new(cipher, Direction::Encrypt, key, &initial_iv, padding)?,
            decrypt: Stream::new(cipher, Direction::Decrypt, key, &initial_iv, padding)?,
        })
    }
    pub fn start(&self, direction: Direction, iv: &[u8]) -> Result<Stream> {
        let base = match direction {
            Direction::Encrypt => &self.encrypt,
            Direction::Decrypt => &self.decrypt,
        };
        if iv.len() != base.iv_size {
            return Err(Error::InvalidInput("incorrect IV length"));
        }
        let mut ctx = Context::new()?;
        // SAFETY: Source is permanently held in its pristine keyed state. Native
        // copy takes a const source and does not modify it; destination is unique.
        check(unsafe { ffi::EVP_CIPHER_CTX_copy(ctx.ptr(), base.ctx.0.as_ptr()) })?;
        // SAFETY: The copy has the selected cipher, key, direction, and padding.
        // The IV has exactly the configured length. No partial state escapes.
        check(unsafe {
            ffi::EVP_CipherInit_ex(
                ctx.ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                if iv.is_empty() {
                    ptr::null()
                } else {
                    iv.as_ptr()
                },
                -1,
            )
        })?;
        Ok(Stream {
            ctx,
            _descriptor: base._descriptor.clone(),
            cipher: base.cipher,
            block_size: base.block_size,
            iv_size: base.iv_size,
            padding: base.padding,
            poisoned: false,
            remaining: Stream::counter_limit(base.cipher, iv),
        })
    }
}

/// Encrypt a complete conventional-cipher message, applying PKCS7 padding for
/// block modes. This does not provide authentication.
pub fn encrypt_padded(cipher: Cipher, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    padded(cipher, Direction::Encrypt, key, iv, plaintext)
}
/// Decrypt legacy unauthenticated ciphertext with PKCS7 padding. Protocols must
/// authenticate ciphertext separately where applicable; padding is not integrity.
pub fn decrypt_padded(cipher: Cipher, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    padded(cipher, Direction::Decrypt, key, iv, ciphertext)
}
fn padded(
    cipher: Cipher,
    direction: Direction,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut stream = Stream::new(cipher, direction, key, iv, true)?;
    let mut scratch: crate::secret::SecretBytes =
        vec![0; stream.update_capacity(input.len())?].into();
    let written = stream.update_into(input, scratch.as_mut())?;
    let tail: crate::secret::SecretBytes = stream.finish()?.into();
    let mut result = Vec::with_capacity(written + tail.as_ref().len());
    result.extend_from_slice(&scratch.as_ref()[..written]);
    result.extend_from_slice(tail.as_ref());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poisoned_stream_rejects_reuse_and_preserves_output() {
        let mut c = Stream::new(
            Cipher::Aes128Ctr,
            Direction::Encrypt,
            &[0; 16],
            &[0; 16],
            false,
        )
        .unwrap();
        c.poisoned = true;
        let mut out = [0xa5; 16];
        assert!(c.update_into(&[0; 16], &mut out).is_err());
        assert!(c.reset_nonce(&[1; 16]).is_err());
        assert!(c.finish().is_err());
        assert_eq!(out, [0xa5; 16]);
    }
}
