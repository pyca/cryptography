//! Algorithm-specific key types. Signing keys cannot perform key agreement and
//! agreement keys cannot sign. Foreign contexts never cross the public API.
use crate::{
    error::{check, pointer},
    ffi, Result,
};
use std::ptr::{self, NonNull};

/// Secret material is erased when dropped and has no Debug or Clone implementation.
pub struct Secret<const N: usize>(pub(crate) [u8; N]);
impl<const N: usize> AsRef<[u8]> for Secret<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: The inline array is writable for its exact size.
        unsafe { ffi::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), N) };
    }
}

struct Key(NonNull<ffi::EVP_PKEY>);
// SAFETY: Keys are immutable after construction; operations use separate contexts.
unsafe impl Send for Key {}
// SAFETY: Shared operations never mutate keys; backend key references are thread-safe.
unsafe impl Sync for Key {}
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: The sole owner releases exactly one reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
impl Key {
    fn private(id: i32, seed: &[u8; 32]) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: id is one of the two supported raw-key algorithms; seed
        // contains exactly the required 32 bytes and is copied by the backend.
        pointer(unsafe {
            ffi::EVP_PKEY_new_raw_private_key(id, ptr::null_mut(), seed.as_ptr(), seed.len())
        })
        .map(Self)
    }
    fn public(id: i32, bytes: &[u8; 32]) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: id names a supported algorithm; bytes contains exactly 32 bytes.
        pointer(unsafe {
            ffi::EVP_PKEY_new_raw_public_key(id, ptr::null_mut(), bytes.as_ptr(), bytes.len())
        })
        .map(Self)
    }
    fn public_bytes(&self) -> Result<[u8; 32]> {
        let mut output = [0; 32];
        let mut size = output.len();
        // SAFETY: All keys here have 32-byte raw public keys; size is an in/out
        // capacity argument and output is writable for that capacity.
        check(unsafe {
            ffi::EVP_PKEY_get_raw_public_key(self.0.as_ptr(), output.as_mut_ptr(), &mut size)
        })?;
        crate::error::check_len(size, output.len())?;
        Ok(output)
    }
    fn seed(&self) -> Result<Secret<32>> {
        let mut output = Secret([0; 32]);
        let mut size = output.0.len();
        // SAFETY: Called only on private keys; the in/out capacity covers output.
        check(unsafe {
            ffi::EVP_PKEY_get_raw_private_key(self.0.as_ptr(), output.0.as_mut_ptr(), &mut size)
        })?;
        crate::error::check_len(size, output.0.len())?;
        Ok(output)
    }
}

struct DigestContext(NonNull<ffi::EVP_MD_CTX>);
impl DigestContext {
    fn new() -> Result<Self> {
        // SAFETY: The allocator has no preconditions.
        pointer(unsafe { ffi::EVP_MD_CTX_new() }).map(Self)
    }
    fn ptr(&mut self) -> *mut ffi::EVP_MD_CTX {
        self.0.as_ptr()
    }
}
impl Drop for DigestContext {
    fn drop(&mut self) {
        // SAFETY: The sole owner frees this context in any initialization state.
        unsafe { ffi::EVP_MD_CTX_free(self.0.as_ptr()) };
    }
}

pub struct Ed25519SigningKey(Key);
/// A public key has no signing operation.
///
/// ```compile_fail
/// use openssl_bridge::curve25519::Ed25519VerifyingKey;
/// let public = Ed25519VerifyingKey::from_bytes(&[0; 32]).unwrap();
/// public.sign(b"message");
/// ```
pub struct Ed25519VerifyingKey(Key);

impl Ed25519SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        Key::private(ffi::EVP_PKEY_ED25519 as i32, seed).map(Self)
    }
    pub fn generate() -> Result<Self> {
        let mut seed = Secret([0; 32]);
        crate::rand::fill_private(&mut seed.0)?;
        Self::from_seed(&seed.0)
    }
    pub fn to_seed(&self) -> Result<Secret<32>> {
        self.0.seed()
    }
    pub fn verifying_key(&self) -> Result<Ed25519VerifyingKey> {
        Ed25519VerifyingKey::from_bytes(&self.0.public_bytes()?)
    }
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut ctx = DigestContext::new()?;
        // SAFETY: ctx is exclusively owned; key is a live Ed25519 private key;
        // pure Ed25519 requires a NULL digest and no engine.
        check(unsafe {
            ffi::EVP_DigestSignInit(
                ctx.ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0 .0.as_ptr(),
            )
        })?;
        let mut output = [0; 64];
        let mut size = output.len();
        // SAFETY: The initialized signer needs exactly 64 output bytes; size is
        // an in/out capacity. message is readable for its declared length.
        check(unsafe {
            ffi::EVP_DigestSign(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut size,
                message.as_ptr(),
                message.len(),
            )
        })?;
        crate::error::check_len(size, output.len())?;
        Ok(output)
    }
}

impl Ed25519VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Key::public(ffi::EVP_PKEY_ED25519 as i32, bytes).map(Self)
    }
    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        self.0.public_bytes()
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 64 {
            return Ok(false);
        }
        let mut ctx = DigestContext::new()?;
        // SAFETY: The context is exclusively owned; this is an immutable
        // Ed25519 public key, and pure Ed25519 requires a NULL digest.
        check(unsafe {
            ffi::EVP_DigestVerifyInit(
                ctx.ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0 .0.as_ptr(),
            )
        })?;
        // SAFETY: The verifier is initialized and both inputs cover their lengths.
        let result = unsafe {
            ffi::EVP_DigestVerify(
                ctx.ptr(),
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
            )
        };
        crate::error::verification_result(result)
    }
}

pub struct X25519SecretKey(Key);
pub struct X25519PublicKey(Key);
impl X25519SecretKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Key::private(ffi::EVP_PKEY_X25519 as i32, bytes).map(Self)
    }
    pub fn generate() -> Result<Self> {
        let mut secret = Secret([0; 32]);
        crate::rand::fill_private(&mut secret.0)?;
        Self::from_bytes(&secret.0)
    }
    pub fn to_bytes(&self) -> Result<Secret<32>> {
        self.0.seed()
    }
    pub fn public_key(&self) -> Result<X25519PublicKey> {
        X25519PublicKey::from_bytes(&self.0.public_bytes()?)
    }
    pub fn exchange(&self, peer: &X25519PublicKey) -> Result<Secret<32>> {
        struct Context(NonNull<ffi::EVP_PKEY_CTX>);
        impl Drop for Context {
            fn drop(&mut self) {
                // SAFETY: The sole owner frees this context in any initialization state.
                unsafe { ffi::EVP_PKEY_CTX_free(self.0.as_ptr()) };
            }
        }
        // SAFETY: This live private key remains borrowed until the context is dropped.
        let ctx = Context(pointer(unsafe {
            ffi::EVP_PKEY_CTX_new(self.0 .0.as_ptr(), ptr::null_mut())
        })?);
        // SAFETY: The context is uniquely owned and attached to an X25519 private key.
        check(unsafe { ffi::EVP_PKEY_derive_init(ctx.0.as_ptr()) })?;
        // SAFETY: peer is a live X25519 public key; backend retains a reference
        // and Rust also keeps peer borrowed through completion of the operation.
        check(unsafe { ffi::EVP_PKEY_derive_set_peer(ctx.0.as_ptr(), peer.0 .0.as_ptr()) })?;
        let mut output = Secret([0; 32]);
        let mut size = output.0.len();
        // SAFETY: The context is initialized with both keys and output fits the
        // algorithm's 32-byte result. Its capacity is also supplied to the backend.
        check(unsafe { ffi::EVP_PKEY_derive(ctx.0.as_ptr(), output.0.as_mut_ptr(), &mut size) })?;
        crate::error::check_len(size, output.0.len())?;
        crate::secret::check_shared_secret(&output.0)?;
        Ok(output)
    }
}
impl X25519PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Key::public(ffi::EVP_PKEY_X25519 as i32, bytes).map(Self)
    }
    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        self.0.public_bytes()
    }
}
