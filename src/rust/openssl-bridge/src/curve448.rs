#![cfg(not(any(backend = "libressl", backend = "boringssl", backend = "awslc")))]
//! Algorithm-specific key types. Signing keys cannot perform key agreement and
//! agreement keys cannot sign. Foreign contexts never cross the public API.
use crate::{
    error::{check, pointer},
    ffi, Error, Result,
};
use std::ptr::{self, NonNull};

use crate::curve25519::Secret;

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
    fn private<const N: usize>(id: i32, seed: &[u8; N]) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: id is one of the two supported raw-key algorithms; seed
        // contains the algorithm-specific raw bytes and is copied by the backend.
        pointer(unsafe {
            ffi::EVP_PKEY_new_raw_private_key(id, ptr::null_mut(), seed.as_ptr(), seed.len())
        })
        .map(Self)
    }
    fn public<const N: usize>(id: i32, bytes: &[u8; N]) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: id names a supported algorithm; bytes has the algorithm-specific size.
        pointer(unsafe {
            ffi::EVP_PKEY_new_raw_public_key(id, ptr::null_mut(), bytes.as_ptr(), bytes.len())
        })
        .map(Self)
    }
    fn public_bytes<const N: usize>(&self) -> Result<[u8; N]> {
        let mut output = [0; N];
        let mut size = output.len();
        // SAFETY: The caller selects the algorithm-specific raw key size; size is an in/out
        // capacity argument and output is writable for that capacity.
        check(unsafe {
            ffi::EVP_PKEY_get_raw_public_key(self.0.as_ptr(), output.as_mut_ptr(), &mut size)
        })?;
        if size != output.len() {
            return Err(Error::InvalidState("unexpected public key length"));
        }
        Ok(output)
    }
    fn seed<const N: usize>(&self) -> Result<Secret<N>> {
        let mut output = Secret([0; N]);
        let mut size = output.0.len();
        // SAFETY: Called only on private keys; the in/out capacity covers output.
        check(unsafe {
            ffi::EVP_PKEY_get_raw_private_key(self.0.as_ptr(), output.0.as_mut_ptr(), &mut size)
        })?;
        if size != output.0.len() {
            return Err(Error::InvalidState("unexpected private key length"));
        }
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

pub struct Ed448SigningKey(Key);
/// A public key has no signing operation.
///
/// ```compile_fail
/// use openssl_bridge::curve448::Ed448VerifyingKey;
/// let public = Ed448VerifyingKey::from_bytes(&[0; 57]).unwrap();
/// public.sign(b"message");
/// ```
pub struct Ed448VerifyingKey(Key);

impl Ed448SigningKey {
    pub fn from_seed(seed: &[u8; 57]) -> Result<Self> {
        Key::private(ffi::EVP_PKEY_ED448 as i32, seed).map(Self)
    }
    pub fn generate() -> Result<Self> {
        let mut seed = Secret([0; 57]);
        crate::rand::fill_private(&mut seed.0)?;
        Self::from_seed(&seed.0)
    }
    pub fn to_seed(&self) -> Result<Secret<57>> {
        self.0.seed()
    }
    pub fn verifying_key(&self) -> Result<Ed448VerifyingKey> {
        Ed448VerifyingKey::from_bytes(&self.0.public_bytes()?)
    }
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 114]> {
        let mut ctx = DigestContext::new()?;
        // SAFETY: ctx is exclusively owned; key is a live Ed448 private key;
        // pure Ed448 requires a NULL digest and no engine.
        check(unsafe {
            ffi::EVP_DigestSignInit(
                ctx.ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0 .0.as_ptr(),
            )
        })?;
        let mut output = [0; 114];
        let mut size = output.len();
        // SAFETY: The initialized signer needs exactly 114 output bytes; size is
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
        if size != output.len() {
            return Err(Error::InvalidState("unexpected Ed448 signature length"));
        }
        Ok(output)
    }
}

impl Ed448VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 57]) -> Result<Self> {
        Key::public(ffi::EVP_PKEY_ED448 as i32, bytes).map(Self)
    }
    pub fn to_bytes(&self) -> Result<[u8; 57]> {
        self.0.public_bytes()
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 114 {
            return Ok(false);
        }
        let mut ctx = DigestContext::new()?;
        // SAFETY: The context is exclusively owned; this is an immutable
        // Ed448 public key, and pure Ed448 requires a NULL digest.
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
        match result {
            1 => Ok(true),
            0 => {
                let _ = Error::capture();
                Ok(false)
            }
            _ => Err(Error::capture()),
        }
    }
}

pub struct X448SecretKey(Key);
pub struct X448PublicKey(Key);
impl X448SecretKey {
    pub fn from_bytes(bytes: &[u8; 56]) -> Result<Self> {
        Key::private(ffi::EVP_PKEY_X448 as i32, bytes).map(Self)
    }
    pub fn generate() -> Result<Self> {
        let mut secret = Secret([0; 56]);
        crate::rand::fill_private(&mut secret.0)?;
        Self::from_bytes(&secret.0)
    }
    pub fn to_bytes(&self) -> Result<Secret<56>> {
        self.0.seed()
    }
    pub fn public_key(&self) -> Result<X448PublicKey> {
        X448PublicKey::from_bytes(&self.0.public_bytes()?)
    }
    pub fn exchange(&self, peer: &X448PublicKey) -> Result<Secret<56>> {
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
        // SAFETY: The context is uniquely owned and attached to an X448 private key.
        check(unsafe { ffi::EVP_PKEY_derive_init(ctx.0.as_ptr()) })?;
        // SAFETY: peer is a live X448 public key; backend retains a reference
        // and Rust also keeps peer borrowed through completion of the operation.
        check(unsafe { ffi::EVP_PKEY_derive_set_peer(ctx.0.as_ptr(), peer.0 .0.as_ptr()) })?;
        let mut output = Secret([0; 56]);
        let mut size = output.0.len();
        // SAFETY: The context is initialized with both keys and output fits the
        // algorithm's 56-byte result. Its capacity is also supplied to the backend.
        check(unsafe { ffi::EVP_PKEY_derive(ctx.0.as_ptr(), output.0.as_mut_ptr(), &mut size) })?;
        if size != output.0.len() {
            return Err(Error::InvalidState("unexpected X448 secret length"));
        }
        if crate::constant_time_eq(&output.0, &[0; 56]) {
            return Err(Error::InvalidInput("X448 shared secret is all zero"));
        }
        Ok(output)
    }
}
impl X448PublicKey {
    pub fn from_bytes(bytes: &[u8; 56]) -> Result<Self> {
        Key::public(ffi::EVP_PKEY_X448 as i32, bytes).map(Self)
    }
    pub fn to_bytes(&self) -> Result<[u8; 56]> {
        self.0.public_bytes()
    }
}
