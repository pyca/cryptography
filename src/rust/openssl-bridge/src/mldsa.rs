//! ML-DSA signatures with distinct roles and bounded context strings.
use crate::{
    curve25519::Secret,
    error::{check, pointer},
    ffi,
    pq::{self, Key},
    Error, Result,
};
use std::ptr;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}
impl Variant {
    fn algorithm(self) -> pq::Algorithm {
        match self {
            Self::MlDsa44 => pq::Algorithm::Dsa44,
            Self::MlDsa65 => pq::Algorithm::Dsa65,
            Self::MlDsa87 => pq::Algorithm::Dsa87,
        }
    }
    pub fn public_key_size(self) -> usize {
        self.algorithm().public_len()
    }
    pub fn signature_size(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}
pub struct PrivateKey {
    variant: Variant,
    seed: Secret<32>,
    public: Vec<u8>,
}
#[derive(Clone)]
pub struct PublicKey {
    variant: Variant,
    public: Vec<u8>,
}
impl PrivateKey {
    pub fn from_seed(variant: Variant, seed: &[u8; 32]) -> Result<Self> {
        let key = Key::private(variant.algorithm(), seed)?;
        Ok(Self {
            variant,
            seed: Secret(*seed),
            public: key.public_bytes(variant.algorithm())?,
        })
    }
    pub fn generate(variant: Variant) -> Result<Self> {
        let mut seed = Secret([0; 32]);
        crate::rand::fill_private(&mut seed.0)?;
        Self::from_seed(variant, &seed.0)
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed.0
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            variant: self.variant,
            public: self.public.clone(),
        }
    }
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        if context.len() > 255 {
            return Err(Error::InvalidInput("ML-DSA context exceeds 255 bytes"));
        }
        let key = Key::private(self.variant.algorithm(), self.seed.as_ref())?;
        digest_sign(self.variant, &key, message, context, false)
    }
    /// Sign the FIPS 204 64-byte message representative, which must include the
    /// public-key hash and context domain separation. This does not sign a message.
    pub fn sign_mu(&self, mu: &[u8; 64]) -> Result<Vec<u8>> {
        #[cfg(backend = "boringssl")]
        {
            boring_sign_mu(self.variant, &self.seed.0, mu)
        }
        #[cfg(backend = "awslc")]
        {
            let key = Key::private(self.variant.algorithm(), self.seed.as_ref())?;
            let ctx = key.context()?;
            // SAFETY: Fresh complete private-key operation.
            check(unsafe { ffi::EVP_PKEY_sign_init(ctx.ptr()) })?;
            let mut signature = vec![0; self.variant.signature_size()];
            let mut length = signature.len();
            // SAFETY: Exact signature capacity and exactly 64 input bytes.
            check(unsafe {
                ffi::EVP_PKEY_sign(
                    ctx.ptr(),
                    signature.as_mut_ptr(),
                    &mut length,
                    mu.as_ptr(),
                    mu.len(),
                )
            })?;
            crate::error::check_len(length, signature.len())?;
            Ok(signature)
        }
        #[cfg(backend = "openssl")]
        {
            let key = Key::private(self.variant.algorithm(), self.seed.as_ref())?;
            digest_sign(self.variant, &key, mu, &[], true)
        }
    }
}
impl PublicKey {
    pub fn from_bytes(variant: Variant, bytes: &[u8]) -> Result<Self> {
        let _ = Key::public(variant.algorithm(), bytes)?;
        Ok(Self {
            variant,
            public: bytes.to_vec(),
        })
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.public
    }
    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<bool> {
        if context.len() > 255 {
            return Err(Error::InvalidInput("ML-DSA context exceeds 255 bytes"));
        }
        if signature.len() != self.variant.signature_size() {
            return Ok(false);
        }
        let key = Key::public(self.variant.algorithm(), &self.public)?;
        digest_verify(&key, message, context, signature, false)
    }
    pub fn verify_mu(&self, mu: &[u8; 64], signature: &[u8]) -> Result<bool> {
        if signature.len() != self.variant.signature_size() {
            return Ok(false);
        }
        #[cfg(backend = "boringssl")]
        {
            boring_verify_mu(self.variant, &self.public, mu, signature)
        }
        #[cfg(backend = "awslc")]
        {
            let key = Key::public(self.variant.algorithm(), &self.public)?;
            let ctx = key.context()?;
            // SAFETY: Fresh complete public-key operation.
            check(unsafe { ffi::EVP_PKEY_verify_init(ctx.ptr()) })?;
            // SAFETY: All input sizes match their borrowed storage.
            Ok(pq::verified(unsafe {
                ffi::EVP_PKEY_verify(
                    ctx.ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    mu.as_ptr(),
                    mu.len(),
                )
            }))
        }
        #[cfg(backend = "openssl")]
        {
            let key = Key::public(self.variant.algorithm(), &self.public)?;
            digest_verify(&key, mu, &[], signature, true)
        }
    }
}
// The context is private and always borrowed from a successfully initialized
// local EVP_MD_CTX. No foreign pointer is accepted by the public interface.
fn configure(ctx: *mut ffi::EVP_PKEY_CTX, context: &[u8], external_mu: bool) -> Result<()> {
    pointer(ctx)?;
    #[cfg(any(backend = "boringssl", backend = "awslc"))]
    {
        if external_mu {
            return Err(Error::InvalidState(
                "external mu requires the backend-specific operation",
            ));
        }
        if !context.is_empty() {
            // SAFETY: Initialized local ML-DSA context; setter copies the bytes.
            check(unsafe {
                ffi::EVP_PKEY_CTX_set1_signature_context_string(
                    ctx,
                    context.as_ptr(),
                    context.len(),
                )
            })?;
        }
    }
    #[cfg(backend = "openssl")]
    {
        let mut context = context.to_vec();
        // SAFETY: The shim constructs parameters on its stack and copies them
        // into this exclusive operation. Writable context storage outlives it.
        check(unsafe {
            ffi::OB_mldsa_parameters(
                ctx,
                context.as_mut_ptr().cast(),
                context.len(),
                u32::from(external_mu),
            )
        })?;
    }
    Ok(())
}
fn digest_sign(
    variant: Variant,
    key: &Key,
    data: &[u8],
    context: &[u8],
    external_mu: bool,
) -> Result<Vec<u8>> {
    let md = pq::Digest::new()?;
    let mut ctx = ptr::null_mut();
    // SAFETY: Fresh digest and complete ML-DSA key. NULL selects its internal hash.
    check(unsafe {
        ffi::EVP_DigestSignInit(md.ptr(), &mut ctx, ptr::null(), ptr::null_mut(), key.ptr())
    })?;
    configure(ctx, context, external_mu)?;
    let mut signature = vec![0; variant.signature_size()];
    let mut length = signature.len();
    // SAFETY: Output matches the algorithm's fixed size; capacity is supplied.
    check(unsafe {
        ffi::EVP_DigestSign(
            md.ptr(),
            signature.as_mut_ptr(),
            &mut length,
            data.as_ptr(),
            data.len(),
        )
    })?;
    crate::error::check_len(length, signature.len())?;
    Ok(signature)
}
fn digest_verify(
    key: &Key,
    data: &[u8],
    context: &[u8],
    signature: &[u8],
    external_mu: bool,
) -> Result<bool> {
    let md = pq::Digest::new()?;
    let mut ctx = ptr::null_mut();
    // SAFETY: Fresh digest and complete ML-DSA public key, with its internal hash.
    check(unsafe {
        ffi::EVP_DigestVerifyInit(md.ptr(), &mut ctx, ptr::null(), ptr::null_mut(), key.ptr())
    })?;
    configure(ctx, context, external_mu)?;
    // SAFETY: All borrowed inputs are readable for their exact declared sizes.
    Ok(pq::verified(unsafe {
        ffi::EVP_DigestVerify(
            md.ptr(),
            signature.as_ptr(),
            signature.len(),
            data.as_ptr(),
            data.len(),
        )
    }))
}

#[cfg(backend = "boringssl")]
struct NativeStorage<T>(Box<std::mem::MaybeUninit<T>>);
#[cfg(backend = "boringssl")]
impl<T> NativeStorage<T> {
    fn new() -> Self {
        let mut value = Box::<T>::new_uninit();
        // SAFETY: Write only raw allocated bytes; no T value is ever assumed
        // initialized. Its address stays stable through native initialization/use.
        unsafe {
            value
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0, std::mem::size_of::<T>())
        };
        Self(value)
    }
    fn ptr(&mut self) -> *mut T {
        self.0.as_mut_ptr()
    }
}
#[cfg(backend = "boringssl")]
impl<T> Drop for NativeStorage<T> {
    fn drop(&mut self) {
        // SAFETY: The entire exclusive allocation consists of writable bytes. Native
        // ML-DSA structs have inline storage only; no native destructor is required.
        unsafe { ffi::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), std::mem::size_of::<T>()) };
    }
}

#[cfg(backend = "boringssl")]
fn boring_sign_mu(variant: Variant, seed: &[u8; 32], mu: &[u8; 64]) -> Result<Vec<u8>> {
    let mut signature = vec![0; variant.signature_size()];
    match variant {
        Variant::MlDsa44 => {
            let mut key = NativeStorage::<ffi::MLDSA44_private_key>::new();
            // SAFETY: Stable correctly aligned native output, exact seed length.
            check(unsafe {
                ffi::MLDSA44_private_key_from_seed(key.ptr(), seed.as_ptr(), seed.len())
            })?;
            // SAFETY: Successfully initialized native key, fixed signature and mu sizes.
            check(unsafe {
                ffi::MLDSA44_sign_message_representative(
                    signature.as_mut_ptr(),
                    key.ptr(),
                    mu.as_ptr(),
                )
            })?;
        }
        Variant::MlDsa65 => {
            let mut key = NativeStorage::<ffi::MLDSA65_private_key>::new();
            // SAFETY: Stable correctly aligned native output, exact seed length.
            check(unsafe {
                ffi::MLDSA65_private_key_from_seed(key.ptr(), seed.as_ptr(), seed.len())
            })?;
            // SAFETY: Successfully initialized native key, fixed signature and mu sizes.
            check(unsafe {
                ffi::MLDSA65_sign_message_representative(
                    signature.as_mut_ptr(),
                    key.ptr(),
                    mu.as_ptr(),
                )
            })?;
        }
        Variant::MlDsa87 => {
            let mut key = NativeStorage::<ffi::MLDSA87_private_key>::new();
            // SAFETY: Stable correctly aligned native output, exact seed length.
            check(unsafe {
                ffi::MLDSA87_private_key_from_seed(key.ptr(), seed.as_ptr(), seed.len())
            })?;
            // SAFETY: Successfully initialized native key, fixed signature and mu sizes.
            check(unsafe {
                ffi::MLDSA87_sign_message_representative(
                    signature.as_mut_ptr(),
                    key.ptr(),
                    mu.as_ptr(),
                )
            })?;
        }
    }
    Ok(signature)
}
#[cfg(backend = "boringssl")]
fn boring_verify_mu(
    variant: Variant,
    public: &[u8],
    mu: &[u8; 64],
    signature: &[u8],
) -> Result<bool> {
    let mut input = std::mem::MaybeUninit::<ffi::CBS>::uninit();
    // SAFETY: CBS_init initializes this output and borrows the immutable public bytes.
    unsafe { ffi::OB_CBS_init(input.as_mut_ptr(), public.as_ptr(), public.len()) };
    let status = match variant {
        Variant::MlDsa44 => {
            let mut key = NativeStorage::<ffi::MLDSA44_public_key>::new();
            // SAFETY: Stable native output and initialized CBS over the public encoding.
            check(unsafe { ffi::MLDSA44_parse_public_key(key.ptr(), input.as_mut_ptr()) })?;
            // SAFETY: Parsed key and signature/mu readable for exact declared lengths.
            unsafe {
                ffi::MLDSA44_verify_message_representative(
                    key.ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    mu.as_ptr(),
                )
            }
        }
        Variant::MlDsa65 => {
            let mut key = NativeStorage::<ffi::MLDSA65_public_key>::new();
            // SAFETY: Stable native output and initialized CBS over the public encoding.
            check(unsafe { ffi::MLDSA65_parse_public_key(key.ptr(), input.as_mut_ptr()) })?;
            // SAFETY: Parsed key and signature/mu readable for exact declared lengths.
            unsafe {
                ffi::MLDSA65_verify_message_representative(
                    key.ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    mu.as_ptr(),
                )
            }
        }
        Variant::MlDsa87 => {
            let mut key = NativeStorage::<ffi::MLDSA87_public_key>::new();
            // SAFETY: Stable native output and initialized CBS over the public encoding.
            check(unsafe { ffi::MLDSA87_parse_public_key(key.ptr(), input.as_mut_ptr()) })?;
            // SAFETY: Parsed key and signature/mu readable for exact declared lengths.
            unsafe {
                ffi::MLDSA87_verify_message_representative(
                    key.ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    mu.as_ptr(),
                )
            }
        }
    };
    Ok(pq::verified(status))
}
