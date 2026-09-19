//! ML-KEM key encapsulation. Decapsulation uses implicit rejection: a correctly
//! sized invalid ciphertext yields a different secret, not an authentication error.
use crate::{
    curve25519::Secret,
    error::check,
    ffi,
    pq::{self, Key},
    Error, Result,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variant {
    MlKem768,
    MlKem1024,
}
impl Variant {
    fn algorithm(self) -> pq::Algorithm {
        match self {
            Self::MlKem768 => pq::Algorithm::Kem768,
            Self::MlKem1024 => pq::Algorithm::Kem1024,
        }
    }
    pub fn public_key_size(self) -> usize {
        self.algorithm().public_len()
    }
    pub fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
}
pub struct PrivateKey {
    variant: Variant,
    seed: Secret<64>,
    public: Vec<u8>,
}
#[derive(Clone)]
pub struct PublicKey {
    variant: Variant,
    public: Vec<u8>,
}
impl PrivateKey {
    pub fn from_seed(variant: Variant, seed: &[u8; 64]) -> Result<Self> {
        let key = Key::private(variant.algorithm(), seed)?;
        Ok(Self {
            variant,
            seed: Secret(*seed),
            public: key.public_bytes(variant.algorithm())?,
        })
    }
    pub fn generate(variant: Variant) -> Result<Self> {
        let mut seed = Secret([0; 64]);
        crate::rand::fill_private(&mut seed.0)?;
        Self::from_seed(variant, &seed.0)
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed.0
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            variant: self.variant,
            public: self.public.clone(),
        }
    }
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Secret<32>> {
        if ciphertext.len() != self.variant.ciphertext_size() {
            return Err(Error::InvalidInput("incorrect ML-KEM ciphertext length"));
        }
        let key = Key::private(self.variant.algorithm(), self.seed.as_ref())?;
        let ctx = key.context()?;
        #[cfg(not(backend = "awslc"))]
        // SAFETY: Fresh context containing a complete ML-KEM private key.
        check(unsafe { ffi::EVP_PKEY_decapsulate_init(ctx.ptr(), std::ptr::null()) })?;
        let mut secret = Secret([0; 32]);
        let mut size = secret.0.len();
        // SAFETY: Secret output has the exact fixed size and ciphertext length was
        // checked before entering native code. Error paths erase secret on drop.
        check(unsafe {
            ffi::EVP_PKEY_decapsulate(
                ctx.ptr(),
                secret.0.as_mut_ptr(),
                &mut size,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        })?;
        if size != secret.0.len() {
            return Err(Error::InvalidState("unexpected ML-KEM shared secret size"));
        }
        Ok(secret)
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
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Secret<32>)> {
        let key = Key::public(self.variant.algorithm(), &self.public)?;
        let ctx = key.context()?;
        #[cfg(not(backend = "awslc"))]
        // SAFETY: Fresh context containing a complete ML-KEM public key.
        check(unsafe { ffi::EVP_PKEY_encapsulate_init(ctx.ptr(), std::ptr::null()) })?;
        let mut ciphertext = vec![0; self.variant.ciphertext_size()];
        let mut secret = Secret([0; 32]);
        let mut ct_size = ciphertext.len();
        let mut ss_size = secret.0.len();
        // SAFETY: Both native in/out lengths contain the actual output capacities;
        // algorithm constants give exact sizes. Partial secrets erase on all exits.
        check(unsafe {
            ffi::EVP_PKEY_encapsulate(
                ctx.ptr(),
                ciphertext.as_mut_ptr(),
                &mut ct_size,
                secret.0.as_mut_ptr(),
                &mut ss_size,
            )
        })?;
        if ct_size != ciphertext.len() || ss_size != secret.0.len() {
            return Err(Error::InvalidState(
                "unexpected ML-KEM encapsulation output size",
            ));
        }
        Ok((ciphertext, secret))
    }
}
