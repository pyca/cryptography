//! Finite-field DH with validated parameters and per-operation native state.
//! This legacy construction is provided for interoperability.
use crate::{
    error::{check, pointer},
    ffi,
    number::Number,
    secret::SecretBytes,
    Error, Result,
};
use std::{
    ptr::{self, NonNull},
    sync::Arc,
};
const MAX_BYTES: usize = 1250; // Native DH maximum is 10,000 bits.
#[derive(Clone, Copy)]
pub struct Components<'a> {
    pub p: &'a [u8],
    pub q: Option<&'a [u8]>,
    pub g: &'a [u8],
}
#[derive(PartialEq, Eq)]
struct ParameterData {
    p: Vec<u8>,
    q: Option<Vec<u8>>,
    g: Vec<u8>,
    bits: usize,
}
#[derive(Clone)]
pub struct Parameters(Arc<ParameterData>);
struct Dh(NonNull<ffi::DH>);
impl Dh {
    fn new() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::DH_new() }).map(Self)
    }
    fn ptr(&self) -> *mut ffi::DH {
        self.0.as_ptr()
    }
    fn from_components(components: Components<'_>) -> Result<Self> {
        let p = Number::from_bytes(components.p, MAX_BYTES)?;
        let q = components
            .q
            .map(|q| Number::from_bytes(q, MAX_BYTES))
            .transpose()?;
        let g = Number::from_bytes(components.g, MAX_BYTES)?;
        if p.bits() < 512
            || g.bits() < 2
            || !g.less_than(&p)
            || q.as_ref()
                .is_some_and(|q| !q.positive() || !q.less_than(&p))
        {
            return Err(Error::InvalidInput("invalid DH parameter range"));
        }
        let dh = Self::new()?;
        // SAFETY: All required numbers are owned, bounded, and non-NULL. set0
        // takes ownership only on success; Rust owners remain live on failure.
        check(unsafe {
            ffi::DH_set0_pqg(
                dh.ptr(),
                p.ptr(),
                q.as_ref().map_or(ptr::null_mut(), Number::ptr),
                g.ptr(),
            )
        })?;
        p.into_raw();
        g.into_raw();
        if let Some(q) = q {
            q.into_raw();
        }
        Ok(dh)
    }
    fn parameters(&self) -> Result<Parameters> {
        let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
        // SAFETY: The complete native DH owns all parameter references; local
        // output pointers are writable and copies are taken before self drops.
        unsafe { ffi::DH_get0_pqg(self.ptr(), &mut p, &mut q, &mut g) };
        // SAFETY: Native getter returns initialized, borrowed component numbers.
        let p = unsafe { Number::copy_raw(p) }?;
        let q = if q.is_null() {
            None
        } else {
            // SAFETY: q is a non-null initialized native parameter.
            Some(unsafe { Number::copy_raw(q) }?)
        };
        // SAFETY: Complete parameters own an initialized generator.
        let g = unsafe { Number::copy_raw(g) }?;
        Ok(Parameters(Arc::new(ParameterData {
            bits: p.bits(),
            p: p.secret_bytes()?.as_ref().to_vec(),
            q: q.map(|q| Ok::<_, Error>(q.secret_bytes()?.as_ref().to_vec()))
                .transpose()?,
            g: g.secret_bytes()?.as_ref().to_vec(),
        })))
    }
    fn check_parameters(&self) -> Result<()> {
        let mut codes = 0;
        // SAFETY: DH has all positive, bounded parameters; codes is writable.
        check(unsafe { ffi::DH_check(self.ptr(), &mut codes) })?;
        if codes != 0 {
            return Err(Error::InvalidInput("invalid DH parameters"));
        }
        Ok(())
    }
    fn check_public(&self, public: &Number) -> Result<()> {
        let mut codes = 0;
        // SAFETY: Parameters are validated and the peer is a bounded positive number.
        check(unsafe { ffi::DH_check_pub_key(self.ptr(), public.ptr(), &mut codes) })?;
        if codes != 0 {
            return Err(Error::InvalidInput("invalid DH public key"));
        }
        Ok(())
    }
    fn set_key(&self, public: Number, private: Option<Number>) -> Result<()> {
        // SAFETY: DH is exclusively owned and not published. Components are
        // owned, initialized, and copied into its ownership only on success.
        check(unsafe {
            ffi::DH_set0_key(
                self.ptr(),
                public.ptr(),
                private.as_ref().map_or(ptr::null_mut(), Number::ptr),
            )
        })?;
        public.into_raw();
        if let Some(p) = private {
            p.into_raw();
        }
        Ok(())
    }
}
impl Drop for Dh {
    fn drop(&mut self) {
        // SAFETY: Sole owner releases DH, which clears its private exponent.
        unsafe { ffi::DH_free(self.ptr()) };
    }
}
impl Parameters {
    pub fn from_components(parts: Components<'_>) -> Result<Self> {
        let dh = Dh::from_components(parts)?;
        dh.check_parameters()?;
        dh.parameters()
    }
    pub fn generate(bits: u32, generator: u32) -> Result<Self> {
        if !(512..=10000).contains(&bits) || !matches!(generator, 2 | 5) {
            return Err(Error::InvalidInput("DH size or generator is out of range"));
        }
        let dh = Dh::new()?;
        // SAFETY: Exclusive DH; bounded size and supported generator. NULL disables callbacks.
        check(unsafe {
            ffi::DH_generate_parameters_ex(dh.ptr(), bits as i32, generator as i32, ptr::null_mut())
        })?;
        dh.check_parameters()?;
        dh.parameters()
    }
    pub fn components(&self) -> Components<'_> {
        Components {
            p: &self.0.p,
            q: self.0.q.as_deref(),
            g: &self.0.g,
        }
    }
    pub fn bits(&self) -> usize {
        self.0.bits
    }
    pub fn generate_key(&self) -> Result<PrivateKey> {
        let dh = Dh::from_components(self.components())?;
        // SAFETY: Exclusive DH contains validated parameters; native routine creates a full key.
        check(unsafe { ffi::DH_generate_key(dh.ptr()) })?;
        let (mut public, mut private) = (ptr::null(), ptr::null());
        // SAFETY: Generated key owns both initialized numbers; get0 only borrows them.
        unsafe { ffi::DH_get0_key(dh.ptr(), &mut public, &mut private) };
        // SAFETY: Successful generation guarantees initialized key components.
        let public = unsafe { Number::copy_raw(public) }?;
        // SAFETY: Successful generation guarantees an initialized private exponent.
        let private = unsafe { Number::copy_raw(private) }?;
        Ok(PrivateKey {
            params: self.clone(),
            private: private.secret_bytes()?,
            public: public.secret_bytes()?.as_ref().to_vec(),
        })
    }
}
pub struct PrivateKey {
    params: Parameters,
    private: SecretBytes,
    public: Vec<u8>,
}
pub struct PublicKey {
    params: Parameters,
    public: Vec<u8>,
}
impl PrivateKey {
    pub fn from_scalar(params: Parameters, scalar: &[u8]) -> Result<Self> {
        let exponent = Number::from_bytes(scalar, MAX_BYTES)?;
        let p = Number::from_bytes(params.components().p, MAX_BYTES)?;
        // Legacy DH imports may use exponents above q (including SSH peers).
        // They are valid modulo the subgroup order. Bound the input by p and
        // validate the resulting public value below, including subgroup checks.
        if !exponent.positive() || !exponent.less_than(&p) {
            return Err(Error::InvalidInput("invalid DH private exponent"));
        }
        let g = Number::from_bytes(params.components().g, MAX_BYTES)?;
        let public = Number::power_mod(&g, &exponent, &p)?;
        Dh::from_components(params.components())?.check_public(&public)?;
        Ok(Self {
            params,
            private: exponent.secret_bytes()?,
            public: public.secret_bytes()?.as_ref().to_vec(),
        })
    }
    pub fn from_components(params: Parameters, scalar: &[u8], public: &[u8]) -> Result<Self> {
        let key = Self::from_scalar(params, scalar)?;
        let public = Number::from_bytes(public, MAX_BYTES)?.secret_bytes()?;
        if key.public != public.as_ref() {
            return Err(Error::InvalidInput(
                "DH public and private components differ",
            ));
        }
        Ok(key)
    }
    pub fn parameters(&self) -> &Parameters {
        &self.params
    }
    pub fn scalar(&self) -> &[u8] {
        self.private.as_ref()
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            params: self.params.clone(),
            public: self.public.clone(),
        }
    }
    pub fn exchange(&self, peer: &PublicKey) -> Result<SecretBytes> {
        if self.params.0 != peer.params.0 {
            return Err(Error::InvalidInput("DH parameters must match"));
        }
        let dh = Dh::from_components(self.params.components())?;
        let peer = Number::from_bytes(&peer.public, MAX_BYTES)?;
        dh.check_public(&peer)?;
        dh.set_key(
            Number::from_bytes(&self.public, MAX_BYTES)?,
            Some(Number::from_bytes(self.private.as_ref(), MAX_BYTES)?),
        )?;
        struct NativeKey(NonNull<ffi::EVP_PKEY>);
        impl NativeKey {
            fn from_dh(dh: &Dh) -> Result<Self> {
                // SAFETY: Native allocator has no preconditions.
                let key = Self(pointer(unsafe { ffi::EVP_PKEY_new() })?);
                // SAFETY: DH is complete; set1 retains its own reference on success.
                check(unsafe { ffi::EVP_PKEY_set1_DH(key.0.as_ptr(), dh.ptr()) })?;
                Ok(key)
            }
        }
        impl Drop for NativeKey {
            fn drop(&mut self) {
                // SAFETY: Releases this owned key reference.
                unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
            }
        }
        struct Operation(NonNull<ffi::EVP_PKEY_CTX>);
        impl Drop for Operation {
            fn drop(&mut self) {
                // SAFETY: Operation context is exclusively owned.
                unsafe { ffi::EVP_PKEY_CTX_free(self.0.as_ptr()) };
            }
        }
        let peer_dh = Dh::from_components(self.params.components())?;
        peer_dh.set_key(peer, None)?;
        let key = NativeKey::from_dh(&dh)?;
        let peer = NativeKey::from_dh(&peer_dh)?;
        // SAFETY: Both complete keys remain alive throughout the operation.
        let op = Operation(pointer(unsafe {
            ffi::EVP_PKEY_CTX_new(key.0.as_ptr(), ptr::null_mut())
        })?);
        // SAFETY: New operation is attached to a complete DH private key.
        check(unsafe { ffi::EVP_PKEY_derive_init(op.0.as_ptr()) })?;
        // SAFETY: Public key has validated matching parameters and subgroup membership.
        check(unsafe { ffi::EVP_PKEY_derive_set_peer(op.0.as_ptr(), peer.0.as_ptr()) })?;
        let mut output: SecretBytes = vec![0; self.params.bits().div_ceil(8)].into();
        let mut length = output.as_ref().len();
        // SAFETY: Output fits the modulus width and capacity is supplied explicitly.
        // EVP preserves provider/FIPS policy for the operation.
        check(unsafe {
            ffi::EVP_PKEY_derive(op.0.as_ptr(), output.as_mut().as_mut_ptr(), &mut length)
        })?;
        crate::error::check_len_at_most(length, output.as_ref().len())?;
        let pad = output.as_ref().len() - length;
        output.as_mut().copy_within(..length, pad);
        output.as_mut()[..pad].fill(0);
        Ok(output)
    }
}
impl PublicKey {
    pub fn from_components(params: Parameters, public: &[u8]) -> Result<Self> {
        let public = Number::from_bytes(public, MAX_BYTES)?;
        Dh::from_components(params.components())?.check_public(&public)?;
        Ok(Self {
            params,
            public: public.secret_bytes()?.as_ref().to_vec(),
        })
    }
    pub fn parameters(&self) -> &Parameters {
        &self.params
    }
    pub fn public_value(&self) -> &[u8] {
        &self.public
    }
}

/// Encoded DH public components for parsing and serialization. This type does
/// not assert that the public value belongs to the group and cannot do crypto.
/// Call `validate` to obtain a key suitable for agreement.
pub struct PublicKeyMaterial {
    params: Parameters,
    public: Vec<u8>,
}
/// Encoded DH private components for legacy import/export. Inconsistent public
/// components may be retained for round trips, but no agreement method exists.
pub struct PrivateKeyMaterial {
    params: Parameters,
    private: SecretBytes,
    public: Vec<u8>,
}
impl PublicKeyMaterial {
    pub fn from_components(params: Parameters, public: &[u8]) -> Result<Self> {
        let public = Number::from_bytes(public, MAX_BYTES)?
            .secret_bytes()?
            .as_ref()
            .to_vec();
        Ok(Self { params, public })
    }
    pub fn parameters(&self) -> &Parameters {
        &self.params
    }
    pub fn public_value(&self) -> &[u8] {
        &self.public
    }
    pub fn validate(&self) -> Result<PublicKey> {
        PublicKey::from_components(self.params.clone(), &self.public)
    }
}
impl PrivateKeyMaterial {
    /// Decode legacy material whose public value is implicit in the encoding.
    /// This computes the value but does not validate the resulting key for use.
    pub fn from_scalar(params: Parameters, scalar: &[u8]) -> Result<Self> {
        let parts = params.components();
        let p = Number::from_bytes(parts.p, MAX_BYTES)?;
        let g = Number::from_bytes(parts.g, MAX_BYTES)?;
        let private = Number::from_bytes(scalar, MAX_BYTES)?;
        let public = Number::power_mod(&g, &private, &p)?.secret_bytes()?;
        Self::from_components(params, scalar, public.as_ref())
    }

    pub fn from_components(params: Parameters, scalar: &[u8], public: &[u8]) -> Result<Self> {
        let private = Number::from_bytes(scalar, MAX_BYTES)?.secret_bytes()?;
        let public = Number::from_bytes(public, MAX_BYTES)?
            .secret_bytes()?
            .as_ref()
            .to_vec();
        Ok(Self {
            params,
            private,
            public,
        })
    }
    pub fn parameters(&self) -> &Parameters {
        &self.params
    }
    pub fn scalar(&self) -> &[u8] {
        self.private.as_ref()
    }
    pub fn public_key(&self) -> PublicKeyMaterial {
        PublicKeyMaterial {
            params: self.params.clone(),
            public: self.public.clone(),
        }
    }
    pub fn validate(&self) -> Result<PrivateKey> {
        PrivateKey::from_components(self.params.clone(), self.private.as_ref(), &self.public)
    }
}
impl From<PrivateKey> for PrivateKeyMaterial {
    fn from(key: PrivateKey) -> Self {
        Self {
            params: key.params,
            private: key.private,
            public: key.public,
        }
    }
}
impl From<PublicKey> for PublicKeyMaterial {
    fn from(key: PublicKey) -> Self {
        Self {
            params: key.params,
            public: key.public,
        }
    }
}
