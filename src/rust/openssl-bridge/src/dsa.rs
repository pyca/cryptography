//! Legacy DSA with checked parameters and separate signing/verification keys.
use crate::{
    error::{check, pointer},
    ffi,
    hash::Algorithm,
    number::Number,
    secret::SecretBytes,
    Error, Result,
};
use std::{
    collections::VecDeque,
    ptr::{self, NonNull},
    sync::{Arc, Mutex},
};
const MAX_BYTES: usize = 512;
#[derive(Clone, Copy)]
pub struct Components<'a> {
    pub p: &'a [u8],
    pub q: &'a [u8],
    pub g: &'a [u8],
}
#[derive(PartialEq, Eq)]
struct ParameterData {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    bits: usize,
}
#[derive(Clone)]
pub struct Parameters(Arc<ParameterData>);
// Public mathematical parameters only: no private key, native state, or provider
// decision is retained. Exact canonical values avoid hash-collision assumptions.
// At most 32 * (512 + 32 + 512) bytes of public component payload are retained.
// Native validation happens outside this lock; duplicate concurrent misses may
// do redundant checks but can never publish an unchecked group.
static VALIDATED_GROUPS: Mutex<VecDeque<Arc<ParameterData>>> = Mutex::new(VecDeque::new());
const GROUP_CACHE_LIMIT: usize = 32;

fn cached_group(data: &ParameterData) -> Option<Parameters> {
    // A poisoned cache is bypassed. It is an optimization, not validation state
    // required to carry out the operation or a reason to panic in a public API.
    let cache = VALIDATED_GROUPS.lock().ok()?;
    cache
        .iter()
        .find(|entry| entry.as_ref() == data)
        .map(|entry| Parameters(entry.clone()))
}

fn retain_validated_group(data: ParameterData) -> Parameters {
    let data = Arc::new(data);
    if let Ok(mut cache) = VALIDATED_GROUPS.lock() {
        if let Some(existing) = cache.iter().find(|entry| entry.as_ref() == data.as_ref()) {
            return Parameters(existing.clone());
        }
        if cache.len() == GROUP_CACHE_LIMIT {
            cache.pop_front();
        }
        cache.push_back(data.clone());
        // NO-COVERAGE-START
        // No application code runs under this cache lock. LLVM attributes the defensive
        // poisoned-lock bypass to this delimiter.
    }
    // NO-COVERAGE-END
    Parameters(data)
}
struct Dsa(NonNull<ffi::DSA>);
impl Dsa {
    fn new() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::DSA_new() }).map(Self)
    }
    fn ptr(&self) -> *mut ffi::DSA {
        self.0.as_ptr()
    }
    fn from_parameters(params: &Parameters) -> Result<Self> {
        let p = Number::from_bytes(&params.0.p, MAX_BYTES)?;
        let q = Number::from_bytes(&params.0.q, 32)?;
        let g = Number::from_bytes(&params.0.g, MAX_BYTES)?;
        let dsa = Self::new()?;
        // SAFETY: Parameters were validated and all numbers are exclusively owned.
        // Ownership transfers only when set0 succeeds.
        check(unsafe { ffi::DSA_set0_pqg(dsa.ptr(), p.ptr(), q.ptr(), g.ptr()) })?;
        p.into_raw();
        q.into_raw();
        g.into_raw();
        Ok(dsa)
    }
    fn set_key(&self, public: &[u8], private: Option<&[u8]>) -> Result<()> {
        let public = Number::from_bytes(public, MAX_BYTES)?;
        let private = private.map(|v| Number::from_bytes(v, 32)).transpose()?;
        // SAFETY: This exclusive DSA already has complete parameters. Components
        // are owned and the caller guarantees their validated relationship.
        check(unsafe {
            ffi::DSA_set0_key(
                self.ptr(),
                public.ptr(),
                private.as_ref().map_or(ptr::null_mut(), Number::ptr),
            )
        })?;
        public.into_raw();
        if let Some(private) = private {
            private.into_raw();
        }
        Ok(())
    }
    fn parameters(&self) -> Result<Parameters> {
        let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
        // SAFETY: Used only after successful native parameter generation.
        unsafe { ffi::DSA_get0_pqg(self.ptr(), &mut p, &mut q, &mut g) };
        // SAFETY: Successful generation initializes all three borrowed numbers.
        let p = unsafe { Number::copy_raw(p) }?;
        // SAFETY: q is an initialized number owned by this native DSA.
        let q = unsafe { Number::copy_raw(q) }?;
        // SAFETY: g is an initialized number owned by this native DSA.
        let g = unsafe { Number::copy_raw(g) }?;
        Ok(Parameters(Arc::new(ParameterData {
            bits: p.bits(),
            p: p.secret_bytes()?.as_ref().to_vec(),
            q: q.secret_bytes()?.as_ref().to_vec(),
            g: g.secret_bytes()?.as_ref().to_vec(),
        })))
    }
}
impl Drop for Dsa {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns DSA; native destruction clears its private key.
        unsafe { ffi::DSA_free(self.ptr()) };
    }
}
impl Parameters {
    pub fn from_components(parts: Components<'_>) -> Result<Self> {
        let p = Number::from_bytes(parts.p, MAX_BYTES)?;
        let q = Number::from_bytes(parts.q, 32)?;
        let g = Number::from_bytes(parts.g, MAX_BYTES)?;
        if ![1024, 2048, 3072, 4096].contains(&p.bits())
            || ![160, 224, 256].contains(&q.bits())
            || g.bits() < 2
            || !g.less_than(&p)
        {
            return Err(Error::InvalidInput(
                "invalid DSA parameter sizes or generator",
            ));
        }
        let data = ParameterData {
            bits: p.bits(),
            p: p.secret_bytes()?.as_ref().to_vec(),
            q: q.secret_bytes()?.as_ref().to_vec(),
            g: g.secret_bytes()?.as_ref().to_vec(),
        };
        if let Some(validated) = cached_group(&data) {
            return Ok(validated);
        }
        if !p.is_prime()?
            || !q.is_prime()?
            || !p.modulo(&q)?.is_one()
            || !Number::power_mod(&g, &q, &p)?.is_one()
        {
            return Err(Error::InvalidInput("invalid DSA group"));
        }
        Ok(retain_validated_group(data))
    }
    pub fn generate(bits: u32) -> Result<Self> {
        if ![1024, 2048, 3072, 4096].contains(&bits) {
            return Err(Error::InvalidInput("unsupported DSA parameter size"));
        }
        let dsa = Dsa::new()?;
        #[allow(clippy::useless_conversion)]
        let native_bits = bits
            .try_into()
            .map_err(|_| Error::InvalidInput("DSA bit size exceeds native limit"))?;
        // SAFETY: Exclusive DSA and checked bit size. NULL seed selects native
        // randomness; unused counters and callbacks are explicitly NULL.
        check(unsafe {
            ffi::DSA_generate_parameters_ex(
                dsa.ptr(),
                native_bits,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })?;
        dsa.parameters()
    }
    pub fn components(&self) -> Components<'_> {
        Components {
            p: &self.0.p,
            q: &self.0.q,
            g: &self.0.g,
        }
    }
    pub fn bits(&self) -> usize {
        self.0.bits
    }
    pub fn generate_key(&self) -> Result<PrivateKey> {
        let dsa = Dsa::from_parameters(self)?;
        // SAFETY: Exclusive native state contains complete validated parameters.
        check(unsafe { ffi::DSA_generate_key(dsa.ptr()) })?;
        let (mut public, mut private) = (ptr::null(), ptr::null());
        // SAFETY: Successful generation guarantees both key components.
        unsafe { ffi::DSA_get0_key(dsa.ptr(), &mut public, &mut private) };
        // SAFETY: Live native key owns initialized public and private numbers.
        let public = unsafe { Number::copy_raw(public) }?;
        // SAFETY: The initialized private exponent remains borrowed for copying.
        let private = unsafe { Number::copy_raw(private) }?;
        Ok(PrivateKey {
            params: self.clone(),
            private: private.secret_bytes()?,
            public: public.secret_bytes()?.as_ref().to_vec(),
        })
    }
}
struct NativeKey(NonNull<ffi::EVP_PKEY>);
impl Drop for NativeKey {
    fn drop(&mut self) {
        // SAFETY: This owns exactly one native key reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
struct Operation {
    ctx: NonNull<ffi::EVP_PKEY_CTX>,
    _key: NativeKey,
}
impl Operation {
    fn new(params: &Parameters, public: &[u8], private: Option<&[u8]>) -> Result<Self> {
        let dsa = Dsa::from_parameters(params)?;
        dsa.set_key(public, private)?;
        // SAFETY: Native allocator has no preconditions.
        let key = NativeKey(pointer(unsafe { ffi::EVP_PKEY_new() })?);
        // SAFETY: Complete DSA is alive and set1 retains a reference on success.
        check(unsafe { ffi::EVP_PKEY_set1_DSA(key.0.as_ptr(), dsa.ptr()) })?;
        // SAFETY: Complete key lives through the operation; context retains it too.
        let ctx = pointer(unsafe { ffi::EVP_PKEY_CTX_new(key.0.as_ptr(), ptr::null_mut()) })?;
        Ok(Self { ctx, _key: key })
    }
    fn ptr(&mut self) -> *mut ffi::EVP_PKEY_CTX {
        self.ctx.as_ptr()
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        // SAFETY: Exclusive operation is released before its key field.
        unsafe { ffi::EVP_PKEY_CTX_free(self.ctx.as_ptr()) };
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
        let private = Number::from_bytes(scalar, 32)?;
        let q = Number::from_bytes(&params.0.q, 32)?;
        if !private.positive() || !private.less_than(&q) {
            return Err(Error::InvalidInput("DSA private scalar must be in [1,q)"));
        }
        let p = Number::from_bytes(&params.0.p, MAX_BYTES)?;
        let g = Number::from_bytes(&params.0.g, MAX_BYTES)?;
        let public = Number::power_mod(&g, &private, &p)?;
        Ok(Self {
            params,
            private: private.secret_bytes()?,
            public: public.secret_bytes()?.as_ref().to_vec(),
        })
    }
    pub fn from_components(params: Parameters, scalar: &[u8], public: &[u8]) -> Result<Self> {
        let key = Self::from_scalar(params, scalar)?;
        let public = Number::from_bytes(public, MAX_BYTES)?.secret_bytes()?;
        if key.public != public.as_ref() {
            return Err(Error::InvalidInput(
                "DSA public and private components differ",
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
    pub fn sign_digest(&self, algorithm: Algorithm, digest: &[u8]) -> Result<Vec<u8>> {
        if algorithm.is_xof() || digest.len() != algorithm.output_size()? {
            return Err(Error::InvalidInput("incorrect DSA digest length"));
        }
        let mut op = Operation::new(&self.params, &self.public, Some(self.private.as_ref()))?;
        // SAFETY: Fresh operation owns a complete validated DSA private key.
        check(unsafe { ffi::EVP_PKEY_sign_init(op.ptr()) })?;
        let mut length = 0;
        // SAFETY: NULL output queries the required DER capacity without writing.
        check(unsafe {
            ffi::EVP_PKEY_sign(
                op.ptr(),
                ptr::null_mut(),
                &mut length,
                digest.as_ptr(),
                digest.len(),
            )
        })?;
        crate::error::check_len_at_most(length, 2 * self.params.0.q.len() + 16)?;
        let mut output = vec![0; length];
        // SAFETY: Output fits the native maximum and its capacity is supplied.
        check(unsafe {
            ffi::EVP_PKEY_sign(
                op.ptr(),
                output.as_mut_ptr(),
                &mut length,
                digest.as_ptr(),
                digest.len(),
            )
        })?;
        crate::error::check_len_at_most(length, output.len())?;
        output.truncate(length);
        Ok(output)
    }
}
impl PublicKey {
    pub fn from_components(params: Parameters, public: &[u8]) -> Result<Self> {
        let public = Number::from_bytes(public, MAX_BYTES)?;
        let p = Number::from_bytes(&params.0.p, MAX_BYTES)?;
        let q = Number::from_bytes(&params.0.q, 32)?;
        if public.bits() < 2
            || !public.less_than(&p)
            || !Number::power_mod(&public, &q, &p)?.is_one()
        {
            return Err(Error::InvalidInput("invalid DSA public key"));
        }
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
    pub fn verify_digest(
        &self,
        algorithm: Algorithm,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        if algorithm.is_xof() || digest.len() != algorithm.output_size()? {
            return Err(Error::InvalidInput("incorrect DSA digest length"));
        }
        if signature.len() > 2 * self.params.0.q.len() + 16 {
            return Ok(false);
        }
        let mut op = Operation::new(&self.params, &self.public, None)?;
        // SAFETY: Fresh operation owns a complete validated DSA public key.
        check(unsafe { ffi::EVP_PKEY_verify_init(op.ptr()) })?;
        // SAFETY: All input borrows cover their declared sizes; verifier has no output.
        let valid = unsafe {
            ffi::EVP_PKEY_verify(
                op.ptr(),
                signature.as_ptr(),
                signature.len(),
                digest.as_ptr(),
                digest.len(),
            )
        };
        if valid == 1 {
            Ok(true)
        } else {
            let _ = Error::capture();
            Ok(false)
        }
    }
}

/// Bounded parameter encodings for legacy parsing. Cryptographic operations
/// require the checked `Parameters` returned by `validate`.
#[derive(Clone)]
pub struct ParameterMaterial {
    data: Arc<ParameterData>,
    validated: Arc<std::sync::OnceLock<Result<Parameters>>>,
}
impl ParameterMaterial {
    pub fn from_components(parts: Components<'_>) -> Result<Self> {
        let p = Number::from_bytes(parts.p, MAX_BYTES)?;
        let q = Number::from_bytes(parts.q, 32)?;
        let g = Number::from_bytes(parts.g, MAX_BYTES)?;
        Ok(Self {
            data: Arc::new(ParameterData {
                bits: p.bits(),
                p: p.secret_bytes()?.as_ref().to_vec(),
                q: q.secret_bytes()?.as_ref().to_vec(),
                g: g.secret_bytes()?.as_ref().to_vec(),
            }),
            validated: Arc::new(std::sync::OnceLock::new()),
        })
    }
    pub fn components(&self) -> Components<'_> {
        Components {
            p: &self.data.p,
            q: &self.data.q,
            g: &self.data.g,
        }
    }
    pub fn bits(&self) -> usize {
        self.data.bits
    }
    pub fn validate(&self) -> Result<Parameters> {
        self.validated
            .get_or_init(|| Parameters::from_components(self.components()))
            .clone()
    }
}
impl From<Parameters> for ParameterMaterial {
    fn from(params: Parameters) -> Self {
        Self {
            data: params.0.clone(),
            validated: Arc::new(std::sync::OnceLock::from(Ok(params))),
        }
    }
}
/// Passive private key encodings. This has no signing operation; validation is
/// explicit and mathematical failures are cached without entering native signing.
pub struct PrivateKeyMaterial {
    params: ParameterMaterial,
    private: SecretBytes,
    public: Vec<u8>,
    validated: std::sync::OnceLock<Result<PrivateKey>>,
}
/// Passive public key encodings. This has no verification operation.
pub struct PublicKeyMaterial {
    params: ParameterMaterial,
    public: Vec<u8>,
    validated: std::sync::OnceLock<Result<PublicKey>>,
}
impl PrivateKeyMaterial {
    /// Decode legacy material whose public value is implicit in the encoding.
    /// This computes the value but does not validate the resulting key for use.
    pub fn from_scalar(params: ParameterMaterial, scalar: &[u8]) -> Result<Self> {
        let parts = params.components();
        let p = Number::from_bytes(parts.p, MAX_BYTES)?;
        let g = Number::from_bytes(parts.g, MAX_BYTES)?;
        let private = Number::from_bytes(scalar, 32)?;
        let public = Number::power_mod(&g, &private, &p)?.secret_bytes()?;
        Self::from_components(params, scalar, public.as_ref())
    }

    pub fn from_components(
        params: ParameterMaterial,
        scalar: &[u8],
        public: &[u8],
    ) -> Result<Self> {
        let private = Number::from_bytes(scalar, 32)?.secret_bytes()?;
        let public = Number::from_bytes(public, MAX_BYTES)?
            .secret_bytes()?
            .as_ref()
            .to_vec();
        Ok(Self {
            params,
            private,
            public,
            validated: std::sync::OnceLock::new(),
        })
    }
    pub fn parameters(&self) -> &ParameterMaterial {
        &self.params
    }
    pub fn scalar(&self) -> &[u8] {
        self.private.as_ref()
    }
    pub fn public_key(&self) -> PublicKeyMaterial {
        PublicKeyMaterial {
            params: self.params.clone(),
            public: self.public.clone(),
            validated: std::sync::OnceLock::new(),
        }
    }
    pub fn validate(&self) -> Result<&PrivateKey> {
        self.validated
            .get_or_init(|| {
                PrivateKey::from_components(
                    self.params.validate()?,
                    self.private.as_ref(),
                    &self.public,
                )
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}
impl PublicKeyMaterial {
    pub fn from_components(params: ParameterMaterial, public: &[u8]) -> Result<Self> {
        let public = Number::from_bytes(public, MAX_BYTES)?
            .secret_bytes()?
            .as_ref()
            .to_vec();
        Ok(Self {
            params,
            public,
            validated: std::sync::OnceLock::new(),
        })
    }
    pub fn parameters(&self) -> &ParameterMaterial {
        &self.params
    }
    pub fn public_value(&self) -> &[u8] {
        &self.public
    }
    pub fn validate(&self) -> Result<&PublicKey> {
        self.validated
            .get_or_init(|| PublicKey::from_components(self.params.validate()?, &self.public))
            .as_ref()
            .map_err(Clone::clone)
    }
}
impl From<PrivateKey> for PrivateKeyMaterial {
    fn from(key: PrivateKey) -> Self {
        Self {
            params: key.params.into(),
            private: key.private,
            public: key.public,
            validated: std::sync::OnceLock::new(),
        }
    }
}
impl From<PublicKey> for PublicKeyMaterial {
    fn from(key: PublicKey) -> Self {
        Self {
            params: key.params.into(),
            public: key.public,
            validated: std::sync::OnceLock::new(),
        }
    }
}
