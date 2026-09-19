//! RSA keys with complete construction and operation-specific padding.
use crate::{
    error::{check, pointer},
    ffi,
    hash::Algorithm,
    Error, Result,
};
use std::{
    mem,
    ptr::{self, NonNull},
};

struct Number(NonNull<ffi::BIGNUM>);
impl Number {
    fn new(bytes: &[u8]) -> Result<Self> {
        crate::error::input_length::<i32>(
            bytes.len().saturating_mul(8),
            "RSA component bit length exceeds INT_MAX",
        )?;
        if bytes.iter().all(|b| *b == 0) {
            return Err(Error::InvalidInput("RSA components must be positive"));
        }
        #[allow(clippy::useless_conversion)] // size_t on BoringSSL/AWS-LC, int elsewhere.
        let len = bytes
            .len()
            .try_into()
            .map_err(|_| Error::InvalidInput("RSA component is too large"))?;
        // SAFETY: bytes covers the checked length. NULL requests a new allocation.
        pointer(unsafe { ffi::BN_bin2bn(bytes.as_ptr(), len, ptr::null_mut()) }).map(Self)
    }
    fn ptr(&self) -> *mut ffi::BIGNUM {
        self.0.as_ptr()
    }
    fn is_even(&self) -> bool {
        // SAFETY: This owns a live positive number; reading bit zero is valid.
        unsafe { ffi::BN_is_bit_set(self.ptr(), 0) == 0 }
    }
}
impl Drop for Number {
    fn drop(&mut self) {
        // SAFETY: This is the sole owner of the native number.
        unsafe { ffi::BN_clear_free(self.ptr()) };
    }
}

struct Rsa(NonNull<ffi::RSA>);
impl Rsa {
    fn new() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: The allocator has no preconditions.
        pointer(unsafe { ffi::RSA_new() }).map(Self)
    }
    fn ptr(&self) -> *mut ffi::RSA {
        self.0.as_ptr()
    }
    fn public(n: &[u8], e: &[u8]) -> Result<Self> {
        let n = Number::new(n)?;
        let e = Number::new(e)?;
        let three = Number::new(&[3])?;
        // SAFETY: All arguments are live, positive numbers. These queries do not mutate them.
        if unsafe { ffi::BN_cmp(e.ptr(), three.ptr()) < 0 || ffi::BN_cmp(e.ptr(), n.ptr()) >= 0 }
            || e.is_even()
        {
            return Err(Error::InvalidInput("invalid RSA public components"));
        }
        let rsa = Self::new()?;
        // SAFETY: Required public components are non-NULL. On success ownership
        // transfers to rsa; on failure the Number owners retain the allocations.
        check(unsafe { ffi::RSA_set0_key(rsa.ptr(), n.ptr(), e.ptr(), ptr::null_mut()) })?;
        mem::forget(n);
        mem::forget(e);
        Ok(rsa)
    }
}
impl Drop for Rsa {
    fn drop(&mut self) {
        // SAFETY: This releases the owned reference and all transferred components.
        unsafe { ffi::RSA_free(self.ptr()) };
    }
}

struct Key(NonNull<ffi::EVP_PKEY>);
// SAFETY: Keys are immutable after construction; operations own separate contexts.
unsafe impl Send for Key {}
// SAFETY: Shared key operations use the backend's thread-safe built-in RSA implementation.
unsafe impl Sync for Key {}
impl Key {
    fn from_rsa(rsa: Rsa) -> Result<Self> {
        // SAFETY: The allocator has no preconditions.
        let result = Self(pointer(unsafe { ffi::EVP_PKEY_new() })?);
        // SAFETY: set1 retains its own RSA reference on success. The temporary
        // Rsa owner drops its reference afterward, including on failure.
        check(unsafe { ffi::EVP_PKEY_set1_RSA(result.0.as_ptr(), rsa.ptr()) })?;
        Ok(result)
    }
    fn rsa(&self) -> *const ffi::RSA {
        // SAFETY: Every Key here was constructed from RSA. The borrowed pointer
        // remains live for the lifetime of self and is never mutated or freed.
        unsafe { ffi::EVP_PKEY_get0_RSA(self.0.as_ptr()) }
    }
    fn size(&self) -> Result<usize> {
        // SAFETY: rsa() is a live immutable RSA key with a positive modulus.
        usize::try_from(unsafe { ffi::RSA_size(self.rsa()) })
            .ok()
            .filter(|n| *n > 0)
            .ok_or(Error::InvalidState("invalid RSA output size"))
    }
    fn bits(&self) -> u32 {
        let mut n = ptr::null();
        // SAFETY: All Key instances contain a positive modulus. get0 returns a
        // borrowed component without changing the key's reference count.
        unsafe {
            ffi::RSA_get0_key(self.rsa(), &mut n, ptr::null_mut(), ptr::null_mut());
            ffi::BN_num_bits(n) as u32
        }
    }
    fn public_parts(&self) -> Result<PublicComponents> {
        let (mut n, mut e) = (ptr::null(), ptr::null());
        // SAFETY: Both required components are borrowed from this live RSA key.
        unsafe {
            ffi::RSA_get0_key(self.rsa(), &mut n, &mut e, ptr::null_mut());
            Ok(PublicComponents {
                n: component(n)?,
                e: component(e)?,
            })
        }
    }
}
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Release the sole owned EVP_PKEY reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}

/// # Safety
/// The pointer must refer to a live immutable BIGNUM throughout the call.
#[allow(clippy::useless_conversion)] // BN_bn2bin returns size_t on BoringSSL/AWS-LC.
unsafe fn component(number: *const ffi::BIGNUM) -> Result<Vec<u8>> {
    if number.is_null() {
        return Err(Error::InvalidState("missing RSA component"));
    }
    // SAFETY: The caller guarantees the borrowed number remains live.
    let bits = unsafe { ffi::BN_num_bits(number) };
    let size = usize::try_from(bits)
        .map_err(|_| Error::InvalidState("invalid component size"))?
        .div_ceil(8);
    let mut bytes = vec![0; size];
    // SAFETY: The destination has exactly BN_num_bytes(number) bytes.
    let written = unsafe { ffi::BN_bn2bin(number, bytes.as_mut_ptr()) };
    crate::secret::clear_on_error(crate::error::check_len(written as usize, size), &mut bytes)?;
    Ok(bytes)
}

struct Context(NonNull<ffi::EVP_PKEY_CTX>);
impl Context {
    fn new(key: &Key) -> Result<Self> {
        // SAFETY: The context retains its own reference to this live key.
        pointer(unsafe { ffi::EVP_PKEY_CTX_new(key.0.as_ptr(), ptr::null_mut()) }).map(Self)
    }
    fn ptr(&mut self) -> *mut ffi::EVP_PKEY_CTX {
        self.0.as_ptr()
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: This is the unique context owner, in any initialization state.
        unsafe { ffi::EVP_PKEY_CTX_free(self.0.as_ptr()) };
    }
}

pub struct PublicComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}
#[derive(Clone, Copy)]
pub struct PrivateComponents<'a> {
    pub n: &'a [u8],
    pub e: &'a [u8],
    pub d: &'a [u8],
    pub p: &'a [u8],
    pub q: &'a [u8],
    pub dmp1: &'a [u8],
    pub dmq1: &'a [u8],
    pub iqmp: &'a [u8],
}

#[derive(Clone, Copy)]
pub enum Validation {
    /// Check structure, primality, and private-key arithmetic using the backend.
    Full,
    /// Check complete positive components, ranges, odd factors and n = p * q.
    /// Do not establish primality or correctness of the private/CRT exponents.
    /// This is intended for keys whose arithmetic has already been validated.
    Structural,
}

struct NumberContext(NonNull<ffi::BN_CTX>);
impl Drop for NumberContext {
    fn drop(&mut self) {
        // SAFETY: The context is uniquely owned and has no outstanding borrows.
        unsafe { ffi::BN_CTX_free(self.0.as_ptr()) };
    }
}

fn validate_structure(
    n: &Number,
    d: &Number,
    factors: [&Number; 2],
    crt: [&Number; 3],
) -> Result<()> {
    let [p, q] = factors;
    let [dmp1, dmq1, iqmp] = crt;
    let one = Number::new(&[1])?;
    // SAFETY: All numbers are live, positive and immutable throughout these
    // comparisons. Restrict the multiplication's result to a bounded bit length.
    let in_range = unsafe {
        ffi::BN_cmp(p.ptr(), one.ptr()) > 0
            && ffi::BN_cmp(q.ptr(), one.ptr()) > 0
            && ffi::BN_cmp(p.ptr(), n.ptr()) < 0
            && ffi::BN_cmp(q.ptr(), n.ptr()) < 0
            && ffi::BN_cmp(d.ptr(), n.ptr()) < 0
            && ffi::BN_cmp(dmp1.ptr(), p.ptr()) < 0
            && ffi::BN_cmp(dmq1.ptr(), q.ptr()) < 0
            && ffi::BN_cmp(iqmp.ptr(), p.ptr()) < 0
            && u64::from(ffi::BN_num_bits(p.ptr()) as u32)
                + u64::from(ffi::BN_num_bits(q.ptr()) as u32)
                <= i32::MAX as u64
    };
    if !in_range || p.is_even() || q.is_even() {
        return Err(Error::InvalidInput("invalid RSA private component ranges"));
    }
    // SAFETY: These allocators have no preconditions; RAII owns both immediately.
    let ctx = NumberContext(pointer(unsafe { ffi::BN_CTX_new() })?);
    // SAFETY: The allocator has no preconditions.
    let product = Number(pointer(unsafe { ffi::BN_new() })?);
    // SAFETY: Destination and context are exclusive and do not alias the factors.
    check(unsafe { ffi::BN_mul(product.ptr(), p.ptr(), q.ptr(), ctx.0.as_ptr()) })?;
    // SAFETY: Both numbers remain live and immutable.
    if unsafe { ffi::BN_cmp(product.ptr(), n.ptr()) } != 0 {
        return Err(Error::InvalidInput("RSA modulus must equal p * q"));
    }
    Ok(())
}

/// Owns a private component export and erases it on drop.
pub struct PrivateExport {
    parts: [Vec<u8>; 8],
}
impl PrivateExport {
    pub fn components(&self) -> PrivateComponents<'_> {
        let [n, e, d, p, q, dmp1, dmq1, iqmp] = &self.parts;
        PrivateComponents {
            n,
            e,
            d,
            p,
            q,
            dmp1,
            dmq1,
            iqmp,
        }
    }
}
impl Drop for PrivateExport {
    fn drop(&mut self) {
        for part in &mut self.parts {
            cleanse(part);
        }
    }
}

/// Secret output, erased when dropped; no implicit Debug or Clone implementation.
pub struct Plaintext(Vec<u8>);
impl AsRef<[u8]> for Plaintext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Plaintext {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}
fn cleanse(bytes: &mut [u8]) {
    // SAFETY: Exclusive slice covers exactly the memory to erase.
    unsafe { ffi::OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
}

#[derive(Clone, Copy)]
pub enum SaltLength {
    Digest,
    Maximum,
    Exact(u32),
}
#[derive(Clone, Copy)]
pub enum SigningPadding {
    Pkcs1v15,
    Pss { mgf1: Algorithm, salt: SaltLength },
}
#[derive(Clone, Copy)]
pub enum VerificationPadding {
    Pkcs1v15,
    Pss { mgf1: Algorithm, salt: SaltLength },
    PssAuto { mgf1: Algorithm },
}
#[derive(Clone, Copy)]
pub enum EncryptionPadding<'a> {
    Pkcs1v15,
    Oaep {
        digest: Algorithm,
        mgf1: Algorithm,
        label: &'a [u8],
    },
}

pub struct PrivateKey(Key);
pub struct PublicKey(Key);
impl PrivateKey {
    pub fn signature_digest_supported(&self, digest: Algorithm) -> Result<bool> {
        signature_digest_supported(&self.0, digest, true)
    }
    pub fn generate(bits: u32, exponent: u32) -> Result<Self> {
        let bits =
            i32::try_from(bits).map_err(|_| Error::InvalidInput("RSA modulus is too large"))?;
        if bits < 512 || exponent < 3 || exponent % 2 == 0 {
            return Err(Error::InvalidInput("invalid RSA generation parameters"));
        }
        let e = Number::new(&exponent.to_be_bytes())?;
        let rsa = Rsa::new()?;
        // SAFETY: rsa is exclusively owned and e is a positive odd exponent.
        // No callback is installed; generation failure drops partial state.
        check(unsafe { ffi::RSA_generate_key_ex(rsa.ptr(), bits, e.ptr(), ptr::null_mut()) })?;
        Key::from_rsa(rsa).map(Self)
    }
    pub fn from_components(parts: PrivateComponents<'_>) -> Result<Self> {
        Self::from_components_with_validation(parts, Validation::Full)
    }
    pub fn from_components_with_validation(
        parts: PrivateComponents<'_>,
        validation: Validation,
    ) -> Result<Self> {
        let rsa = Rsa::public(parts.n, parts.e)?;
        let n = Number::new(parts.n)?;
        let d = Number::new(parts.d)?;
        let p = Number::new(parts.p)?;
        let q = Number::new(parts.q)?;
        let dmp1 = Number::new(parts.dmp1)?;
        let dmq1 = Number::new(parts.dmq1)?;
        let iqmp = Number::new(parts.iqmp)?;
        validate_structure(&n, &d, [&p, &q], [&dmp1, &dmq1, &iqmp])?;
        // SAFETY: rsa already has n/e. Each successful set0 call transfers the
        // supplied allocations; later failure drops rsa and its installed parts.
        check(unsafe { ffi::RSA_set0_key(rsa.ptr(), ptr::null_mut(), ptr::null_mut(), d.ptr()) })?;
        mem::forget(d);
        // SAFETY: Both factors are live and owned until this call succeeds.
        check(unsafe { ffi::RSA_set0_factors(rsa.ptr(), p.ptr(), q.ptr()) })?;
        mem::forget(p);
        mem::forget(q);
        // SAFETY: All CRT parameters are live and owned until success.
        check(unsafe { ffi::RSA_set0_crt_params(rsa.ptr(), dmp1.ptr(), dmq1.ptr(), iqmp.ptr()) })?;
        mem::forget(dmp1);
        mem::forget(dmq1);
        mem::forget(iqmp);
        if matches!(validation, Validation::Full) {
            // SAFETY: All required positive components and structural invariants
            // are established before asking the backend to validate arithmetic.
            check(unsafe { ffi::RSA_check_key(rsa.ptr()) })?;
        }
        Key::from_rsa(rsa).map(Self)
    }
    pub fn bits(&self) -> u32 {
        self.0.bits()
    }
    pub fn public_key(&self) -> Result<PublicKey> {
        let parts = self.0.public_parts()?;
        PublicKey::from_components(&parts.n, &parts.e)
    }
    pub fn export_components(&self) -> Result<PrivateExport> {
        let (mut n, mut e, mut d, mut p, mut q, mut dmp1, mut dmq1, mut iqmp) = (
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        // Allocate the zeroizing owner before any fallible export.
        let mut export = PrivateExport {
            parts: std::array::from_fn(|_| Vec::new()),
        };
        // SAFETY: This key has all components; returned pointers remain borrowed
        // from self through the copy and are never freed or modified here.
        unsafe {
            ffi::RSA_get0_key(self.0.rsa(), &mut n, &mut e, &mut d);
            ffi::RSA_get0_factors(self.0.rsa(), &mut p, &mut q);
            ffi::RSA_get0_crt_params(self.0.rsa(), &mut dmp1, &mut dmq1, &mut iqmp);
            for (output, value) in export
                .parts
                .iter_mut()
                .zip([n, e, d, p, q, dmp1, dmq1, iqmp])
            {
                *output = component(value)?;
            }
        }
        Ok(export)
    }
    pub fn sign_digest(
        &self,
        digest: Algorithm,
        data: &[u8],
        padding: SigningPadding,
    ) -> Result<Vec<u8>> {
        validate_digest(digest, data)?;
        self.sign_data(Some(digest), data, padding)
    }

    /// Sign a caller-supplied PKCS1 v1.5 block without adding DigestInfo.
    pub fn sign_pkcs1v15_block(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_data(None, data, SigningPadding::Pkcs1v15)
    }

    fn sign_data(
        &self,
        digest: Option<Algorithm>,
        data: &[u8],
        padding: SigningPadding,
    ) -> Result<Vec<u8>> {
        let mut ctx = Context::new(&self.0)?;
        // SAFETY: This unique context is attached to a complete private key.
        check(unsafe { ffi::EVP_PKEY_sign_init(ctx.ptr()) })?;
        let padding = match padding {
            SigningPadding::Pkcs1v15 => VerificationPadding::Pkcs1v15,
            SigningPadding::Pss { mgf1, salt } => VerificationPadding::Pss { mgf1, salt },
        };
        signature_parameters(&mut ctx, &self.0, digest, padding)?;
        let mut output = vec![0; self.0.size()?];
        let mut written = output.len();
        // SAFETY: The context is fully configured, data matches the digest size,
        // and output capacity is both sufficient and passed to the native API.
        check(unsafe {
            ffi::EVP_PKEY_sign(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                data.as_ptr(),
                data.len(),
            )
        })?;
        crate::error::check_len(written, output.len())?;
        Ok(output)
    }
    pub fn decrypt(&self, ciphertext: &[u8], padding: EncryptionPadding<'_>) -> Result<Plaintext> {
        let mut output = Plaintext(vec![0; self.0.size()?]);
        let written = self.decrypt_into(ciphertext, padding, &mut output.0)?;
        output.0.truncate(written);
        Ok(output)
    }

    /// Decrypt into a caller-owned modulus-sized buffer. Failed native decryption
    /// erases the output; successful decryption erases bytes beyond the result.
    /// This preserves control of allocation timing for legacy PKCS1 v1.5 callers.
    pub fn decrypt_into(
        &self,
        ciphertext: &[u8],
        padding: EncryptionPadding<'_>,
        output: &mut [u8],
    ) -> Result<usize> {
        let size = self.0.size()?;
        if ciphertext.len() != size {
            return Err(Error::InvalidInput(
                "RSA ciphertext must match modulus size",
            ));
        }
        if output.len() < size {
            return Err(Error::InvalidInput("RSA output buffer is too small"));
        }
        let mut ctx = Context::new(&self.0)?;
        // SAFETY: This unique context is attached to a complete private key.
        check(unsafe { ffi::EVP_PKEY_decrypt_init(ctx.ptr()) })?;
        encryption_parameters(&mut ctx, padding)?;
        let output = &mut output[..size];
        let mut written = output.len();
        // SAFETY: All parameters are set; output covers the modulus size and the
        // supplied capacity. Input and output are disjoint Rust borrows.
        let result = check(unsafe {
            ffi::EVP_PKEY_decrypt(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        });
        crate::secret::clear_on_error(result, output)?;
        crate::secret::clear_on_error(
            crate::error::check_len_at_most(written, output.len()),
            output,
        )?;
        cleanse(&mut output[written..]);
        Ok(written)
    }
}
impl PublicKey {
    pub fn signature_digest_supported(&self, digest: Algorithm) -> Result<bool> {
        signature_digest_supported(&self.0, digest, false)
    }
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self> {
        Key::from_rsa(Rsa::public(n, e)?).map(Self)
    }
    pub fn bits(&self) -> u32 {
        self.0.bits()
    }
    pub fn export_components(&self) -> Result<PublicComponents> {
        self.0.public_parts()
    }
    pub fn verify_digest(
        &self,
        digest: Algorithm,
        data: &[u8],
        signature: &[u8],
        padding: VerificationPadding,
    ) -> Result<bool> {
        validate_digest(digest, data)?;
        self.verify_data(Some(digest), data, signature, padding)
    }

    /// Verify a caller-supplied PKCS1 v1.5 block without expecting DigestInfo.
    pub fn verify_pkcs1v15_block(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify_data(None, data, signature, VerificationPadding::Pkcs1v15)
    }

    fn verify_data(
        &self,
        digest: Option<Algorithm>,
        data: &[u8],
        signature: &[u8],
        padding: VerificationPadding,
    ) -> Result<bool> {
        if signature.len() != self.0.size()? {
            return Ok(false);
        }
        let mut ctx = Context::new(&self.0)?;
        // SAFETY: This unique context has a public key with valid n/e.
        check(unsafe { ffi::EVP_PKEY_verify_init(ctx.ptr()) })?;
        signature_parameters(&mut ctx, &self.0, digest, padding)?;
        // SAFETY: Input slices cover their lengths; context is fully initialized.
        crate::error::verification_result(unsafe {
            ffi::EVP_PKEY_verify(
                ctx.ptr(),
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
            )
        })
    }
    /// Recover a verified PKCS1 v1.5 signature's payload. A digest requests
    /// validation and removal of DigestInfo; None returns the complete block.
    pub fn recover_pkcs1v15(&self, signature: &[u8], digest: Option<Algorithm>) -> Result<Vec<u8>> {
        if signature.len() != self.0.size()? {
            return Err(Error::InvalidInput("RSA signature must match modulus size"));
        }
        if digest.is_some_and(|d| d.is_xof()) {
            return Err(Error::InvalidInput("RSA requires a fixed-output digest"));
        }
        let mut ctx = Context::new(&self.0)?;
        // SAFETY: This unique context is attached to a complete public key.
        check(unsafe { ffi::EVP_PKEY_verify_recover_init(ctx.ptr()) })?;
        signature_parameters(&mut ctx, &self.0, digest, VerificationPadding::Pkcs1v15)?;
        let mut output = vec![0; self.0.size()?];
        let mut written = output.len();
        // SAFETY: This context is configured for recovery; output is writable for
        // the supplied capacity and signature contains exactly the modulus size.
        check(unsafe {
            ffi::EVP_PKEY_verify_recover(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                signature.as_ptr(),
                signature.len(),
            )
        })?;
        crate::error::check_len_at_most(written, output.len())?;
        output.truncate(written);
        Ok(output)
    }

    pub fn encrypt(&self, plaintext: &[u8], padding: EncryptionPadding<'_>) -> Result<Vec<u8>> {
        let mut ctx = Context::new(&self.0)?;
        // SAFETY: This unique context has a public key with valid n/e.
        check(unsafe { ffi::EVP_PKEY_encrypt_init(ctx.ptr()) })?;
        encryption_parameters(&mut ctx, padding)?;
        let mut output = vec![0; self.0.size()?];
        let mut written = output.len();
        // SAFETY: Input covers its length; native code validates the padding's
        // maximum plaintext size. Output capacity is the modulus size.
        check(unsafe {
            ffi::EVP_PKEY_encrypt(
                ctx.ptr(),
                output.as_mut_ptr(),
                &mut written,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        })?;
        crate::error::check_len(written, output.len())?;
        Ok(output)
    }
}

fn validate_digest(digest: Algorithm, data: &[u8]) -> Result<()> {
    if digest.is_xof() || digest.output_size()? != data.len() {
        return Err(Error::InvalidInput(
            "RSA requires a digest of the declared algorithm and length",
        ));
    }
    Ok(())
}

fn signature_digest_supported(key: &Key, digest: Algorithm, signing: bool) -> Result<bool> {
    if digest.is_xof() {
        return Ok(false);
    }
    let mut ctx = Context::new(key)?;
    // SAFETY: PrivateKey callers select signing; PublicKey callers select
    // verification. The unique context owns a reference to the appropriate key.
    check(unsafe {
        if signing {
            ffi::EVP_PKEY_sign_init(ctx.ptr())
        } else {
            ffi::EVP_PKEY_verify_init(ctx.ptr())
        }
    })?;
    // SAFETY: The context is initialized for verification and digest is live.
    let result = unsafe { ffi::OB_signature_md(ctx.ptr(), digest.as_ptr()) };
    if result == 1 {
        Ok(true)
    } else {
        let _ = Error::capture();
        Ok(false)
    }
}
fn signature_parameters(
    ctx: &mut Context,
    key: &Key,
    digest: Option<Algorithm>,
    padding: VerificationPadding,
) -> Result<()> {
    if let Some(digest) = digest {
        // SAFETY: ctx has completed signature initialization; digest is a live descriptor.
        check(unsafe { ffi::OB_signature_md(ctx.ptr(), digest.as_ptr()) })?;
    }
    let (mgf1, salt) = match padding {
        VerificationPadding::Pkcs1v15 => {
            // SAFETY: PKCS1 signature padding needs no additional controls.
            return check(unsafe { ffi::OB_rsa_padding(ctx.ptr(), ffi::RSA_PKCS1_PADDING as i32) });
        }
        VerificationPadding::Pss { mgf1, salt } => {
            let digest = digest.ok_or(Error::InvalidInput("PSS requires a digest"))?;
            let size = match salt {
                SaltLength::Digest => digest.output_size()?,
                SaltLength::Exact(size) => size as usize,
                SaltLength::Maximum => ((key.bits() - 1) as usize)
                    .div_ceil(8)
                    .checked_sub(digest.output_size()? + 2)
                    .ok_or(Error::InvalidInput("RSA modulus is too small for digest"))?,
            };
            (
                mgf1,
                i32::try_from(size).map_err(|_| Error::InvalidInput("PSS salt is too long"))?,
            )
        }
        // All four native EVP implementations document -2 as automatic salt
        // recovery when verifying. This variant is unavailable to sign_digest.
        VerificationPadding::PssAuto { mgf1 } => (mgf1, -2),
    };
    if mgf1.is_xof() {
        return Err(Error::InvalidInput("MGF1 requires a fixed-output digest"));
    }
    // SAFETY: Each control applies only after sign/verify init and before use.
    unsafe {
        check(ffi::OB_rsa_padding(
            ctx.ptr(),
            ffi::RSA_PKCS1_PSS_PADDING as i32,
        ))?;
        check(ffi::OB_rsa_mgf1_md(ctx.ptr(), mgf1.as_ptr()))?;
        check(ffi::OB_rsa_pss_saltlen(ctx.ptr(), salt))
    }
}
fn encryption_parameters(ctx: &mut Context, padding: EncryptionPadding<'_>) -> Result<()> {
    match padding {
        EncryptionPadding::Pkcs1v15 => {
            // SAFETY: ctx has completed encrypt_init or decrypt_init.
            check(unsafe { ffi::OB_rsa_padding(ctx.ptr(), ffi::RSA_PKCS1_PADDING as i32) })
        }
        EncryptionPadding::Oaep {
            digest,
            mgf1,
            label,
        } => {
            if digest.is_xof() || mgf1.is_xof() {
                return Err(Error::InvalidInput("OAEP requires fixed-output digests"));
            }
            let length = label
                .len()
                .try_into()
                .map_err(|_| Error::InvalidInput("OAEP label is too long"))?;
            // SAFETY: ctx is exclusively owned and initialized for encryption or
            // decryption. The shim copies the checked label before transferring it.
            unsafe {
                check(ffi::OB_rsa_padding(
                    ctx.ptr(),
                    ffi::RSA_PKCS1_OAEP_PADDING as i32,
                ))?;
                check(ffi::OB_rsa_oaep_md(ctx.ptr(), digest.as_ptr()))?;
                check(ffi::OB_rsa_mgf1_md(ctx.ptr(), mgf1.as_ptr()))?;
                check(ffi::OB_rsa_oaep_label(ctx.ptr(), label.as_ptr(), length))
            }
        }
    }
}
