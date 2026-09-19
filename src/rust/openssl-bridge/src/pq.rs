//! Private native ownership for the closed post-quantum algorithm set.
use crate::{
    error::{check, pointer},
    ffi, Error, Result,
};
use std::ptr::{self, NonNull};
#[derive(Clone, Copy)]
pub(crate) enum Algorithm {
    Dsa44,
    Dsa65,
    Dsa87,
    Kem768,
    Kem1024,
}
impl Algorithm {
    #[cfg(backend = "openssl")]
    fn name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Dsa44 => c"ML-DSA-44",
            Self::Dsa65 => c"ML-DSA-65",
            Self::Dsa87 => c"ML-DSA-87",
            Self::Kem768 => c"ML-KEM-768",
            Self::Kem1024 => c"ML-KEM-1024",
        }
    }
    #[cfg(backend = "boringssl")]
    fn alg(self) -> *const ffi::EVP_PKEY_ALG {
        // SAFETY: Closed algorithm set; getters return immutable static descriptors.
        unsafe {
            match self {
                Self::Dsa44 => ffi::EVP_pkey_ml_dsa_44(),
                Self::Dsa65 => ffi::EVP_pkey_ml_dsa_65(),
                Self::Dsa87 => ffi::EVP_pkey_ml_dsa_87(),
                Self::Kem768 => ffi::EVP_pkey_ml_kem_768(),
                Self::Kem1024 => ffi::EVP_pkey_ml_kem_1024(),
            }
        }
    }
    #[cfg(any(backend = "boringssl", backend = "awslc"))]
    fn nid(self) -> i32 {
        #[cfg(backend = "boringssl")]
        let value = match self {
            Self::Dsa44 => ffi::NID_ML_DSA_44,
            Self::Dsa65 => ffi::NID_ML_DSA_65,
            Self::Dsa87 => ffi::NID_ML_DSA_87,
            Self::Kem768 => ffi::NID_ML_KEM_768,
            Self::Kem1024 => ffi::NID_ML_KEM_1024,
        };
        #[cfg(backend = "awslc")]
        let value = match self {
            Self::Dsa44 => ffi::NID_MLDSA44,
            Self::Dsa65 => ffi::NID_MLDSA65,
            Self::Dsa87 => ffi::NID_MLDSA87,
            Self::Kem768 => ffi::NID_MLKEM768,
            Self::Kem1024 => ffi::NID_MLKEM1024,
        };
        value as i32
    }
    pub(crate) fn public_len(self) -> usize {
        match self {
            Self::Dsa44 => 1312,
            Self::Dsa65 => 1952,
            Self::Dsa87 => 2592,
            Self::Kem768 => 1184,
            Self::Kem1024 => 1568,
        }
    }
    fn seed_len(self) -> usize {
        match self {
            Self::Dsa44 | Self::Dsa65 | Self::Dsa87 => 32,
            Self::Kem768 | Self::Kem1024 => 64,
        }
    }
}
pub(crate) struct Key(NonNull<ffi::EVP_PKEY>);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Exactly one owned native reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
impl Key {
    pub(crate) fn ptr(&self) -> *mut ffi::EVP_PKEY {
        self.0.as_ptr()
    }
    pub(crate) fn private(algorithm: Algorithm, seed: &[u8]) -> Result<Self> {
        crate::initialize()?;
        if seed.len() != algorithm.seed_len() {
            return Err(Error::InvalidInput("incorrect post-quantum seed length"));
        }
        #[cfg(backend = "boringssl")]
        {
            // SAFETY: Descriptor matches the checked seed size; input is copied.
            pointer(unsafe {
                ffi::EVP_PKEY_from_private_seed(algorithm.alg(), seed.as_ptr(), seed.len())
            })
            .map(Self)
        }
        #[cfg(backend = "awslc")]
        {
            if matches!(
                algorithm,
                Algorithm::Dsa44 | Algorithm::Dsa65 | Algorithm::Dsa87
            ) {
                // SAFETY: Closed ML-DSA variant and correctly sized seed.
                return pointer(unsafe {
                    ffi::EVP_PKEY_pqdsa_new_raw_private_key(
                        algorithm.nid(),
                        seed.as_ptr(),
                        seed.len(),
                    )
                })
                .map(Self);
            }
            // SAFETY: KEM is a native algorithm id; NULL uses the default engine.
            let ctx = Context(pointer(unsafe {
                ffi::EVP_PKEY_CTX_new_id(ffi::NID_kem as i32, ptr::null_mut())
            })?);
            // SAFETY: Fresh KEM context; variant is one of two supported ML-KEM ids.
            check(unsafe { ffi::EVP_PKEY_CTX_kem_set_params(ctx.ptr(), algorithm.nid()) })?;
            // SAFETY: This exclusively owned context has complete parameters.
            check(unsafe { ffi::EVP_PKEY_keygen_init(ctx.ptr()) })?;
            let mut raw = ptr::null_mut();
            let mut size = seed.len();
            // SAFETY: Initialized keygen context and exactly 64 input bytes.
            let status = unsafe {
                ffi::EVP_PKEY_keygen_deterministic(ctx.ptr(), &mut raw, seed.as_ptr(), &mut size)
            };
            let key = NonNull::new(raw).map(Self);
            check(status)?;
            if size != seed.len() {
                return Err(Error::InvalidState("unexpected ML-KEM seed size"));
            }
            key.ok_or_else(Error::capture)
        }
        #[cfg(backend = "openssl")]
        {
            // SAFETY: Closed algorithm name and default provider configuration.
            let ctx = Context(pointer(unsafe {
                ffi::EVP_PKEY_CTX_new_from_name(
                    ptr::null_mut(),
                    algorithm.name().as_ptr(),
                    ptr::null(),
                )
            })?);
            // SAFETY: Fresh exclusively owned context.
            check(unsafe { ffi::EVP_PKEY_fromdata_init(ctx.ptr()) })?;
            // The OSSL_PARAM API takes a mutable pointer although import only reads it.
            // Copy into erased writable storage to keep that contract explicit.
            let mut seed: crate::secret::SecretBytes = seed.to_vec().into();
            // SAFETY: Parameter and writable backing buffer live through import.
            let mut params = unsafe {
                [
                    ffi::OSSL_PARAM_construct_octet_string(
                        c"seed".as_ptr(),
                        seed.as_mut().as_mut_ptr().cast(),
                        seed.as_ref().len(),
                    ),
                    ffi::OSSL_PARAM_construct_end(),
                ]
            };
            let mut raw = ptr::null_mut();
            // SAFETY: Terminated parameters describe the exact seed; output starts NULL.
            let status = unsafe {
                ffi::EVP_PKEY_fromdata(
                    ctx.ptr(),
                    &mut raw,
                    ffi::EVP_PKEY_KEYPAIR as i32,
                    params.as_mut_ptr(),
                )
            };
            let key = NonNull::new(raw).map(Self);
            check(status)?;
            key.ok_or_else(Error::capture)
        }
    }
    pub(crate) fn public(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        crate::initialize()?;
        if bytes.len() != algorithm.public_len() {
            return Err(Error::InvalidInput(
                "incorrect post-quantum public key length",
            ));
        }
        #[cfg(backend = "boringssl")]
        // SAFETY: Closed algorithm id, exact public-key size, copied input.
        let raw = unsafe {
            ffi::EVP_PKEY_new_raw_public_key(
                algorithm.nid(),
                ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        #[cfg(backend = "awslc")]
        // SAFETY: Both paths copy input and validate the selected algorithm's encoding.
        let raw = unsafe {
            match algorithm {
                Algorithm::Dsa44 | Algorithm::Dsa65 | Algorithm::Dsa87 => {
                    ffi::EVP_PKEY_pqdsa_new_raw_public_key(
                        algorithm.nid(),
                        bytes.as_ptr(),
                        bytes.len(),
                    )
                }
                Algorithm::Kem768 | Algorithm::Kem1024 => ffi::EVP_PKEY_kem_new_raw_public_key(
                    algorithm.nid(),
                    bytes.as_ptr(),
                    bytes.len(),
                ),
            }
        };
        #[cfg(backend = "openssl")]
        // SAFETY: Closed algorithm name and exactly sized readable input.
        let raw = unsafe {
            ffi::EVP_PKEY_new_raw_public_key_ex(
                ptr::null_mut(),
                algorithm.name().as_ptr(),
                ptr::null(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        pointer(raw).map(Self)
    }
    pub(crate) fn public_bytes(&self, algorithm: Algorithm) -> Result<Vec<u8>> {
        let mut bytes = vec![0; algorithm.public_len()];
        let mut length = bytes.len();
        // SAFETY: Buffer capacity is supplied and matches the selected algorithm.
        check(unsafe {
            ffi::EVP_PKEY_get_raw_public_key(self.ptr(), bytes.as_mut_ptr(), &mut length)
        })?;
        if length != bytes.len() {
            return Err(Error::InvalidState(
                "unexpected post-quantum public key size",
            ));
        }
        Ok(bytes)
    }
    pub(crate) fn context(&self) -> Result<Context> {
        // SAFETY: Complete live key; native context retains its own reference.
        pointer(unsafe { ffi::EVP_PKEY_CTX_new(self.ptr(), ptr::null_mut()) }).map(Context)
    }
}
pub(crate) struct Context(NonNull<ffi::EVP_PKEY_CTX>);
impl Context {
    pub(crate) fn ptr(&self) -> *mut ffi::EVP_PKEY_CTX {
        self.0.as_ptr()
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: Exclusive native operation owner.
        unsafe { ffi::EVP_PKEY_CTX_free(self.ptr()) };
    }
}
pub(crate) struct Digest(NonNull<ffi::EVP_MD_CTX>);
impl Digest {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: Native allocator has no preconditions.
        pointer(unsafe { ffi::EVP_MD_CTX_new() }).map(Self)
    }
    pub(crate) fn ptr(&self) -> *mut ffi::EVP_MD_CTX {
        self.0.as_ptr()
    }
}
impl Drop for Digest {
    fn drop(&mut self) {
        // SAFETY: Exclusive native digest owner.
        unsafe { ffi::EVP_MD_CTX_free(self.ptr()) };
    }
}
pub(crate) fn verified(status: i32) -> bool {
    if status == 1 {
        true
    } else {
        let _ = Error::capture();
        false
    }
}
