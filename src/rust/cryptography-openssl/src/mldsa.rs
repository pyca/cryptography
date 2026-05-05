// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use foreign_types_shared::ForeignType;
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use foreign_types_shared::ForeignTypeRef;
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use openssl_sys as ffi;
#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
use std::os::raw::c_int;

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use crate::cvt;
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use crate::cvt_p;
use crate::OpenSSLResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
pub const PKEY_ID: openssl::pkey::Id = openssl::pkey::Id::from_raw(ffi::NID_PQDSA);

/// Check whether a PKey is an ML-DSA key.
///
/// OpenSSL 3.x provider-based keys return -1 from EVP_PKEY_get_id(), so
/// NID-based matching does not work. `PKeyRef::is_a` queries by algorithm
/// name instead.
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
pub fn is_mldsa_pkey<T>(pkey: &openssl::pkey::PKeyRef<T>) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let raw = pkey.id().as_raw();
            raw == ffi::NID_ML_DSA_44 || raw == ffi::NID_ML_DSA_65 || raw == ffi::NID_ML_DSA_87
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            pkey.id() == PKEY_ID
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            pkey.is_a(openssl::pkey::KeyType::ML_DSA_44)
                || pkey.is_a(openssl::pkey::KeyType::ML_DSA_65)
                || pkey.is_a(openssl::pkey::KeyType::ML_DSA_87)
        }
    }
}

impl MlDsaVariant {
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    pub fn nid(self) -> c_int {
        match self {
            MlDsaVariant::MlDsa44 => ffi::NID_MLDSA44,
            MlDsaVariant::MlDsa65 => ffi::NID_MLDSA65,
            MlDsaVariant::MlDsa87 => ffi::NID_MLDSA87,
        }
    }

    pub fn from_pkey<T: openssl::pkey::HasPublic>(
        pkey: &openssl::pkey::PKeyRef<T>,
    ) -> MlDsaVariant {
        cfg_if::cfg_if! {
            if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
                match pkey.id().as_raw() {
                    ffi::NID_ML_DSA_44 => MlDsaVariant::MlDsa44,
                    ffi::NID_ML_DSA_65 => MlDsaVariant::MlDsa65,
                    ffi::NID_ML_DSA_87 => MlDsaVariant::MlDsa87,
                    _ => panic!("Unsupported ML-DSA variant"),
                }
            } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
                // SAFETY: EVP_PKEY_pqdsa_get_type returns the NID of the
                // PQDSA algorithm for a valid PQDSA pkey.
                let nid = unsafe { ffi::EVP_PKEY_pqdsa_get_type(pkey.as_ptr()) };
                match nid {
                    ffi::NID_MLDSA44 => MlDsaVariant::MlDsa44,
                    ffi::NID_MLDSA65 => MlDsaVariant::MlDsa65,
                    ffi::NID_MLDSA87 => MlDsaVariant::MlDsa87,
                    _ => panic!("Unsupported ML-DSA variant"),
                }
            } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
                // Provider-based keys in OpenSSL 3.x return -1 from
                // EVP_PKEY_get_id(), so we must use name-based lookup.
                if pkey.is_a(openssl::pkey::KeyType::ML_DSA_44) {
                    MlDsaVariant::MlDsa44
                } else if pkey.is_a(openssl::pkey::KeyType::ML_DSA_65) {
                    MlDsaVariant::MlDsa65
                } else if pkey.is_a(openssl::pkey::KeyType::ML_DSA_87) {
                    MlDsaVariant::MlDsa87
                } else {
                    panic!("Unsupported ML-DSA variant")
                }
            }
        }
    }
}

#[cfg(CRYPTOGRAPHY_IS_BORINGSSL)]
fn evp_pkey_alg(variant: MlDsaVariant) -> *const ffi::EVP_PKEY_ALG {
    // SAFETY: These functions return static, non-null pointers to the
    // EVP_PKEY_ALG for each ML-DSA variant.
    unsafe {
        match variant {
            MlDsaVariant::MlDsa44 => ffi::EVP_pkey_ml_dsa_44(),
            MlDsaVariant::MlDsa65 => ffi::EVP_pkey_ml_dsa_65(),
            MlDsaVariant::MlDsa87 => ffi::EVP_pkey_ml_dsa_87(),
        }
    }
}

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
fn set_context_string<T>(
    pkey_ctx: &mut openssl::pkey_ctx::PkeyCtxRef<T>,
    context: &[u8],
) -> OpenSSLResult<()> {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            // SAFETY: pkey_ctx is a valid EVP_PKEY_CTX.
            let res = unsafe {
                ffi::EVP_PKEY_CTX_set1_signature_context_string(
                    pkey_ctx.as_ptr(),
                    context.as_ptr(),
                    context.len(),
                )
            };
            cvt(res)?;
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            pkey_ctx.set_context_string(context)?;
        }
    }
    Ok(())
}

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
extern "C" {
    // We call ml_dsa_{44,65}_sign/verify directly instead of going through
    // EVP_DigestSign/EVP_DigestVerify because the EVP PQDSA path hardcodes
    // context to (NULL, 0), so we'd lose context string support.
    fn ml_dsa_44_sign(
        private_key: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_44_verify(
        public_key: *const u8,
        sig: *const u8,
        sig_len: usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_65_sign(
        private_key: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_65_verify(
        public_key: *const u8,
        sig: *const u8,
        sig_len: usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_87_sign(
        private_key: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;

    fn ml_dsa_87_verify(
        public_key: *const u8,
        sig: *const u8,
        sig_len: usize,
        message: *const u8,
        message_len: usize,
        ctx_string: *const u8,
        ctx_string_len: usize,
    ) -> c_int;
}

/// Extract the raw 32-byte seed from an ML-DSA private key.
///
/// Avoids the PKCS#8 round-trip that vanilla OpenSSL 3.5 encodes
/// differently from BoringSSL/AWS-LC.
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
pub fn mldsa_seed_raw(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> OpenSSLResult<[u8; 32]> {
    let mut seed = [0u8; 32];
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let mut seed_len = seed.len();
            // SAFETY: pkey is a valid EVP_PKEY and seed is a 32-byte buffer.
            unsafe {
                cvt(ffi::EVP_PKEY_get_private_seed(
                    pkey.as_ptr(),
                    seed.as_mut_ptr(),
                    &mut seed_len,
                ))?;
            }
            assert_eq!(seed_len, 32);
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            pkey.seed_into(&mut seed)?;
        }
    }
    Ok(seed)
}

pub fn new_raw_private_key(
    variant: MlDsaVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            // SAFETY: EVP_PKEY_from_private_seed creates a new EVP_PKEY from
            // the seed. evp_pkey_alg returns a valid algorithm pointer.
            unsafe {
                let pkey = cvt_p(ffi::EVP_PKEY_from_private_seed(
                    evp_pkey_alg(variant),
                    data.as_ptr(),
                    data.len(),
                ))?;
                Ok(openssl::pkey::PKey::from_ptr(pkey))
            }
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            // SAFETY: EVP_PKEY_pqdsa_new_raw_private_key creates a new
            // EVP_PKEY from raw key bytes. For ML-DSA, a seed expands into
            // the full keypair.
            unsafe {
                let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_private_key(
                    variant.nid(),
                    data.as_ptr(),
                    data.len(),
                ))?;
                Ok(openssl::pkey::PKey::from_ptr(pkey))
            }
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            let key_type = match variant {
                MlDsaVariant::MlDsa44 => openssl::pkey::KeyType::ML_DSA_44,
                MlDsaVariant::MlDsa65 => openssl::pkey::KeyType::ML_DSA_65,
                MlDsaVariant::MlDsa87 => openssl::pkey::KeyType::ML_DSA_87,
            };
            openssl::pkey::PKey::private_key_from_seed(None, key_type, None, data)
        }
    }
}

pub fn new_raw_public_key(
    variant: MlDsaVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let nid = match variant {
                MlDsaVariant::MlDsa44 => ffi::NID_ML_DSA_44,
                MlDsaVariant::MlDsa65 => ffi::NID_ML_DSA_65,
                MlDsaVariant::MlDsa87 => ffi::NID_ML_DSA_87,
            };
            openssl::pkey::PKey::public_key_from_raw_bytes(
                data,
                openssl::pkey::Id::from_raw(nid),
            )
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            // SAFETY: EVP_PKEY_pqdsa_new_raw_public_key creates a new
            // EVP_PKEY from raw public key bytes.
            unsafe {
                let pkey = cvt_p(ffi::EVP_PKEY_pqdsa_new_raw_public_key(
                    variant.nid(),
                    data.as_ptr(),
                    data.len(),
                ))?;
                Ok(openssl::pkey::PKey::from_ptr(pkey))
            }
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            let key_type = match variant {
                MlDsaVariant::MlDsa44 => openssl::pkey::KeyType::ML_DSA_44,
                MlDsaVariant::MlDsa65 => openssl::pkey::KeyType::ML_DSA_65,
                MlDsaVariant::MlDsa87 => openssl::pkey::KeyType::ML_DSA_87,
            };
            openssl::pkey::PKey::public_key_from_raw_bytes_ex(None, key_type, None, data)
        }
    }
}

pub fn sign(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    cfg_if::cfg_if! {
        if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))] {
            let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
            let pkey_ctx = md_ctx.digest_sign_init(None, pkey)?;
            if !context.is_empty() {
                set_context_string(pkey_ctx, context)?;
            }
            let mut sig = vec![];
            md_ctx.digest_sign_to_vec(data, &mut sig)?;
            Ok(sig)
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            let raw_key = pkey.raw_private_key()?;
            let variant = MlDsaVariant::from_pkey(pkey);

            type SignFn = unsafe extern "C" fn(
                *const u8,
                *mut u8,
                *mut usize,
                *const u8,
                usize,
                *const u8,
                usize,
            ) -> c_int;
            let (signature_bytes, sign_func): (usize, SignFn) = match variant {
                MlDsaVariant::MlDsa44 => (2420, ml_dsa_44_sign),
                MlDsaVariant::MlDsa65 => (3309, ml_dsa_65_sign),
                MlDsaVariant::MlDsa87 => (4627, ml_dsa_87_sign),
            };

            let mut sig = vec![0u8; signature_bytes];
            let mut sig_len: usize = 0;

            let msg_ptr = if data.is_empty() {
                std::ptr::null()
            } else {
                data.as_ptr()
            };
            let ctx_ptr = if context.is_empty() {
                std::ptr::null()
            } else {
                context.as_ptr()
            };

            // SAFETY: The sign function takes raw key bytes, message, and
            // context.
            unsafe {
                let r = sign_func(
                    raw_key.as_ptr(),
                    sig.as_mut_ptr(),
                    &mut sig_len,
                    msg_ptr,
                    data.len(),
                    ctx_ptr,
                    context.len(),
                );
                cvt(r)?;
            }

            sig.truncate(sig_len);
            Ok(sig)
        }
    }
}

pub fn verify(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    signature: &[u8],
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<bool> {
    cfg_if::cfg_if! {
        if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))] {
            let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
            let pkey_ctx = md_ctx.digest_verify_init(None, pkey)?;
            if !context.is_empty() {
                set_context_string(pkey_ctx, context)?;
            }
            Ok(md_ctx.digest_verify(data, signature).unwrap_or(false))
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            let raw_key = pkey.raw_public_key()?;
            let variant = MlDsaVariant::from_pkey(pkey);

            type VerifyFn = unsafe extern "C" fn(
                *const u8,
                *const u8,
                usize,
                *const u8,
                usize,
                *const u8,
                usize,
            ) -> c_int;
            let verify_func: VerifyFn = match variant {
                MlDsaVariant::MlDsa44 => ml_dsa_44_verify,
                MlDsaVariant::MlDsa65 => ml_dsa_65_verify,
                MlDsaVariant::MlDsa87 => ml_dsa_87_verify,
            };

            let msg_ptr = if data.is_empty() {
                std::ptr::null()
            } else {
                data.as_ptr()
            };
            let ctx_ptr = if context.is_empty() {
                std::ptr::null()
            } else {
                context.as_ptr()
            };

            // SAFETY: The verify function takes raw key bytes, signature,
            // message, and context.
            let r = unsafe {
                verify_func(
                    raw_key.as_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    msg_ptr,
                    data.len(),
                    ctx_ptr,
                    context.len(),
                )
            };

            if r != 1 {
                // Clear any errors from the OpenSSL error stack to prevent
                // leaking errors into subsequent operations.
                let _ = openssl::error::ErrorStack::get();
            }

            Ok(r == 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MlDsaVariant;

    #[test]
    #[should_panic(expected = "Unsupported ML-DSA variant")]
    fn test_from_pkey_wrong_type() {
        let key = openssl::pkey::PKey::generate_ed25519().unwrap();
        MlDsaVariant::from_pkey(&key);
    }
}
