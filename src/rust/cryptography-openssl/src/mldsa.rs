// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use foreign_types_shared::ForeignType;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
use foreign_types_shared::ForeignTypeRef;
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
use openssl_sys as ffi;
#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
use std::os::raw::c_int;

#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
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

/// The length, in bytes, of an ML-DSA external mu (message representative)
/// value, as defined in FIPS 204.
pub const MLDSA_MU_BYTES: usize = 64;

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

fn set_context_string<T>(
    pkey_ctx: &mut openssl::pkey_ctx::PkeyCtxRef<T>,
    context: &[u8],
) -> OpenSSLResult<()> {
    cfg_if::cfg_if! {
        if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
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

/// Extract the raw 32-byte seed from an ML-DSA private key.
pub fn mldsa_seed_raw(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> OpenSSLResult<[u8; 32]> {
    let mut seed = [0u8; 32];
    cfg_if::cfg_if! {
        if #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))] {
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
    let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
    let pkey_ctx = md_ctx.digest_sign_init(None, pkey)?;
    if !context.is_empty() {
        set_context_string(pkey_ctx, context)?;
    }
    let mut sig = vec![];
    md_ctx.digest_sign_to_vec(data, &mut sig)?;
    Ok(sig)
}

pub fn verify(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    signature: &[u8],
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<bool> {
    let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
    let pkey_ctx = md_ctx.digest_verify_init(None, pkey)?;
    if !context.is_empty() {
        set_context_string(pkey_ctx, context)?;
    }
    Ok(md_ctx.digest_verify(data, signature).unwrap_or(false))
}

/// Enable "external mu" mode on an OpenSSL signing/verification context by
/// setting the integer `mu` signature parameter (OSSL_SIGNATURE_PARAM_MU) to 1.
#[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)]
fn set_mu<T>(pkey_ctx: &mut openssl::pkey_ctx::PkeyCtxRef<T>) -> OpenSSLResult<()> {
    // A fixed OSSL_PARAM array holding the integer "mu" parameter set to 1
    // enables external mu mode. The provider reads it back with
    // OSSL_PARAM_get_int, which accepts an unsigned integer param, so we can
    // build the array on the stack rather than via an allocating
    // OSSL_PARAM_BLD.
    let mut mu: std::ffi::c_uint = 1;
    // SAFETY: `params` and its backing `mu` value outlive the call into
    // OpenSSL, and the array is terminated with OSSL_PARAM_construct_end().
    unsafe {
        let params = [
            ffi::OSSL_PARAM_construct_uint(c"mu".as_ptr(), &mut mu),
            ffi::OSSL_PARAM_construct_end(),
        ];
        cvt(ffi::EVP_PKEY_CTX_set_params(
            pkey_ctx.as_ptr(),
            params.as_ptr(),
        ))?;
    }
    Ok(())
}

/// Sign a precomputed external mu (message representative). `mu` must be
/// [`MLDSA_MU_BYTES`] long, and already incorporates any context string, so no
/// context is accepted here.
pub fn sign_mu(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    mu: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    // The BoringSSL path passes `mu` to the low-level API as a bare pointer
    // that is read for exactly MLDSA_MU_BYTES, so enforce the length here for
    // soundness rather than relying on callers.
    assert_eq!(mu.len(), MLDSA_MU_BYTES);
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            // BoringSSL has no EVP-level external mu support, so we drop down to
            // the low-level ML-DSA API, reconstructing the private key from its
            // 32-byte seed.
            let seed = mldsa_seed_raw(pkey)?;
            // SAFETY: `seed` is a valid 32-byte seed and `mu` is a valid
            // MLDSA_MU_BYTES buffer; both outlive the calls below.
            unsafe {
                match MlDsaVariant::from_pkey(pkey) {
                    MlDsaVariant::MlDsa44 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA44_private_key>::uninit();
                        cvt(ffi::MLDSA44_private_key_from_seed(
                            key.as_mut_ptr(),
                            seed.as_ptr(),
                            seed.len(),
                        ))?;
                        let key = key.assume_init();
                        let mut sig = vec![0u8; ffi::MLDSA44_SIGNATURE_BYTES as usize];
                        cvt(ffi::MLDSA44_sign_message_representative(
                            sig.as_mut_ptr(),
                            &key,
                            mu.as_ptr(),
                        ))?;
                        Ok(sig)
                    }
                    MlDsaVariant::MlDsa65 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA65_private_key>::uninit();
                        cvt(ffi::MLDSA65_private_key_from_seed(
                            key.as_mut_ptr(),
                            seed.as_ptr(),
                            seed.len(),
                        ))?;
                        let key = key.assume_init();
                        let mut sig = vec![0u8; ffi::MLDSA65_SIGNATURE_BYTES as usize];
                        cvt(ffi::MLDSA65_sign_message_representative(
                            sig.as_mut_ptr(),
                            &key,
                            mu.as_ptr(),
                        ))?;
                        Ok(sig)
                    }
                    MlDsaVariant::MlDsa87 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA87_private_key>::uninit();
                        cvt(ffi::MLDSA87_private_key_from_seed(
                            key.as_mut_ptr(),
                            seed.as_ptr(),
                            seed.len(),
                        ))?;
                        let key = key.assume_init();
                        let mut sig = vec![0u8; ffi::MLDSA87_SIGNATURE_BYTES as usize];
                        cvt(ffi::MLDSA87_sign_message_representative(
                            sig.as_mut_ptr(),
                            &key,
                            mu.as_ptr(),
                        ))?;
                        Ok(sig)
                    }
                }
            }
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            // AWS-LC's EVP_PKEY_sign treats its input as an external mu (the
            // "ExternalMu" format) for ML-DSA keys.
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;
            ctx.sign_init()?;
            let mut sig = vec![];
            ctx.sign_to_vec(mu, &mut sig)?;
            Ok(sig)
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            // OpenSSL signs an external mu by setting the "mu" parameter and
            // passing the 64-byte mu in place of the message. ML-DSA only
            // supports the digest-sign flow (EVP_PKEY_sign_init is not
            // implemented for it), so we cannot use the one-shot PkeyCtx path
            // the AWS-LC branch uses.
            let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
            let pkey_ctx = md_ctx.digest_sign_init(None, pkey)?;
            set_mu(pkey_ctx)?;
            let mut sig = vec![];
            md_ctx.digest_sign_to_vec(mu, &mut sig)?;
            Ok(sig)
        }
    }
}

/// Verify a signature over a precomputed external mu (message representative).
/// `mu` must be [`MLDSA_MU_BYTES`] long.
pub fn verify_mu(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    signature: &[u8],
    mu: &[u8],
) -> OpenSSLResult<bool> {
    // The BoringSSL path passes `mu` to the low-level API as a bare pointer
    // that is read for exactly MLDSA_MU_BYTES, so enforce the length here for
    // soundness rather than relying on callers.
    assert_eq!(mu.len(), MLDSA_MU_BYTES);
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let raw = pkey.raw_public_key()?;
            // SAFETY: We parse the low-level public key from its encoded form
            // and verify the signature over the MLDSA_MU_BYTES `mu`.
            unsafe {
                match MlDsaVariant::from_pkey(pkey) {
                    MlDsaVariant::MlDsa44 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA44_public_key>::uninit();
                        let mut cbs = std::mem::MaybeUninit::<ffi::CBS>::uninit();
                        ffi::CBS_init(cbs.as_mut_ptr(), raw.as_ptr(), raw.len());
                        cvt(ffi::MLDSA44_parse_public_key(
                            key.as_mut_ptr(),
                            cbs.as_mut_ptr(),
                        ))?;
                        let key = key.assume_init();
                        Ok(ffi::MLDSA44_verify_message_representative(
                            &key,
                            signature.as_ptr(),
                            signature.len(),
                            mu.as_ptr(),
                        ) == 1)
                    }
                    MlDsaVariant::MlDsa65 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA65_public_key>::uninit();
                        let mut cbs = std::mem::MaybeUninit::<ffi::CBS>::uninit();
                        ffi::CBS_init(cbs.as_mut_ptr(), raw.as_ptr(), raw.len());
                        cvt(ffi::MLDSA65_parse_public_key(
                            key.as_mut_ptr(),
                            cbs.as_mut_ptr(),
                        ))?;
                        let key = key.assume_init();
                        Ok(ffi::MLDSA65_verify_message_representative(
                            &key,
                            signature.as_ptr(),
                            signature.len(),
                            mu.as_ptr(),
                        ) == 1)
                    }
                    MlDsaVariant::MlDsa87 => {
                        let mut key = std::mem::MaybeUninit::<ffi::MLDSA87_public_key>::uninit();
                        let mut cbs = std::mem::MaybeUninit::<ffi::CBS>::uninit();
                        ffi::CBS_init(cbs.as_mut_ptr(), raw.as_ptr(), raw.len());
                        cvt(ffi::MLDSA87_parse_public_key(
                            key.as_mut_ptr(),
                            cbs.as_mut_ptr(),
                        ))?;
                        let key = key.assume_init();
                        Ok(ffi::MLDSA87_verify_message_representative(
                            &key,
                            signature.as_ptr(),
                            signature.len(),
                            mu.as_ptr(),
                        ) == 1)
                    }
                }
            }
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;
            ctx.verify_init()?;
            Ok(ctx.verify(mu, signature).unwrap_or(false))
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            let mut md_ctx = openssl::md_ctx::MdCtx::new()?;
            let pkey_ctx = md_ctx.digest_verify_init(None, pkey)?;
            set_mu(pkey_ctx)?;
            Ok(md_ctx.digest_verify(mu, signature).unwrap_or(false))
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
