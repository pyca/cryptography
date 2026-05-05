// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::ForeignType;
#[cfg(CRYPTOGRAPHY_IS_BORINGSSL)]
use foreign_types_shared::ForeignTypeRef;
use openssl_sys as ffi;
#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
use std::os::raw::c_int;

use crate::cvt;
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC))]
use crate::cvt_p;
use crate::OpenSSLResult;

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
pub const PKEY_ID: openssl::pkey::Id = openssl::pkey::Id::from_raw(ffi::NID_kem);

/// Check whether a PKey is an ML-KEM key.
///
/// OpenSSL 3.x provider-based keys return -1 from EVP_PKEY_get_id(), so
/// NID-based matching does not work. `PKeyRef::is_a` queries by algorithm
/// name instead.
#[cfg(any(
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC,
    CRYPTOGRAPHY_OPENSSL_350_OR_GREATER
))]
pub fn is_mlkem_pkey<T>(pkey: &openssl::pkey::PKeyRef<T>) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let raw = pkey.id().as_raw();
            raw == ffi::NID_ML_KEM_768 || raw == ffi::NID_ML_KEM_1024
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            pkey.id() == PKEY_ID
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            pkey.is_a(openssl::pkey::KeyType::ML_KEM_768)
                || pkey.is_a(openssl::pkey::KeyType::ML_KEM_1024)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    #[cfg(CRYPTOGRAPHY_IS_AWSLC)]
    pub fn nid(self) -> c_int {
        match self {
            MlKemVariant::MlKem768 => ffi::NID_MLKEM768,
            MlKemVariant::MlKem1024 => ffi::NID_MLKEM1024,
        }
    }

    pub fn from_pkey<T: openssl::pkey::HasPublic>(
        pkey: &openssl::pkey::PKeyRef<T>,
    ) -> MlKemVariant {
        cfg_if::cfg_if! {
            if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
                match pkey.id().as_raw() {
                    ffi::NID_ML_KEM_768 => MlKemVariant::MlKem768,
                    ffi::NID_ML_KEM_1024 => MlKemVariant::MlKem1024,
                    _ => panic!("Unsupported ML-KEM variant"),
                }
            } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
                // AWS-LC is missing the equivalent `EVP_PKEY_pqdsa_get_type`,
                // so we are using the key size as a discriminator to find the
                // variant.
                let len = pkey
                    .raw_public_key()
                    .expect("valid ML-KEM public key")
                    .len();
                match len {
                    1184 => MlKemVariant::MlKem768,
                    1568 => MlKemVariant::MlKem1024,
                    _ => panic!("Unsupported ML-KEM variant"),
                }
            } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
                // Provider-based keys in OpenSSL 3.x return -1 from
                // EVP_PKEY_get_id(), so we must use name-based lookup.
                if pkey.is_a(openssl::pkey::KeyType::ML_KEM_768) {
                    MlKemVariant::MlKem768
                } else if pkey.is_a(openssl::pkey::KeyType::ML_KEM_1024) {
                    MlKemVariant::MlKem1024
                } else {
                    panic!("Unsupported ML-KEM variant")
                }
            }
        }
    }
}

#[cfg(CRYPTOGRAPHY_IS_BORINGSSL)]
fn evp_pkey_alg(variant: MlKemVariant) -> *const ffi::EVP_PKEY_ALG {
    // SAFETY: These functions return static, non-null pointers to the
    // EVP_PKEY_ALG for each ML-KEM variant.
    unsafe {
        match variant {
            MlKemVariant::MlKem768 => ffi::EVP_pkey_ml_kem_768(),
            MlKemVariant::MlKem1024 => ffi::EVP_pkey_ml_kem_1024(),
        }
    }
}

#[cfg(CRYPTOGRAPHY_IS_AWSLC)]
extern "C" {
    // Manually declared because this function is in an experimental header
    // in AWS-LC (April 2026).
    // https://github.com/aws/aws-lc/blob/23b13826748f942ed7d6c4bcb9971dc9244cbc6f/include/openssl/experimental/kem_deterministic_api.h#L31
    fn EVP_PKEY_keygen_deterministic(
        ctx: *mut ffi::EVP_PKEY_CTX,
        out_pkey: *mut *mut ffi::EVP_PKEY,
        seed: *const u8,
        seed_len: *mut usize,
    ) -> c_int;
}

/// Extract the raw 64-byte seed from an ML-KEM private key.
///
/// Avoids the PKCS#8 round-trip that vanilla OpenSSL 3.5 encodes
/// differently from BoringSSL/AWS-LC.
#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
pub fn mlkem_seed_raw(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> OpenSSLResult<[u8; 64]> {
    let mut seed = [0u8; 64];
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let mut seed_len = seed.len();
            // SAFETY: pkey is a valid EVP_PKEY and seed is a 64-byte buffer.
            unsafe {
                cvt(ffi::EVP_PKEY_get_private_seed(
                    pkey.as_ptr(),
                    seed.as_mut_ptr(),
                    &mut seed_len,
                ))?;
            }
            assert_eq!(seed_len, 64);
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            pkey.seed_into(&mut seed)?;
        }
    }
    Ok(seed)
}

pub fn new_raw_private_key(
    variant: MlKemVariant,
    seed: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            // SAFETY: EVP_PKEY_from_private_seed creates a new EVP_PKEY from
            // the seed. evp_pkey_alg returns a valid algorithm pointer.
            unsafe {
                let pkey = cvt_p(ffi::EVP_PKEY_from_private_seed(
                    evp_pkey_alg(variant),
                    seed.as_ptr(),
                    seed.len(),
                ))?;
                Ok(openssl::pkey::PKey::from_ptr(pkey))
            }
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            let ctx = openssl::pkey_ctx::PkeyCtx::new_id(PKEY_ID)?;
            // SAFETY: ctx is a valid EVP_PKEY_CTX for KEM.
            unsafe {
                cvt(ffi::EVP_PKEY_CTX_kem_set_params(
                    ctx.as_ptr(),
                    variant.nid(),
                ))?
            };
            // SAFETY: ctx is a valid EVP_PKEY_CTX with KEM params set.
            unsafe { cvt(ffi::EVP_PKEY_keygen_init(ctx.as_ptr()))? };

            let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();
            let mut seed_len = seed.len();
            // SAFETY: ctx is initialized for keygen, seed points to valid memory.
            unsafe {
                cvt(EVP_PKEY_keygen_deterministic(
                    ctx.as_ptr(),
                    &mut pkey,
                    seed.as_ptr(),
                    &mut seed_len,
                ))?;
            }
            assert_eq!(seed_len, 64);
            // SAFETY: EVP_PKEY_keygen_deterministic succeeded, pkey is valid.
            let pkey = unsafe { openssl::pkey::PKey::from_ptr(pkey) };
            Ok(pkey)
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            let key_type = match variant {
                MlKemVariant::MlKem768 => openssl::pkey::KeyType::ML_KEM_768,
                MlKemVariant::MlKem1024 => openssl::pkey::KeyType::ML_KEM_1024,
            };
            openssl::pkey::PKey::private_key_from_seed(None, key_type, None, seed)
        }
    }
}

pub fn new_raw_public_key(
    variant: MlKemVariant,
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    cfg_if::cfg_if! {
        if #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)] {
            let nid = match variant {
                MlKemVariant::MlKem768 => ffi::NID_ML_KEM_768,
                MlKemVariant::MlKem1024 => ffi::NID_ML_KEM_1024,
            };
            openssl::pkey::PKey::public_key_from_raw_bytes(
                data,
                openssl::pkey::Id::from_raw(nid),
            )
        } else if #[cfg(CRYPTOGRAPHY_IS_AWSLC)] {
            // SAFETY: data points to valid memory of the given length.
            unsafe {
                let pkey = cvt_p(ffi::EVP_PKEY_kem_new_raw_public_key(
                    variant.nid(),
                    data.as_ptr(),
                    data.len(),
                ))?;
                Ok(openssl::pkey::PKey::from_ptr(pkey))
            }
        } else if #[cfg(CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)] {
            let key_type = match variant {
                MlKemVariant::MlKem768 => openssl::pkey::KeyType::ML_KEM_768,
                MlKemVariant::MlKem1024 => openssl::pkey::KeyType::ML_KEM_1024,
            };
            openssl::pkey::PKey::public_key_from_raw_bytes_ex(None, key_type, None, data)
        }
    }
}

pub fn encapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> OpenSSLResult<(Vec<u8>, Vec<u8>)> {
    let (ct_bytes, ss_bytes) = match MlKemVariant::from_pkey(pkey) {
        MlKemVariant::MlKem768 => (1088, 32),
        MlKemVariant::MlKem1024 => (1568, 32),
    };
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
    {
        // SAFETY: ctx is a valid EVP_PKEY_CTX for the KEM operation.
        let res = unsafe { ffi::EVP_PKEY_encapsulate_init(ctx.as_ptr(), std::ptr::null()) };
        cvt(res)?;
    }

    let mut ciphertext = vec![0u8; ct_bytes];
    let mut shared_secret = vec![0u8; ss_bytes];
    let mut ct_len = ciphertext.len();
    let mut ss_len = shared_secret.len();
    // SAFETY: ctx is a valid EVP_PKEY_CTX, buffers are correctly sized.
    unsafe {
        cvt(ffi::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ciphertext.as_mut_ptr(),
            &mut ct_len,
            shared_secret.as_mut_ptr(),
            &mut ss_len,
        ))?;
    }
    assert_eq!(ct_len, ct_bytes);
    assert_eq!(ss_len, ss_bytes);
    Ok((ciphertext, shared_secret))
}

pub fn decapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    ciphertext: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_OPENSSL_350_OR_GREATER))]
    {
        // SAFETY: ctx is a valid EVP_PKEY_CTX for the KEM operation.
        let res = unsafe { ffi::EVP_PKEY_decapsulate_init(ctx.as_ptr(), std::ptr::null()) };
        cvt(res)?;
    }

    let ss_bytes: usize = 32;
    let mut shared_secret = vec![0u8; ss_bytes];
    let mut ss_len = ss_bytes;
    // SAFETY: ctx is a valid EVP_PKEY_CTX, buffers are correctly sized.
    unsafe {
        cvt(ffi::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            shared_secret.as_mut_ptr(),
            &mut ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }
    assert_eq!(ss_len, ss_bytes);
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::MlKemVariant;

    #[test]
    #[should_panic(expected = "Unsupported ML-KEM variant")]
    fn test_from_pkey_wrong_type() {
        let key = openssl::pkey::PKey::generate_ed25519().unwrap();
        MlKemVariant::from_pkey(&key);
    }
}
