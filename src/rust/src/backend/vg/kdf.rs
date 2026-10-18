// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! verified-garbage's PBKDF2 and scrypt behind `backend/kdf.rs` (which calls
//! verified-garbage's Argon2 directly, and composes the other KDFs from
//! HMAC, CMAC and hashes on either backend).

use std::num::NonZeroU32;

use pyo3::types::PyAnyMethods;
use verified_garbage::hashes::{
    md5::Md5, sha1::Sha1, sha224::Sha224, sha256::Sha256, sha384::Sha384, sha512::Sha512,
    sha512_224::Sha512_224, sha512_256::Sha512_256,
};
use verified_garbage::pbkdf2::pbkdf2_hmac as vg_pbkdf2;

use cryptography_crypto::hash::MessageDigest;

use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

/// Checks that verified-garbage has PBKDF2 with HMAC over `md` (MD5, SHA-1
/// and SHA-2) and the iteration count.
pub(super) fn check_pbkdf2(
    py: pyo3::Python<'_>,
    algorithm: &pyo3::Bound<'_, pyo3::PyAny>,
    md: MessageDigest,
    iterations: usize,
) -> CryptographyResult<()> {
    if !cryptography_crypto::hmac::supported(md) {
        let name = algorithm.getattr(pyo3::intern!(py, "name"))?;
        return Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                format!("{name} is not supported for PBKDF2 by this backend"),
                exceptions::Reasons::UNSUPPORTED_HASH,
            )),
        ));
    }
    if u32::try_from(iterations).is_err() {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "iterations must be less than 2**32 with this backend.",
            ),
        ));
    }
    Ok(())
}

/// PBKDF2 with HMAC over `md`, which `check_pbkdf2` accepted.
pub(super) fn pbkdf2_hmac(
    md: MessageDigest,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out: &mut [u8],
) -> CryptographyResult<()> {
    let iterations = u32::try_from(iterations)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(CryptographyError::VerifiedGarbage(
            "invalid PBKDF2 iterations",
        ))?;
    // RFC 8018's "derived key too long", which verified-garbage panics on.
    if out.len() as u64 > u64::from(u32::MAX) * md.size() as u64 {
        return Err(CryptographyError::VerifiedGarbage(
            "PBKDF2 derived key too long",
        ));
    }
    match md {
        MessageDigest::Md5 => vg_pbkdf2::<Md5>(password, salt, iterations, out),
        MessageDigest::Sha1 => vg_pbkdf2::<Sha1>(password, salt, iterations, out),
        MessageDigest::Sha224 => vg_pbkdf2::<Sha224>(password, salt, iterations, out),
        MessageDigest::Sha256 => vg_pbkdf2::<Sha256>(password, salt, iterations, out),
        MessageDigest::Sha384 => vg_pbkdf2::<Sha384>(password, salt, iterations, out),
        MessageDigest::Sha512 => vg_pbkdf2::<Sha512>(password, salt, iterations, out),
        MessageDigest::Sha512_224 => vg_pbkdf2::<Sha512_224>(password, salt, iterations, out),
        MessageDigest::Sha512_256 => vg_pbkdf2::<Sha512_256>(password, salt, iterations, out),
        _ => {
            return Err(CryptographyError::VerifiedGarbage(
                "PBKDF2 with an unsupported hash",
            ))
        }
    }
    Ok(())
}

/// scrypt, with OpenSSL's memory limit (half the address space). Fails as
/// OpenSSL's does for parameters it cannot derive with.
pub(super) fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    out: &mut [u8],
) -> Result<(), ()> {
    if out.is_empty() {
        return Ok(());
    }
    let r = u32::try_from(r).map_err(|_| ())?;
    let p = u32::try_from(p).map_err(|_| ())?;
    verified_garbage::scrypt::scrypt(password, salt, n, r, p, usize::MAX / 2, out).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use cryptography_crypto::hash::MessageDigest;

    #[test]
    fn test_pbkdf2_dispatch() {
        for md in [
            MessageDigest::Md5,
            MessageDigest::Sha1,
            MessageDigest::Sha224,
            MessageDigest::Sha256,
            MessageDigest::Sha384,
            MessageDigest::Sha512,
            MessageDigest::Sha512_224,
            MessageDigest::Sha512_256,
        ] {
            // The first block of PBKDF2 with one iteration is
            // HMAC(P, S || INT(1)).
            let mut out = vec![0; md.size()];
            assert!(super::pbkdf2_hmac(md, b"password", b"salt", 1, &mut out).is_ok());
            let mut h = cryptography_crypto::hmac::Hmac::new(b"password", md).unwrap();
            h.update(b"salt\x00\x00\x00\x01").unwrap();
            assert_eq!(out, h.finish().unwrap());
        }
        let mut out = [0; 16];
        assert!(super::pbkdf2_hmac(MessageDigest::Sha3_256, b"p", b"s", 1, &mut out).is_err());
        assert!(super::pbkdf2_hmac(MessageDigest::Sha256, b"p", b"s", 0, &mut out).is_err());
    }

    #[test]
    fn test_scrypt() {
        let mut out = [0; 32];
        assert!(super::scrypt(b"p", b"s", 16, 1, 1, &mut out).is_ok());
        let mut expected = [0; 32];
        verified_garbage::scrypt::scrypt(b"p", b"s", 16, 1, 1, usize::MAX, &mut expected).unwrap();
        assert_eq!(out, expected);
        assert!(super::scrypt(b"p", b"s", 16, 1, 1, &mut []).is_ok());
        assert!(super::scrypt(b"p", b"s", 16, 1 << 32, 1, &mut out).is_err());
        assert!(super::scrypt(b"p", b"s", 15, 1, 1, &mut out).is_err());
    }
}
