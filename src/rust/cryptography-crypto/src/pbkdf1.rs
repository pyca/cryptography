// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

/// This is the OpenSSL KDF that's used in decrypting PEM blocks. It is a
/// generalization of PBKDF1.
pub fn openssl_kdf(
    hash_alg: openssl::hash::MessageDigest,
    password: &[u8],
    salt: [u8; 8],
    length: usize,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut key = Vec::with_capacity(length);

    while key.len() < length {
        let mut h = openssl::hash::Hasher::new(hash_alg)?;

        if !key.is_empty() {
            h.update(&key[key.len() - hash_alg.size()..])?;
        }

        h.update(password)?;
        h.update(&salt)?;

        let digest = h.finish()?;
        let size = digest.len().min(length - key.len());
        key.extend_from_slice(&digest[..size]);
    }

    Ok(key)
}

/// PBKDF1 as defined in RFC 2898 for PKCS#5 v1.5 PBE algorithms
pub fn pbkdf1(
    hash_alg: openssl::hash::MessageDigest,
    password: &[u8],
    salt: [u8; 8],
    iterations: u64,
    length: usize,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    if length > hash_alg.size() || iterations == 0 {
        return Err(openssl::error::ErrorStack::get());
    }

    let mut h = openssl::hash::Hasher::new(hash_alg)?;
    h.update(password)?;
    h.update(&salt)?;
    let mut t = h.finish()?;

    // Apply hash function for specified iterations
    for _ in 1..iterations {
        let mut h = openssl::hash::Hasher::new(hash_alg)?;
        h.update(&t)?;
        t = h.finish()?;
    }

    // Return the first `length` bytes
    Ok(t[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::{openssl_kdf, pbkdf1};

    #[test]
    fn test_openssl_kdf() {
        for (md, password, salt, expected) in [
            (
                openssl::hash::MessageDigest::md5(),
                b"password123" as &[u8],
                [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                &[
                    0x31, 0xcc, 0x91, 0x39, 0x80, 0x69, 0x98, 0xb2, 0xaa, 0xc3, 0x66, 0xcf, 0x40,
                    0x1b, 0x49, 0xdc, 0x0d, 0x37, 0xbd, 0x5c, 0x22, 0x52, 0xc7, 0xcb,
                ][..],
            ),
            (
                openssl::hash::MessageDigest::md5(),
                b"diffpassword",
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22],
                &[
                    0x89, 0x9b, 0x70, 0x37, 0xdb, 0x29, 0x42, 0x69, 0xdb, 0x4d, 0x67, 0xb9, 0x81,
                    0x67, 0xa7, 0x59, 0xfd, 0xec, 0x5d, 0x0f, 0x57, 0x52, 0xef, 0x04,
                ],
            ),
            (
                openssl::hash::MessageDigest::md5(),
                b"secret_key",
                [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                &[
                    0xa1, 0x98, 0x00, 0xf9, 0xab, 0x97, 0x36, 0xa1, 0x83, 0x4a, 0x19, 0x76, 0x47,
                    0x25, 0xda, 0x9b,
                ],
            ),
            (
                openssl::hash::MessageDigest::md5(),
                b"another_password",
                [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00],
                &[
                    0xc2, 0x09, 0x35, 0x72, 0xe5, 0x62, 0xd4, 0xba, 0x90, 0x4a, 0x5f, 0x46, 0x7f,
                    0x27, 0xd2, 0x6c,
                ],
            ),
            (
                openssl::hash::MessageDigest::md5(),
                b"very_long_and_complex_password",
                [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
                &[
                    0x1c, 0x5d, 0xdf, 0xa2, 0xca, 0xca, 0x41, 0xa4, 0xc9, 0xb4, 0x31, 0xd2, 0x9f,
                    0x04, 0x46, 0x81, 0xd2, 0x2b, 0x4e, 0x40, 0x06, 0x41, 0x5d, 0x37, 0x20, 0xef,
                    0x01, 0x1d, 0xc7, 0x8a, 0x16, 0xb5,
                ],
            ),
            (
                openssl::hash::MessageDigest::md5(),
                b"different_secure_password",
                [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
                &[
                    0xca, 0x08, 0xce, 0xb2, 0x46, 0x8f, 0xdc, 0x72, 0x83, 0xc7, 0x0b, 0x8a, 0xd0,
                    0x94, 0x54, 0x2b, 0x22, 0xd5, 0x1f, 0xf2, 0x5d, 0x0c, 0x1d, 0x99, 0xf3, 0x2f,
                    0x54, 0xa8, 0x68, 0x95, 0x13, 0xbd,
                ],
            ),
        ] {
            let key = openssl_kdf(md, password, salt, expected.len()).unwrap();
            assert_eq!(key, expected);
        }
    }

    #[test]
    fn test_pbkdf1() {
        assert!(pbkdf1(openssl::hash::MessageDigest::md5(), b"abc", [0; 8], 1, 20).is_err());
        assert!(pbkdf1(openssl::hash::MessageDigest::md5(), b"abc", [0; 8], 0, 8).is_err());
    }
}
